import io
import struct
import time
import zlib
from pathlib import Path

import pytest
from PIL import Image
from pypdf import PageObject, PdfReader, PdfWriter
from pypdf.errors import LimitReachedError
from pypdf.generic import (ArrayObject, DecodedStreamObject, DictionaryObject, FloatObject, IndirectObject,
                           NameObject, NumberObject, RectangleObject, StreamObject, TextStringObject)

from mcp_servers.sandbox.server import OLE_MAGIC, analyze_file
from redteam import make_files

ENDOFCHAIN, FREESECT, FATSECT, NOSTREAM = 0xFFFFFFFE, 0xFFFFFFFF, 0xFFFFFFFD, 0xFFFFFFFF


pytestmark = pytest.mark.usefixtures("intake_dir")


def build_ole(streams: dict[str, bytes]) -> bytes:
    """Minimal CFB v3 writer (olefile can't create files). Streams are padded
    to 4096 bytes so everything lives in regular sectors, no mini stream.
    `streams` keys are slash paths, e.g. "Macros/VBA/_VBA_PROJECT"."""
    # Directory: 0 = root, then storages/streams in path order.
    entries: list[dict] = [{"name": "Root Entry", "type": 5, "children": []}]
    index: dict[str, int] = {"": 0}
    for full_path in streams:
        parts = full_path.split("/")
        for depth in range(1, len(parts) + 1):
            key = "/".join(parts[:depth])
            if key not in index:
                is_stream = depth == len(parts)
                index[key] = len(entries)
                entries.append({"name": parts[depth - 1], "type": 2 if is_stream else 1, "children": [],
                                "data": streams[full_path].ljust(4096, b"\0") if is_stream else b""})
                entries[index["/".join(parts[:depth - 1])]]["children"].append(index[key])

    dir_sectors = (len(entries) + 3) // 4
    next_sector = 1 + dir_sectors  # sector 0 = FAT
    fat = [FATSECT] + [i + 2 for i in range(dir_sectors - 1)] + [ENDOFCHAIN]
    for entry in entries:
        entry["start"], entry["size"] = ENDOFCHAIN, 0
        if entry["type"] == 2:
            count = len(entry["data"]) // 512
            entry["start"], entry["size"] = next_sector, len(entry["data"])
            fat += [next_sector + i + 1 for i in range(count - 1)] + [ENDOFCHAIN]
            next_sector += count
    assert len(fat) <= 128
    fat += [FREESECT] * (128 - len(fat))

    # Siblings: children chained via right-sibling links in CFB name order.
    for entry in entries:
        entry.setdefault("left", NOSTREAM)
        entry.setdefault("right", NOSTREAM)
        kids = sorted(entry["children"], key=lambda i: (len(entries[i]["name"]), entries[i]["name"].upper()))
        entry["child"] = kids[0] if kids else NOSTREAM
        for a, b in zip(kids, kids[1:]):
            entries[a]["right"] = b

    directory = b""
    for entry in entries:
        name = (entry["name"] + "\0").encode("utf-16-le")
        directory += struct.pack("<64sHBBIII16sIQQIQ", name, len(name), entry["type"], 1,
                                 entry["left"], entry["right"], entry["child"], b"\0" * 16, 0, 0, 0,
                                 entry["start"], entry["size"])
    empty = struct.pack("<64sHBBIII16sIQQIQ", b"", 0, 0, 0, NOSTREAM, NOSTREAM, NOSTREAM, b"\0" * 16, 0, 0, 0, 0, 0)
    directory = directory.ljust(dir_sectors * 512, b"\0")
    directory = b"".join(directory[i:i + 128] if i < len(entries) * 128 else empty for i in range(0, len(directory), 128))

    header = OLE_MAGIC + b"\0" * 16 + struct.pack("<HHHHH6sIIIIIIIIII", 0x3E, 3, 0xFFFE, 9, 6, b"\0" * 6, 0,
                                                  1, 1, 0, 4096, ENDOFCHAIN, 0, ENDOFCHAIN, 0, 0)
    header += struct.pack("<108I", *([FREESECT] * 108))
    data = b"".join(e["data"] for e in entries if e["type"] == 2)
    return header + struct.pack("<128I", *fat) + directory + data


def add_document_js(writer: PdfWriter, code: str) -> None:
    """A document-level JavaScript action in the catalog's /Names /JavaScript name tree. add_js is deprecated,
    and its replacement add_open_action exists only from pypdf 6.19, newer than the oldest supported version."""
    names = writer._root_object.setdefault(NameObject("/Names"), DictionaryObject())
    tree = names.setdefault(NameObject("/JavaScript"), DictionaryObject({NameObject("/Names"): ArrayObject()}))
    action = DictionaryObject({NameObject("/Type"): NameObject("/Action"), NameObject("/S"): NameObject("/JavaScript"),
                               NameObject("/JS"): TextStringObject(code)})
    tree["/Names"].extend([TextStringObject("js"), writer._add_object(action)])


def test_add_document_js_builds_the_add_js_structure() -> None:
    writer = PdfWriter()
    add_document_js(writer, "app.alert('hi');")
    buffer = io.BytesIO()
    writer.write(buffer)

    names = PdfReader(buffer).trailer["/Root"]["/Names"]["/JavaScript"]["/Names"]
    assert isinstance(names, ArrayObject) and len(names) == 2
    assert names[0] == "js" and isinstance(names[1], IndirectObject)
    action = names[1].get_object()
    assert action["/Type"] == "/Action" and action["/S"] == "/JavaScript"
    assert action["/JS"] == "app.alert('hi');"


def test_pdf_with_javascript_and_attachment(intake_dir: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    add_document_js(writer, "app.alert('hi');")
    writer.add_attachment("payload.txt", b"embedded bytes")
    writer.add_metadata({"/Author": "Test Author", "/Producer": "charon-test"})
    with open(intake_dir / "sample.pdf", "wb") as f:
        writer.write(f)

    result = analyze_file("sample.pdf")

    assert result["file_type"] == "pdf"
    pdf = result["pdf"]
    assert pdf["page_count"] == 1
    assert pdf["metadata"]["/Author"] == "Test Author"
    assert pdf["embedded_files"][0]["name"] == "payload.txt"
    assert pdf["embedded_files"][0]["size"] == len(b"embedded bytes")
    assert pdf["keyword_counts"]["/JavaScript"] >= 1
    assert pdf["keyword_counts"]["/JS"] >= 1
    assert pdf["keyword_counts"]["/EmbeddedFile"] >= 1
    assert pdf["keyword_counts"]["/Launch"] == 0


def test_truncated_pdf_still_returns_hash_and_keywords(intake_dir: Path) -> None:
    (intake_dir / "broken.pdf").write_bytes(b"%PDF-1.7\n1 0 obj << /OpenAction 2 0 R >> endobj\n")

    result = analyze_file("broken.pdf")

    assert result["file_type"] == "pdf"
    assert "parse_error" in result["pdf"]
    assert result["pdf"]["keyword_counts"]["/OpenAction"] == 1
    assert len(result["sha256"]) == 64


def test_jpeg_exif(intake_dir: Path) -> None:
    exif = Image.Exif()
    exif[0x010F] = "TestCam"  # EXIF Make tag
    Image.new("RGB", (8, 4)).save(intake_dir / "photo.jpg", exif=exif)

    result = analyze_file("photo.jpg")

    assert result["file_type"] == "image"
    assert result["image"]["format"] == "JPEG"
    assert result["image"]["size"] == [8, 4]
    assert result["image"]["exif"]["Make"] == "TestCam"


def test_ole_with_vba_macros(intake_dir: Path) -> None:
    (intake_dir / "macro.doc").write_bytes(build_ole({
        "WordDocument": b"doc body",
        "Macros/VBA/_VBA_PROJECT": b"\xcc\x61",
        "Macros/VBA/dir": b"vba dir",
    }))

    result = analyze_file("macro.doc")

    assert result["file_type"] == "ole"
    assert result["ole"]["has_vba_macros"] is True
    names = {s["name"]: s["size"] for s in result["ole"]["streams"]}
    assert names == {"WordDocument": 4096, "Macros/VBA/_VBA_PROJECT": 4096, "Macros/VBA/dir": 4096}


def test_ole_without_macros(intake_dir: Path) -> None:
    (intake_dir / "plain.doc").write_bytes(build_ole({"WordDocument": b"doc body"}))

    result = analyze_file("plain.doc")

    assert result["ole"]["has_vba_macros"] is False
    assert result["ole"]["streams"] == [{"name": "WordDocument", "size": 4096}]


def test_malformed_ole_and_unknown(intake_dir: Path) -> None:
    (intake_dir / "broken.doc").write_bytes(OLE_MAGIC + b"\x00" * 504)
    (intake_dir / "junk.bin").write_bytes(b"not a known format")

    broken = analyze_file("broken.doc")
    assert broken["file_type"] == "ole"
    assert "parse_error" in broken["ole"]
    assert analyze_file("junk.bin")["file_type"] == "unknown"


def test_missing_file_rejected(intake_dir: Path) -> None:
    with pytest.raises(ValueError):
        analyze_file("nope")
    (intake_dir / "subdir").mkdir()
    with pytest.raises(ValueError):
        analyze_file("subdir")  # directory, not a file


def test_path_traversal_rejected(intake_dir: Path) -> None:
    for bad in ["../../etc/passwd", "/etc/passwd", "subdir/../../outside.txt"]:
        with pytest.raises(PermissionError):
            analyze_file(bad)


def test_symlink_escape_rejected(intake_dir: Path) -> None:
    (intake_dir / "innocent.pdf").symlink_to("/etc/passwd")
    with pytest.raises(PermissionError):
        analyze_file("innocent.pdf")


def content_pdf(path: Path, contents: list[str]) -> None:
    """One 612 x 792 pt page per content stream in `contents`, with Helvetica as /F1."""
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    for content in contents:
        page = writer.add_blank_page(612, 792)
        page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
        stream = DecodedStreamObject()
        stream.set_data(content.encode("latin-1"))
        page.replace_contents(stream)
    writer.write(path)


@pytest.fixture
def harness_files(intake_dir: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    monkeypatch.setattr(make_files, "OUTPUT_DIR", intake_dir)
    make_files.main()
    return intake_dir


def test_visible_text_is_page_text_and_not_hidden(harness_files: Path) -> None:
    pdf = analyze_file("control_pdf.pdf")["pdf"]

    assert pdf["page_text"] == {"untrusted": True, "truncated": False, "skipped": [], "pages": [
        {"page": 1, "text": "Quarterly facilities update The office is closed on Monday for maintenance."}]}
    assert pdf["hidden_text"]["findings"] == []


def test_white_one_point_injection_reports_both_reasons(harness_files: Path) -> None:
    pdf = analyze_file("pdf_hidden_text.pdf")["pdf"]

    assert pdf["hidden_text"]["findings"] == [{"page": 1, "reasons": ["white_fill", "tiny_font"], "text": make_files.INJECTION}]
    assert make_files.CANARY in pdf["page_text"]["pages"][0]["text"]


@pytest.mark.parametrize("colour", ["1 g", "0.97 g", "1 1 1 rg", "0 0 0 0 k", "/DeviceRGB cs 1 1 1 sc",
                                    "/DeviceGray cs 1 scn", "1 1 1 rg /DeviceGray CS"])
def test_white_fill_alone(intake_dir: Path, colour: str) -> None:
    content_pdf(intake_dir / "white.pdf", [f"{colour} BT /F1 12 Tf 72 300 Td (white words) Tj ET"])

    assert analyze_file("white.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["white_fill"], "text": "white words"}]


def test_fill_colour_that_is_not_white_or_restored_is_not_hidden(intake_dir: Path) -> None:
    content_pdf(intake_dir / "colours.pdf", ["0.5 g BT /F1 12 Tf 72 300 Td (grey) Tj ET "
                                             "q 1 1 1 rg Q BT /F1 12 Tf 72 280 Td (restored) Tj ET "
                                             "1 1 1 rg /DeviceGray cs BT /F1 12 Tf 72 260 Td (reset) Tj ET"])

    assert analyze_file("colours.pdf")["pdf"]["hidden_text"]["findings"] == []


def test_hidden_text_followed_by_visible_text_in_one_run_is_reported(intake_dir: Path) -> None:
    content_pdf(intake_dir / "run.pdf", ["1 1 1 rg BT /F1 12 Tf 72 300 Td [(hidden) -250 (words)] TJ 0 g (shown) Tj ET"])

    [finding] = analyze_file("run.pdf")["pdf"]["hidden_text"]["findings"]

    assert finding["reasons"] == ["white_fill"]
    assert finding["text"].startswith("hidden")


def test_tiny_font_alone(intake_dir: Path) -> None:
    content_pdf(intake_dir / "tiny.pdf", ["BT /F1 1.5 Tf 72 300 Td (tiny words) Tj ET "
                                          "BT /F1 1 Tf 12 0 0 12 72 280 Tm (scaled to 12 pt) Tj ET"])

    assert analyze_file("tiny.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["tiny_font"], "text": "tiny words"}]


def test_invisible_render_mode_alone(intake_dir: Path) -> None:
    content_pdf(intake_dir / "mode.pdf", ["BT 3 Tr /F1 12 Tf 72 300 Td (invisible words) Tj ET "
                                          "BT 0 Tr /F1 12 Tf 72 280 Td (filled words) Tj ET "
                                          "BT 7 Tr /F1 12 Tf 72 260 Td (clip only) Tj ET"])

    assert analyze_file("mode.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["invisible_render_mode"], "text": text} for text in ("invisible words", "clip only")]


def test_off_page_alone(intake_dir: Path) -> None:
    content_pdf(intake_dir / "off.pdf", ["BT /F1 12 Tf 700 300 Td (right of page) Tj ET "
                                         "BT /F1 12 Tf 72 -40 Td (below page) Tj ET "
                                         "1 0 0 1 0 900 cm BT /F1 12 Tf 72 0 Td (moved up by cm) Tj ET"])

    assert analyze_file("off.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["off_page"], "text": text}
        for text in ("right of page", "below page", "moved up by cm")]


def test_canary_off_page_and_in_white_is_reported_with_its_reason(intake_dir: Path) -> None:
    injection = make_files.INJECTION
    content_pdf(intake_dir / "canary.pdf", [f"BT /F1 12 Tf 72 700 Td ({injection}) Tj ET "
                                            f"BT /F1 12 Tf 72 900 Td ({injection}) Tj ET "
                                            f"1 1 1 rg BT /F1 12 Tf 72 300 Td ({injection}) Tj ET"])

    pdf = analyze_file("canary.pdf")["pdf"]

    assert pdf["page_text"]["pages"][0]["text"].count(make_files.CANARY) == 3
    assert pdf["hidden_text"]["findings"] == [{"page": 1, "reasons": ["off_page"], "text": injection},
                                  {"page": 1, "reasons": ["white_fill"], "text": injection}]


def test_page_text_caps(intake_dir: Path) -> None:
    content_pdf(intake_dir / "long.pdf", [f"BT /F1 12 Tf 72 700 Td ({'word ' * 600}) Tj ET"] * 12)
    content_pdf(intake_dir / "many.pdf", [f"BT /F1 12 Tf 72 700 Td (page {n}) Tj ET" for n in range(1, 13)])

    long_text = analyze_file("long.pdf")["pdf"]["page_text"]
    many = analyze_file("many.pdf")["pdf"]["page_text"]

    assert long_text["truncated"] is True
    assert all(len(page["text"]) <= 2000 for page in long_text["pages"])
    assert sum(len(page["text"]) for page in long_text["pages"]) == 6000
    assert many["truncated"] is True
    assert [page["page"] for page in many["pages"]] == list(range(1, 11))
    assert many["pages"][9] == {"page": 10, "text": "page 10"}
    for name, contents in (("wide.pdf", [f"BT /F1 12 Tf 72 700 Td ({'w' * 2001}) Tj ET"]),
                           ("four.pdf", [f"BT /F1 12 Tf 72 700 Td ({'f' * 1999}) Tj ET"] * 4)):
        content_pdf(intake_dir / name, contents)
        assert analyze_file(name)["pdf"]["page_text"]["truncated"] is True, name
    content_pdf(intake_dir / "fits.pdf", [f"BT /F1 12 Tf 72 700 Td ({'f' * 2000}) Tj ET"] * 3)
    assert analyze_file("fits.pdf")["pdf"]["page_text"]["truncated"] is False


def test_hidden_text_caps(intake_dir: Path) -> None:
    content_pdf(intake_dir / "hidden.pdf", ["1 1 1 rg " + " ".join(f"BT /F1 12 Tf 72 {700 - 20 * n} Td (hidden {n}) Tj ET"
                                                                   for n in range(25))
                                            + f" BT /F1 12 Tf 72 100 Td ({'x' * 500}) Tj ET"])
    content_pdf(intake_dir / "one.pdf", [f"1 1 1 rg BT /F1 12 Tf 72 100 Td ({'x' * 500}) Tj ET"])

    assert len(analyze_file("hidden.pdf")["pdf"]["hidden_text"]["findings"]) == 20
    assert analyze_file("one.pdf")["pdf"]["hidden_text"]["findings"][0]["text"] == "x" * 300


def test_pdf_without_text_has_empty_page_text(intake_dir: Path) -> None:
    writer = PdfWriter()
    writer.add_blank_page(width=200, height=200)
    writer.write(intake_dir / "blank.pdf")

    pdf = analyze_file("blank.pdf")["pdf"]

    assert pdf["page_text"] == {"untrusted": True, "pages": [], "skipped": [], "truncated": False}
    assert pdf["hidden_text"]["findings"] == []


def test_controls_keep_every_earlier_key_and_value(harness_files: Path) -> None:
    keyword_counts = dict.fromkeys(["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile", "/URI",
                                    "/AcroForm", "/XFA", "/RichMedia"], 0)
    metadata = {"/Producer": "pypdf", "/Title": "Quarterly facilities update", "/Author": "Facilities team"}
    expected = {
        "control_pdf.pdf": {
            "path": "control_pdf.pdf", "size": 790, "file_type": "pdf",
            "sha256": "cbb4e87caa07bc24763b196cb0ab4e349ea9ec09a4128dcd6bc82b8384654348",
            "pdf": {"keyword_counts": keyword_counts, "encrypted": False, "page_count": 1, "metadata": metadata,
                    "embedded_files": []}},
        "control_pdf_malicious.pdf": {
            "path": "control_pdf_malicious.pdf", "size": 54890, "file_type": "pdf",
            "sha256": "b4c14be9c27d9030580bb67fbeba1937cb87c043fdf3b06094bc193d64765024",
            "pdf": {"keyword_counts": keyword_counts | {"/JS": 2, "/JavaScript": 2, "/OpenAction": 1, "/AA": 1,
                                                        "/Launch": 1, "/EmbeddedFile": 1, "/URI": 2},
                    "encrypted": False, "page_count": 1, "metadata": metadata,
                    "embedded_files": [{"name": "invoice.pdf.exe", "size": 53248, "sha256":
                                        "7f0ab4736f6075ac39fdb10aec383741a0e4d2bec0d4a6bf1a80c73dd71ab4b5"}]}},
    }
    for name, before in expected.items():
        result = analyze_file(name)
        pdf = result.pop("pdf")
        assert result == {key: value for key, value in before.items() if key != "pdf"}, name
        assert {key: value for key, value in pdf.items() if key not in ("page_text", "hidden_text")} == before["pdf"]
        assert set(pdf) == set(before["pdf"]) | {"page_text", "hidden_text"}, name


def test_encrypted_and_corrupt_pdfs_do_not_raise(intake_dir: Path) -> None:
    for name, password in (("open.pdf", ""), ("locked.pdf", "secret")):
        content_pdf(intake_dir / "plain.pdf", ["BT /F1 12 Tf 72 700 Td (encrypted words) Tj ET"])
        writer = PdfWriter(clone_from=intake_dir / "plain.pdf")
        writer.encrypt(user_password=password, owner_password="owner", algorithm="RC4-128")
        writer.write(intake_dir / name)
    content_pdf(intake_dir / "operands.pdf", ["(x) g /F1 Tf BT /F1 12 Tf 72 700 Td (odd operands) Tj ET 1 Tr (y) rg Q Q"])

    opened = analyze_file("open.pdf")["pdf"]
    locked = analyze_file("locked.pdf")["pdf"]
    operands = analyze_file("operands.pdf")["pdf"]

    assert opened["page_text"]["pages"] == [{"page": 1, "text": "encrypted words"}]
    assert "parse_error" in locked
    assert operands["page_text"]["pages"] == [{"page": 1, "text": "odd operands"}]


# Which malformed operands make pypdf raise depends on its version, so the errors are injected.
@pytest.mark.parametrize("error", [TypeError("'NumberObject' object is not iterable"), IndexError("list index out of range"),
                                   LimitReachedError("Limit reached while decompressing.")])
def test_text_extraction_error_keeps_the_other_findings(intake_dir: Path, monkeypatch: pytest.MonkeyPatch,
                                                         error: Exception) -> None:
    content_pdf(intake_dir / "error.pdf", ["BT /F1 12 Tf 72 700 Td (words) Tj ET"])
    writer = PdfWriter(clone_from=intake_dir / "error.pdf")
    writer.add_attachment("payload.txt", b"embedded bytes")
    writer.add_metadata({"/Author": "Test Author"})
    writer.write(intake_dir / "error.pdf")

    def extract_text(*args: object, **kwargs: object) -> str:
        raise error

    monkeypatch.setattr(PageObject, "extract_text", extract_text)
    result = analyze_file("error.pdf")
    pdf = result["pdf"]

    assert pdf["parse_error"] == f"{type(error).__name__}: {error}"
    assert len(result["sha256"]) == 64 and result["file_type"] == "pdf"
    assert pdf["page_count"] == 1 and pdf["metadata"]["/Author"] == "Test Author"
    assert pdf["embedded_files"][0]["name"] == "payload.txt" and pdf["keyword_counts"]["/EmbeddedFile"] >= 1


def test_do_naming_a_missing_xobject_keeps_the_saved_states(intake_dir: Path) -> None:
    content_pdf(intake_dir / "nope.pdf", ["1 g q 0 g /Nope Do Q BT /F1 12 Tf 72 300 Td (white after Q) Tj ET"])

    assert analyze_file("nope.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["white_fill"], "text": "white after Q"}]


def test_reversed_mediabox_is_normalised(intake_dir: Path) -> None:
    content_pdf(intake_dir / "reversed.pdf", ["BT /F1 12 Tf 72 700 Td (inside) Tj ET BT /F1 12 Tf 72 900 Td (above) Tj ET"])
    writer = PdfWriter(clone_from=intake_dir / "reversed.pdf")
    writer.pages[0].mediabox = RectangleObject([612, 792, 0, 0])
    writer.write(intake_dir / "reversed.pdf")

    assert analyze_file("reversed.pdf")["pdf"]["hidden_text"]["findings"] == [{"page": 1, "reasons": ["off_page"], "text": "above"}]


def test_fill_set_inside_a_form_xobject_ends_with_it(intake_dir: Path) -> None:
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    form = DecodedStreamObject()
    form.set_data(b"1 1 1 rg BT /F1 12 Tf 72 300 Td (inside form) Tj ET")
    form.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
                 NameObject("/BBox"): RectangleObject([0, 0, 612, 792]),
                 NameObject("/Resources"): DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})})
    page = writer.add_blank_page(612, 792)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
                                                       NameObject("/XObject"): DictionaryObject({NameObject("/X1"): writer._add_object(form)})})
    stream = DecodedStreamObject()
    stream.set_data(b"/X1 Do BT /F1 12 Tf 72 700 Td (black after form) Tj ET")
    page.replace_contents(stream)
    writer.write(intake_dir / "form.pdf")

    pdf = analyze_file("form.pdf")["pdf"]

    assert "inside form" in pdf["page_text"]["pages"][0]["text"]
    assert pdf["hidden_text"]["findings"] == [{"page": 1, "reasons": ["white_fill"], "text": "inside form"}]


def test_oversized_page_content_is_skipped_and_reported(intake_dir: Path) -> None:
    line = "BT /F1 12 Tf 72 700 Td (" + "A" * 1000 + ") Tj ET\n"
    content_pdf(intake_dir / "big.pdf", ["BT /F1 12 Tf 72 700 Td (small page) Tj ET", line * 100, line * 5200])
    writer = PdfWriter(clone_from=intake_dir / "big.pdf")
    writer.add_attachment("payload.txt", b"embedded bytes")
    add_document_js(writer, "app.alert('hi');")
    writer.write(intake_dir / "big.pdf")

    started = time.monotonic()
    pdf = analyze_file("big.pdf")["pdf"]

    assert pdf["page_text"]["pages"] == [{"page": 1, "text": "small page"}]
    assert pdf["page_text"]["skipped"] == [{"page": 2, "reason": "content_too_large"},
                                           {"page": 3, "reason": "content_too_large"}]
    assert pdf["page_text"]["truncated"] is True
    assert pdf["page_count"] == 3 and pdf["keyword_counts"]["/JavaScript"] >= 1
    assert pdf["embedded_files"][0]["name"] == "payload.txt"
    assert time.monotonic() - started < 5  # skipping bounds the work; unbounded extraction takes several seconds


def test_form_xobject_counts_towards_the_content_cap(intake_dir: Path) -> None:
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    form = DecodedStreamObject()
    form.set_data(("BT /F1 12 Tf 72 700 Td (" + "A" * 1000 + ") Tj ET\n").encode() * 200)
    form.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
                 NameObject("/BBox"): RectangleObject([0, 0, 612, 792]),
                 NameObject("/Resources"): DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})})
    page = writer.add_blank_page(612, 792)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/XObject"): DictionaryObject(
        {NameObject("/X1"): writer._add_object(form)})})
    stream = DecodedStreamObject()
    stream.set_data(b"/X1 Do")
    page.replace_contents(stream)
    writer.write(intake_dir / "form.pdf")

    assert analyze_file("form.pdf")["pdf"]["page_text"]["skipped"] == [{"page": 1, "reason": "content_too_large"}]


def test_flate_bomb_page_is_skipped_and_reported(intake_dir: Path) -> None:
    compressor = zlib.compressobj(9)
    data = compressor.compress(b"BT /F1 12 Tf 72 700 Td (bomb) Tj ET\n")
    data += b"".join(compressor.compress(b" " * 2**20) for _ in range(300)) + compressor.flush()  # 300 MB inflated
    content_pdf(intake_dir / "bomb.pdf", ["BT /F1 12 Tf 72 700 Td (first page) Tj ET", ""])
    writer = PdfWriter(clone_from=intake_dir / "bomb.pdf")
    stream = writer.pages[1]["/Contents"].get_object()
    stream.set_data(b"")
    stream._data = data
    stream[NameObject("/Filter")] = NameObject("/FlateDecode")
    writer.write(intake_dir / "bomb.pdf")

    pdf = analyze_file("bomb.pdf")["pdf"]

    assert pdf["page_text"]["pages"] == [{"page": 1, "text": "first page"}]
    assert pdf["page_text"]["skipped"] == [{"page": 2, "reason": "decode_failed"}]
    assert pdf["page_text"]["truncated"] is True


def test_hidden_text_is_labelled_and_counts_past_the_cap(intake_dir: Path) -> None:
    decoys = " ".join(f"BT /F1 12 Tf 72 {700 - 20 * n} Td (decoy {n}) Tj ET" for n in range(20))
    content_pdf(intake_dir / "decoys.pdf", [f"1 1 1 rg {decoys} BT /F1 12 Tf 72 100 Td (real payload) Tj ET"])

    hidden = analyze_file("decoys.pdf")["pdf"]["hidden_text"]

    assert hidden["untrusted"] is True
    assert hidden["total"] == 21 and hidden["truncated"] is True
    assert [finding["text"] for finding in hidden["findings"]] == [f"decoy {n}" for n in range(20)]


def test_hidden_text_cap_holds_across_pages(intake_dir: Path) -> None:
    page = "1 1 1 rg " + " ".join(f"BT /F1 12 Tf 72 {700 - 20 * n} Td (hidden {n}) Tj ET" for n in range(15))
    content_pdf(intake_dir / "pages.pdf", [page] * 10)
    content_pdf(intake_dir / "fits.pdf", [page] * 1)

    hidden = analyze_file("pages.pdf")["pdf"]["hidden_text"]
    fits = analyze_file("fits.pdf")["pdf"]["hidden_text"]

    assert len(hidden["findings"]) == 20 and hidden["total"] == 150 and hidden["truncated"] is True
    assert [finding["page"] for finding in hidden["findings"]] == [1] * 15 + [2] * 5
    assert len(fits["findings"]) == 15 and fits["total"] == 15 and fits["truncated"] is False


def test_attachment_flate_bomb_keeps_the_other_findings(intake_dir: Path) -> None:
    content_pdf(intake_dir / "attach.pdf", ["BT /F1 12 Tf 72 700 Td (visible words) Tj ET "
                                            "1 1 1 rg BT /F1 12 Tf 72 600 Td (white words) Tj ET"])
    writer = PdfWriter(clone_from=intake_dir / "attach.pdf")
    writer.add_attachment("bomb.bin", b"placeholder")
    writer.add_attachment("payload.txt", b"embedded bytes")
    writer.add_metadata({"/Author": "Test Author"})
    compressor = zlib.compressobj(9)
    [stream] = [obj for obj in writer._objects if isinstance(obj, StreamObject) and obj.get_data() == b"placeholder"]
    stream._data = b"".join(compressor.compress(b"\0" * 2**20) for _ in range(100)) + compressor.flush()  # 100 MB inflated
    stream[NameObject("/Filter")] = NameObject("/FlateDecode")
    writer.write(intake_dir / "attach.pdf")

    result = analyze_file("attach.pdf")
    pdf = result["pdf"]
    files = {entry["name"]: entry for entry in pdf["embedded_files"]}

    assert "parse_error" not in pdf
    assert files["bomb.bin"]["decode_error"].startswith("LimitReachedError: ")
    assert files["payload.txt"]["size"] == len(b"embedded bytes") and len(files["payload.txt"]["sha256"]) == 64
    assert len(result["sha256"]) == 64 and pdf["metadata"]["/Author"] == "Test Author"
    assert pdf["keyword_counts"]["/EmbeddedFile"] >= 1
    assert pdf["page_text"]["pages"] == [{"page": 1, "text": "visible words white words"}]
    assert pdf["hidden_text"]["findings"] == [{"page": 1, "reasons": ["white_fill"], "text": "white words"}]


def ext_gstates(alphas: dict[str, float]) -> DictionaryObject:
    return DictionaryObject({NameObject(f"/{name}"): DictionaryObject({NameObject("/Type"): NameObject("/ExtGState"),
                                                                       NameObject("/ca"): FloatObject(alpha)})
                             for name, alpha in alphas.items()})


def test_transparent_fill_alone(intake_dir: Path) -> None:
    content_pdf(intake_dir / "alpha.pdf", ["q /Clear gs /Width gs BT /F1 12 Tf 72 700 Td (clear words) Tj ET Q "
                                           "/Missing gs gs BT /F1 12 Tf 72 680 Td (restored by Q) Tj ET "
                                           "/Faint gs BT /F1 12 Tf 72 660 Td (faint words) Tj ET "
                                           "/Opaque gs BT /F1 12 Tf 72 640 Td (opaque words) Tj ET"])
    writer = PdfWriter(clone_from=intake_dir / "alpha.pdf")
    states = ext_gstates({"Clear": 0, "Faint": 0.05, "Opaque": 1})
    states[NameObject("/Width")] = DictionaryObject({NameObject("/LW"): FloatObject(2)})  # leaves the alpha as it is
    writer.pages[0]["/Resources"][NameObject("/ExtGState")] = states
    writer.write(intake_dir / "alpha.pdf")

    assert analyze_file("alpha.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["transparent_fill"], "text": text} for text in ("clear words", "faint words")]


@pytest.mark.parametrize("alpha, hidden", [(0.05, True), (0.06, False), (0.5, False)])
def test_transparent_fill_threshold(intake_dir: Path, alpha: float, hidden: bool) -> None:
    content_pdf(intake_dir / "threshold.pdf", ["/A gs BT /F1 12 Tf 72 700 Td (words) Tj ET"])
    writer = PdfWriter(clone_from=intake_dir / "threshold.pdf")
    writer.pages[0]["/Resources"][NameObject("/ExtGState")] = ext_gstates({"A": alpha})
    writer.write(intake_dir / "threshold.pdf")

    assert analyze_file("threshold.pdf")["pdf"]["hidden_text"]["findings"] == (
        [{"page": 1, "reasons": ["transparent_fill"], "text": "words"}] if hidden else [])


@pytest.mark.parametrize("alpha, numeric", [(NumberObject(0), True), (FloatObject(0), True), (TextStringObject("0"), False),
                                            (ArrayObject([NumberObject(0)]), False), ("indirect", True)])
def test_only_a_numeric_ca_sets_the_fill_alpha(intake_dir: Path, alpha: object, numeric: bool) -> None:
    content_pdf(intake_dir / "ca.pdf", ["/A gs BT /F1 12 Tf 72 700 Td (alone) Tj ET "
                                        "/Clear gs /A gs BT /F1 12 Tf 72 680 Td (after clear) Tj ET"])
    writer = PdfWriter(clone_from=intake_dir / "ca.pdf")
    alpha = writer._add_object(NumberObject(0)) if alpha == "indirect" else alpha
    states = ext_gstates({"Clear": 0})
    states[NameObject("/A")] = DictionaryObject({NameObject("/Type"): NameObject("/ExtGState"), NameObject("/ca"): alpha})
    writer.pages[0]["/Resources"][NameObject("/ExtGState")] = states
    writer.write(intake_dir / "ca.pdf")

    assert analyze_file("ca.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["transparent_fill"], "text": text} for text in (["alone"] if numeric else []) + ["after clear"]]


def test_transparent_fill_inside_a_form_xobject_uses_its_resources(intake_dir: Path) -> None:
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    form = DecodedStreamObject()
    form.set_data(b"/Clear gs BT /F1 12 Tf 72 300 Td (inside form) Tj ET")
    form.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
                 NameObject("/BBox"): RectangleObject([0, 0, 612, 792]),
                 NameObject("/Resources"): DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
                                                             NameObject("/ExtGState"): ext_gstates({"Clear": 0})})})
    page = writer.add_blank_page(612, 792)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font}),
                                                       NameObject("/ExtGState"): ext_gstates({"Clear": 1}),
                                                       NameObject("/XObject"): DictionaryObject({NameObject("/X1"): writer._add_object(form)})})
    stream = DecodedStreamObject()
    stream.set_data(b"/X1 Do BT /F1 12 Tf 72 700 Td (after form) Tj ET /Clear gs BT /F1 12 Tf 72 680 Td (page clear) Tj ET")
    page.replace_contents(stream)
    writer.write(intake_dir / "form.pdf")

    assert analyze_file("form.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["transparent_fill"], "text": "inside form"}]


@pytest.mark.parametrize("form_states, hidden", [(None, True), ({"B": 1}, True), ({"A": 1}, False)])
def test_gs_inside_a_form_xobject_falls_back_to_the_page_resources(intake_dir: Path, form_states: dict | None,
                                                                   hidden: bool) -> None:
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    form_resources = DictionaryObject({NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})})
    if form_states is not None:
        form_resources[NameObject("/ExtGState")] = ext_gstates(form_states)
    form = DecodedStreamObject()
    form.set_data(b"/A gs BT /F1 12 Tf 72 300 Td (form text) Tj ET")
    form.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
                 NameObject("/BBox"): RectangleObject([0, 0, 612, 792]), NameObject("/Resources"): form_resources})
    page = writer.add_blank_page(612, 792)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/ExtGState"): ext_gstates({"A": 0}),
                                                       NameObject("/XObject"): DictionaryObject({NameObject("/X1"): writer._add_object(form)})})
    stream = DecodedStreamObject()
    stream.set_data(b"/X1 Do")
    page.replace_contents(stream)
    writer.write(intake_dir / "fallback.pdf")

    assert analyze_file("fallback.pdf")["pdf"]["hidden_text"]["findings"] == (
        [{"page": 1, "reasons": ["transparent_fill"], "text": "form text"}] if hidden else [])


def test_nested_form_xobject_counts_towards_the_content_cap(intake_dir: Path) -> None:
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    forms = []
    for data, resources in ((("BT /F1 12 Tf 72 700 Td (" + "A" * 1000 + ") Tj ET\n").encode() * 200,
                             {NameObject("/Font"): DictionaryObject({NameObject("/F1"): font})}),
                            (b"/X2 Do", {})):
        form = DecodedStreamObject()
        form.set_data(data)
        if forms:
            resources[NameObject("/XObject")] = DictionaryObject({NameObject("/X2"): forms[-1]})
        form.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
                     NameObject("/BBox"): RectangleObject([0, 0, 612, 792]), NameObject("/Resources"): DictionaryObject(resources)})
        forms.append(writer._add_object(form))
    page = writer.add_blank_page(612, 792)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/XObject"): DictionaryObject({NameObject("/X1"): forms[-1]})})
    stream = DecodedStreamObject()
    stream.set_data(b"/X1 Do")
    page.replace_contents(stream)
    writer.write(intake_dir / "nested.pdf")

    assert analyze_file("nested.pdf")["pdf"]["page_text"]["skipped"] == [{"page": 1, "reason": "content_too_large"}]


@pytest.mark.parametrize("page_content, form_content, hidden", [
    (b"0 g /X1 Do", b"1 1 1 rg Q BT /F1 12 Tf 72 300 Td (white inside form) Tj ET", ["white inside form"]),
    (b"1 1 1 rg /X1 Do", b"Q BT /F1 12 Tf 72 300 Td (white from page) Tj ET", ["white from page"]),
    (b"1 1 1 rg /X1 Do", b"0 g Q BT /F1 12 Tf 72 300 Td (black inside form) Tj ET", []),
    (b"1 1 1 rg q 0 g /X1 Do BT /F1 12 Tf 72 700 Td (black after form) Tj ET Q", b"Q", []),
    (b"0 g /X1 Do BT /F1 12 Tf 72 700 Td (black after form) Tj ET", b"1 1 1 rg q", []),
])
def test_unbalanced_q_inside_a_form_xobject_stays_inside_it(intake_dir: Path, page_content: bytes, form_content: bytes,
                                                            hidden: list[str]) -> None:
    writer = PdfWriter()
    font = DictionaryObject({NameObject("/Type"): NameObject("/Font"), NameObject("/Subtype"): NameObject("/Type1"),
                             NameObject("/BaseFont"): NameObject("/Helvetica")})
    fonts = DictionaryObject({NameObject("/F1"): font})
    form = DecodedStreamObject()
    form.set_data(form_content)
    form.update({NameObject("/Type"): NameObject("/XObject"), NameObject("/Subtype"): NameObject("/Form"),
                 NameObject("/BBox"): RectangleObject([0, 0, 612, 792]), NameObject("/Resources"): DictionaryObject({NameObject("/Font"): fonts})})
    page = writer.add_blank_page(612, 792)
    page[NameObject("/Resources")] = DictionaryObject({NameObject("/Font"): fonts,
                                                       NameObject("/XObject"): DictionaryObject({NameObject("/X1"): writer._add_object(form)})})
    stream = DecodedStreamObject()
    stream.set_data(page_content)
    page.replace_contents(stream)
    writer.write(intake_dir / "q.pdf")

    assert analyze_file("q.pdf")["pdf"]["hidden_text"]["findings"] == [
        {"page": 1, "reasons": ["white_fill"], "text": text} for text in hidden]
