import shutil
from pathlib import Path

import pytest
from PIL import Image, ImageDraw, ImageFont

from mcp_servers.ocr.server import extract_text

needs_tesseract = pytest.mark.skipif(shutil.which("tesseract") is None, reason="tesseract binary not installed")


pytestmark = pytest.mark.usefixtures("intake_dir")


def text_image(text: str) -> Image.Image:
    img = Image.new("RGB", (900, 120), "white")
    ImageDraw.Draw(img).text((20, 30), text, fill="black", font=ImageFont.load_default(size=48))
    return img


@needs_tesseract
def test_png(intake_dir: Path) -> None:
    text_image("VERIFY YOUR ACCOUNT").save(intake_dir / "phish.png")

    result = extract_text("phish.png")

    assert result["file_type"] == "image"
    assert "VERIFY YOUR ACCOUNT" in result["text"]


@needs_tesseract
def test_pdf_embedded_image(intake_dir: Path) -> None:
    text_image("INVOICE OVERDUE").save(intake_dir / "scan.pdf")  # Pillow embeds the image in a 1-page PDF

    result = extract_text("scan.pdf")

    assert result["file_type"] == "pdf"
    assert result["images"][0]["page"] == 1
    assert "INVOICE OVERDUE" in result["images"][0]["text"]


def test_unknown_file_skips_ocr(intake_dir: Path) -> None:
    (intake_dir / "junk.bin").write_bytes(b"not an image")
    assert extract_text("junk.bin") == {"path": "junk.bin", "file_type": "unknown", "text": ""}


def test_path_traversal_rejected(intake_dir: Path) -> None:
    for bad in ["../../etc/passwd", "/etc/passwd"]:
        with pytest.raises(PermissionError):
            extract_text(bad)
