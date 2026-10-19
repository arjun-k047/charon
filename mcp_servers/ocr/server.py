"""
ocr MCP tool server - extract text from an image, or from the images
embedded in a PDF's pages, with pytesseract + Pillow.

PDF pages are never rendered: only image XObjects already embedded in the
file are pulled out (via pypdf) and OCR'd. Reads only from the intake
directory (same guard as the sandbox server).
"""

import io
import logging

import pytesseract
from mcp.server.fastmcp import FastMCP
from PIL import Image, UnidentifiedImageError
from pypdf import PdfReader
from pypdf.errors import PdfReadError

from mcp_servers.sandbox.server import resolve_intake_path

logger = logging.getLogger(__name__)

mcp = FastMCP("ocr")


@mcp.tool()
def extract_text(path: str) -> dict:
    """OCR a file in the intake directory. Images are OCR'd directly; for a
    PDF, every image embedded in each page is OCR'd (pages are not
    rendered, so a text-only PDF yields no results)."""
    resolved = resolve_intake_path(path)
    with open(resolved, "rb") as f:
        is_pdf = b"%PDF" in f.read(1024)
    if not is_pdf:
        try:
            with Image.open(resolved) as img:
                return {"path": path, "file_type": "image", "text": pytesseract.image_to_string(img)}
        except UnidentifiedImageError:
            return {"path": path, "file_type": "unknown", "text": ""}

    results: list[dict] = []
    try:
        reader = PdfReader(resolved)
        for page_number, page in enumerate(reader.pages, start=1):
            for embedded in page.images:
                with Image.open(io.BytesIO(embedded.data)) as img:
                    results.append({
                        "page": page_number,
                        "image": embedded.name,
                        "text": pytesseract.image_to_string(img),
                    })
    except (PdfReadError, ValueError, KeyError, NotImplementedError, UnidentifiedImageError) as exc:
        logger.warning("PDF image extraction failed on %s: %s", resolved, exc)
        return {"path": path, "file_type": "pdf", "images": results, "parse_error": f"{type(exc).__name__}: {exc}"}
    return {"path": path, "file_type": "pdf", "images": results}


if __name__ == "__main__":
    mcp.run()
