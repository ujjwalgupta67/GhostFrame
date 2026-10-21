from __future__ import annotations

import io

from PIL import Image

from ..security import MAX_IMAGE_PIXELS, UnsafeFileError


def sanitize_image(data: bytes, file_type: str) -> tuple[bytes, list[str]]:
    output = io.BytesIO()
    try:
        with Image.open(io.BytesIO(data)) as image:
            if image.width * image.height > MAX_IMAGE_PIXELS:
                raise UnsafeFileError("This image exceeds the 50-megapixel safety limit.")
            if getattr(image, "n_frames", 1) > 1:
                raise UnsafeFileError("Animated or multi-frame images are not supported because frames could be lost.")
            image.load(); pixels = image.copy()
            preserved = {}
            if image.info.get("icc_profile"):
                preserved["icc_profile"] = image.info["icc_profile"]
            if image.info.get("dpi"):
                preserved["dpi"] = image.info["dpi"]
            if file_type == "jpg":
                if pixels.mode not in {"RGB", "L"}:
                    pixels = pixels.convert("RGB")
                pixels.save(output, format="JPEG", quality=95, optimize=True, **preserved)
            else:
                pixels.save(output, format="PNG", optimize=True, **preserved)
    except UnsafeFileError:
        raise
    except (OSError, ValueError) as exc:
        raise UnsafeFileError("The image could not be sanitized because it is damaged or unsupported.") from exc
    return output.getvalue(), ["Re-encoded pixel data without EXIF, GPS, XMP, IPTC, comments, or textual metadata."]
