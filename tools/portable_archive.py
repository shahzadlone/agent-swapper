"""Conservative cross-platform checks for archive-entry names."""
from pathlib import PurePosixPath
import unicodedata


def safe_path(name):
    path = PurePosixPath(name)
    if not name or path.is_absolute() or "\\" in name or unicodedata.normalize("NFC", name) != name:
        raise ValueError("unsafe or non-normalized archive entry")
    reserved = {"CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)), *(f"LPT{i}" for i in range(1, 10)),
                *(f"{prefix}{digit}" for prefix in ("COM", "LPT") for digit in "¹²³")}
    for part in name.split("/"):
        if (part in ("", ".", "..") or part.endswith((" ", "."))
                or part.split(".", 1)[0].upper() in reserved
                or any(c in '<>:"|?*' or unicodedata.category(c).startswith("C")
                       or unicodedata.category(c) in ("Zl", "Zp") for c in part)):
            raise ValueError("unsafe or nonportable archive entry")
    return str(path)


def ensure_portable_names(names):
    seen = set()
    for name in names:
        safe_path(name)
        key = name.casefold()
        if key in seen:
            raise ValueError("archive contains case-colliding entries")
        seen.add(key)
    for key in seen:
        parts = key.split("/")
        if any("/".join(parts[:index]) in seen for index in range(1, len(parts))):
            raise ValueError("archive contains a file/directory name conflict")
