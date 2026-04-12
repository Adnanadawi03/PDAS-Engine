import re, io, zipfile
from collections import Counter
from typing import Tuple, Dict

def _shannon_entropy(b: bytes) -> float:
    if not b:
        return 0.0
    c = Counter(b)
    total = len(b)
    import math
    return -sum((n/total) * math.log2(n/total) for n in c.values())

def sniff_type_and_features(file_bytes: bytes, filename: str) -> Tuple[str, Dict]:
    name = (filename or "").lower()
    features = {
        "size": len(file_bytes),
        "ext": name.rsplit(".",1)[-1] if "." in name else "",
        "url_count": len(re.findall(rb"https?://[^\s<>\"']+", file_bytes, flags=re.I)),
        "entropy": _shannon_entropy(file_bytes[:200_000]),
    }

    if file_bytes.startswith(b"%PDF"):
        ftype = "pdf"
        features["pdf_has_js"] = b"/JavaScript" in file_bytes
        features["pdf_has_openaction"] = (b"/OpenAction" in file_bytes) or (b"/AA" in file_bytes)
    elif file_bytes.startswith(b"MZ"):
        ftype = "pe"
        for s in (b"powershell", b"cmd.exe", b"rundll32", b"CreateRemoteThread"):
            features[f"pe_str_{s.decode('latin1')}"] = (s in file_bytes)
    elif file_bytes.startswith(b"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"):
        ftype = "ole"
        features["has_macros"] = True
    elif file_bytes.startswith(b"PK\x03\x04"):
        ftype = "ooxml"
        try:
            z = zipfile.ZipFile(io.BytesIO(file_bytes))
            names = set(z.namelist())
            features["ooxml_word"]  = any(n.startswith("word/") for n in names)
            features["ooxml_excel"] = any(n.startswith("xl/")   for n in names)
            features["has_macros"]  = any("vbaProject.bin" in n for n in names)
        except Exception:
            features["zip_broken"] = True
    else:
        ftype = "other"

    features["type"] = ftype
    return ftype, features
