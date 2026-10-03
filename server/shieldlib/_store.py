"""Location of the library's private data (hidden folder)."""
import os
import sys

LIB_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(LIB_DIR, ".data")
USER_AGENT = "SAYNO/2.0 (+personal scam scanner)"

os.makedirs(DATA_DIR, exist_ok=True)
if sys.platform == "win32":
    try:  # FILE_ATTRIBUTE_HIDDEN
        import ctypes
        ctypes.windll.kernel32.SetFileAttributesW(DATA_DIR, 0x02)
    except Exception:
        pass
