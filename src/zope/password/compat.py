import sys

PY3 = sys.version_info[0] == 3

if PY3:
    text_type = str
    bytes_type = bytes
else:
    text_type = unicode
    bytes_type = str
