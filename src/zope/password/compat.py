import sys

PY3 = sys.version_info[0] == 3

text_type = str if bytes is not str else unicode
bytes_type = bytes
