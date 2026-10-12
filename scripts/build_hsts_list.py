"""Build sitewarden/data/hsts-preload.txt.gz from Chromium's transport_security_state_static.json.

Each line is "<name> <i|e>": i = includeSubDomains, e = exact host only.
"""
import gzip
import json
import pathlib
import re
import sys


def build(src: pathlib.Path, dst: pathlib.Path) -> int:
    text = src.read_text()
    text = re.sub(r"^\s*//.*$", "", text, flags=re.M)
    data = json.loads(text)
    lines = []
    for e in data["entries"]:
        if e.get("mode") != "force-https":
            continue
        lines.append(f"{e['name'].lower()} {'i' if e.get('include_subdomains') else 'e'}")
    lines.sort()
    with gzip.open(dst, "wt", compresslevel=9) as fh:
        fh.write("\n".join(lines) + "\n")
    return len(lines)


if __name__ == "__main__":
    src = pathlib.Path(sys.argv[1])
    dst = pathlib.Path(__file__).resolve().parents[1] / "sitewarden" / "data" / "hsts-preload.txt.gz"
    print(build(src, dst), "entries ->", dst)
