import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
py_files = sorted(root.rglob('*.py'))

triple_single = re.compile(r"'''(.*?)'''", re.S)
triple_double = re.compile(r'"""(.*?)"""', re.S)

for p in py_files:
    try:
        text = p.read_text(encoding='utf-8')
    except Exception:
        try:
            text = p.read_text(encoding='latin-1')
        except Exception:
            continue

    cleaned = triple_single.sub('', text)
    cleaned = triple_double.sub('', cleaned)

    lines = cleaned.splitlines()
    comment_lines = []
    for i, line in enumerate(lines, start=1):
        if line.lstrip().startswith('#'):
            comment_lines.append((i, line.rstrip()))

    if comment_lines:
        print(f"FILE: {p.relative_to(root)}")
        for ln, content in comment_lines:
            print(f"  {ln:4d}: {content}")
        print()
