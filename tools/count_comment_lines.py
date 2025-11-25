import re
from pathlib import Path

root = Path(__file__).resolve().parents[1]
py_files = list(root.rglob('*.py'))

results = []
total = 0

triple_single = re.compile(r"'''(.*?)'''", re.S)
triple_double = re.compile(r'"""(.*?)"""', re.S)

for p in sorted(py_files):
    try:
        text = p.read_text(encoding='utf-8')
    except Exception:
        try:
            text = p.read_text(encoding='latin-1')
        except Exception:
            continue

    cleaned = triple_single.sub('', text)
    cleaned = triple_double.sub('', cleaned)

    count = 0
    for line in cleaned.splitlines():
        s = line.lstrip()
        if s.startswith('#'):
            count += 1
    if count > 0:
        results.append((str(p.relative_to(root)), count))
        total += count

for fname, cnt in results:
    print(f"{cnt:5d}  {fname}")
print('-----')
print(f"Total comment-only lines to delete: {total}")
print(f"Files with removable comment-only lines: {len(results)}")
