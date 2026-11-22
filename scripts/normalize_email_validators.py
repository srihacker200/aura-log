"""Normalize over-escaped email regexes in app.py before starting the service."""
from pathlib import Path

app = Path(__file__).resolve().parents[1] / "app.py"
source = app.read_text(encoding="utf-8")
slash = chr(92)
lines = source.splitlines(keepends=True)
changed = 0
for index, line in enumerate(lines):
    if "re.fullmatch(r\"" in line and "@" in line and "\\\\" in line:
        lines[index] = line.replace(slash * 2, slash)
        changed += 1
source = "".join(lines)
app.write_text(source, encoding="utf-8")

# Verify every email-validation regex uses a single escape for whitespace and dots.
for line in source.splitlines():
    if "re.fullmatch(r\"" in line and "@" in line:
        if slash * 2 in line:
            raise SystemExit("Email validator still contains doubled backslashes.")
        if "\\s" not in line or "\\." not in line:
            raise SystemExit("Email validator verification failed.")
print(f"Email validator normalization passed ({changed} line(s) corrected).")
