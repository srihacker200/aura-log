"""Normalize legacy over-escaped email regexes before launching the app."""
from pathlib import Path

app = Path(__file__).resolve().parents[1] / "app.py"
source = app.read_text(encoding="utf-8")
backslash = chr(92)
lines = source.splitlines(keepends=True)
changed = 0
email_regex_count = 0
for index, line in enumerate(lines):
    if 're.fullmatch(r"' in line and "@" in line:
        email_regex_count += 1
        normalized = line.replace(backslash * 2, backslash)
        if normalized != line:
            lines[index] = normalized
            changed += 1
source = "".join(lines)
if not email_regex_count:
    raise SystemExit("No email validators found; refusing to deploy.")
for line in source.splitlines():
    if 're.fullmatch(r"' in line and "@" in line and backslash * 2 in line:
        raise SystemExit("Email validator still contains doubled backslashes.")
app.write_text(source, encoding="utf-8")
print(f"Email validators checked: {email_regex_count}; corrected: {changed}.")
