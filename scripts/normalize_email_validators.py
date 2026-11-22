"""Normalize legacy over-escaped email regex literals before launching the app."""
from pathlib import Path

app = Path(__file__).resolve().parents[1] / "app.py"
source = app.read_text(encoding="utf-8")
malformed = 'r"[^@\\\\s]+@[^@\\\\s]+\\\\.[^@\\\\s]+"'
correct = 'r"[^@\\s]+@[^@\\s]+\\.[^@\\s]+"'
count = source.count(malformed)
if count:
    source = source.replace(malformed, correct)
    app.write_text(source, encoding="utf-8")
if malformed in source or correct not in source:
    raise SystemExit("Email validator normalization failed; refusing to build.")
print(f"Email validator check passed; corrected {count} over-escaped pattern(s).")
