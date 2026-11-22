#!/usr/bin/env python3
"""Create a compressed MongoDB archive. Requires MongoDB Database Tools (mongodump)."""
import os
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

uri = os.environ.get("MONGODB_URI")
database = os.environ.get("MONGODB_DATABASE", "aura_log")
if not uri:
    sys.exit("Set MONGODB_URI in the environment; never put credentials in this script.")
if not shutil.which("mongodump"):
    sys.exit("Install MongoDB Database Tools (mongodump) first.")
out_dir = Path(os.environ.get("BACKUP_DIR", "backups"))
out_dir.mkdir(parents=True, exist_ok=True)
archive = out_dir / f"{database}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.archive.gz"
subprocess.run(["mongodump", f"--uri={uri}", f"--db={database}", f"--archive={archive}", "--gzip"], check=True)
print(f"Backup created: {archive}")
