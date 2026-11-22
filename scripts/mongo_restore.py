#!/usr/bin/env python3
"""Restore an archive only after explicit confirmation; this overwrites matching collections."""
import os
import shutil
import subprocess
import sys
from pathlib import Path

uri = os.environ.get("MONGODB_URI")
database = os.environ.get("MONGODB_DATABASE", "aura_log")
archive = Path(sys.argv[1]) if len(sys.argv) > 1 else None
if not uri or not archive or not archive.is_file():
    sys.exit("Usage: MONGODB_URI=... python scripts/mongo_restore.py BACKUP.archive.gz")
if os.environ.get("CONFIRM_RESTORE") != "YES":
    sys.exit("Restore overwrites collections. Set CONFIRM_RESTORE=YES only after verifying the archive and target database.")
if not shutil.which("mongorestore"):
    sys.exit("Install MongoDB Database Tools (mongorestore) first.")
subprocess.run(["mongorestore", f"--uri={uri}", f"--archive={archive}", "--gzip", "--drop", f"--nsInclude={database}.*"], check=True)
print(f"Restore completed for database {database}.")
