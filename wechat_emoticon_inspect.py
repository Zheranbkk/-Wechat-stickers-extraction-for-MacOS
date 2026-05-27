#!/usr/bin/env python3
"""
wechat_emoticon_inspect.py

READ-ONLY format inspection for WeChat emoticon (sticker) storage on macOS.

This is step 2 of discovery. Step 1 (wechat_sticker_discovery.py) located the
likely sticker directories. This script looks *only* at the confirmed emoticon
folders and classifies the file formats found there, so we can later build a
correct, copy-based exporter.

Scope (the ONLY things this script touches)
-------------------------------------------
Under the account folder(s) inside:

    ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files/

it inspects exclusively:

    <account>/business/emoticon
    <account>/cache/*/Emoticon

Nothing else is opened or walked.

Safety guarantees (by construction)
-----------------------------------
  * It NEVER writes, moves, renames, deletes, decrypts, or overwrites any
    WeChat file. The only file written is the Markdown report.
  * It NEVER opens message / contact / favourite / session databases. Any file
    that looks database-like (by extension or name) is recorded but NOT read.
  * It does NOT walk FileStorage or any directory outside the emoticon targets.
  * Account folder names (wxid_* / hashes / uuids) are anonymised in all
    output. Full private paths are never printed.
  * It reads at most the first 512 bytes of each (non-database) file, purely to
    identify a format signature. No file is read in full.
  * It exports NOTHING. Inspection only.

Usage
-----
    python3 wechat_emoticon_inspect.py
    python3 wechat_emoticon_inspect.py --out emoticon_format_report.md

Run it on the macOS machine where WeChat is installed and logged in.
"""

from __future__ import annotations

import argparse
import os
import re
import sys
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------- #
# Configuration
# --------------------------------------------------------------------------- #

HOME = Path.home()

XWECHAT_ROOT = (
    HOME
    / "Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files"
)

# Sub-paths to inspect, relative to a single account folder.
BUSINESS_EMOTICON_REL = ("business", "emoticon")
CACHE_EMOTICON_GLOB = "cache/*/Emoticon"  # relative to account folder

# Files we refuse to open for byte sampling (defensive — should not appear in
# the emoticon dirs, but we never want to read a database by accident).
DB_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm", ".db-journal"}
DB_NAME_TOKENS = [
    "msg",
    "message",
    "contact",
    "session",
    "favorite",
    "favourite",
    "fav.archive",
    "wccontact",
    "fts",
]

# Magic-byte signatures looked for at offset 0 and, for unknowns, within 512 B.
SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG"),
    (b"\xff\xd8\xff", "JPEG"),
    (b"GIF87a", "GIF"),
    (b"GIF89a", "GIF"),
    (b"PK\x03\x04", "ZIP"),
    (b"SQLite format 3\x00", "SQLite"),
    (b"bplist", "bplist"),
]

READ_BYTES = 512          # max bytes read from any file
HEX_PREVIEW_BYTES = 64    # bytes shown as hex in the report
MAX_FILES_PER_DIR = 200_000  # safety cap so the scan stays bounded
LARGEST_N = 20

# --------------------------------------------------------------------------- #
# Anonymisation
# --------------------------------------------------------------------------- #

_ACCOUNT_PATTERNS = [
    re.compile(r"^wxid_[A-Za-z0-9]+$"),
    re.compile(r"^[0-9a-fA-F]{16,}$"),                  # md5-like account hashes
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}$"),  # uuid-like
]

_anon_map: dict[str, str] = {}
_anon_counter = [0]


def _looks_like_account(component: str) -> bool:
    return any(p.match(component) for p in _ACCOUNT_PATTERNS)


def _anon_component(component: str) -> str:
    if component in _anon_map:
        return _anon_map[component]
    _anon_counter[0] += 1
    placeholder = f"user_{_anon_counter[0]}"
    _anon_map[component] = placeholder
    return placeholder


def anon_rel(rel: str) -> str:
    """Anonymise any account-like components inside a relative path string."""
    parts = Path(rel).parts
    return "/".join(
        _anon_component(p) if _looks_like_account(p) else p for p in parts
    )


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def human_size(num_bytes: int) -> str:
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024.0:
            return f"{size:.1f} {unit}" if unit != "B" else f"{int(size)} {unit}"
        size /= 1024.0
    return f"{size:.1f} PB"


def hexdump(b: bytes) -> str:
    return " ".join(f"{x:02x}" for x in b)


def is_database_like(name: str) -> bool:
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    if ext in DB_EXTENSIONS:
        return True
    return any(token in lower for token in DB_NAME_TOKENS)


def detect_type(buf: bytes) -> str:
    """Classify by signature at offset 0."""
    if not buf:
        return "empty"
    if buf[0:4] == b"RIFF" and buf[8:12] == b"WEBP":
        return "WEBP"
    for sig, label in SIGNATURES:
        if buf.startswith(sig):
            return label
    return "unknown"


def scan_within(buf: bytes) -> list[tuple[str, int]]:
    """Find known signatures anywhere in the first READ_BYTES bytes.

    Returns a list of (type, offset) sorted by offset. Used for 'unknown'
    files where the signature may sit behind a small header/wrapper.
    """
    hits: list[tuple[str, int]] = []

    # WEBP needs RIFF at offset, 'WEBP' at offset+8.
    i = buf.find(b"WEBP")
    while i != -1:
        if i >= 8 and buf[i - 8 : i - 4] == b"RIFF":
            hits.append(("WEBP", i - 8))
        i = buf.find(b"WEBP", i + 1)

    for sig, label in SIGNATURES:
        j = buf.find(sig)
        if j != -1:
            hits.append((label, j))

    hits.sort(key=lambda t: t[1])
    return hits


def safe_stat_size(path: str) -> int:
    try:
        return os.stat(path, follow_symlinks=False).st_size
    except OSError:
        return 0


# --------------------------------------------------------------------------- #
# Account / target discovery
# --------------------------------------------------------------------------- #

def find_account_dirs(root: Path) -> list[Path]:
    """Direct children of xwechat_files that actually contain emoticon data."""
    accounts: list[Path] = []
    if not root.exists():
        return accounts
    try:
        children = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return accounts

    for child in children:
        has_business = (child.joinpath(*BUSINESS_EMOTICON_REL)).is_dir()
        cache_dir = child / "cache"
        has_cache = False
        if cache_dir.is_dir():
            try:
                has_cache = any(cache_dir.glob("*/Emoticon"))
            except OSError:
                has_cache = False
        if has_business or has_cache:
            accounts.append(child)
    return accounts


def target_dirs_for_account(account: Path) -> list[tuple[str, Path]]:
    """Return (label, absolute_path) for each emoticon target under an account.

    label is the account-relative path, e.g. 'business/emoticon' or
    'cache/2026-04/Emoticon'. Account name is never part of the label.
    """
    targets: list[tuple[str, Path]] = []

    business = account.joinpath(*BUSINESS_EMOTICON_REL)
    if business.is_dir():
        targets.append(("business/emoticon", business))

    cache_dir = account / "cache"
    if cache_dir.is_dir():
        try:
            for emo in sorted(cache_dir.glob("*/Emoticon")):
                if emo.is_dir():
                    label = "/".join(("cache",) + emo.relative_to(cache_dir).parts)
                    targets.append((label, emo))
        except OSError:
            pass

    return targets


# --------------------------------------------------------------------------- #
# File inspection
# --------------------------------------------------------------------------- #

class FileRecord:
    __slots__ = (
        "rel",          # anonymised path relative to the account folder
        "folder",       # target label, e.g. 'business/emoticon'
        "size",
        "ext",
        "head_hex",     # hex of first HEX_PREVIEW_BYTES bytes ('' if not read)
        "dtype",        # detected type
        "within",       # list[(type, offset)] for unknowns
    )

    def __init__(self, rel, folder, size, ext, head_hex, dtype, within):
        self.rel = rel
        self.folder = folder
        self.size = size
        self.ext = ext
        self.head_hex = head_hex
        self.dtype = dtype
        self.within = within


def inspect_file(full: str, account: Path, folder_label: str) -> FileRecord:
    name = os.path.basename(full)
    size = safe_stat_size(full)
    ext = os.path.splitext(name)[1].lower() or "(none)"

    rel_to_account = os.path.relpath(full, account)
    rel_safe = anon_rel(rel_to_account)

    if is_database_like(name):
        return FileRecord(
            rel_safe, folder_label, size, ext,
            head_hex="", dtype="skipped (database — not opened)", within=[],
        )

    try:
        with open(full, "rb") as fh:
            buf = fh.read(READ_BYTES)
    except OSError as exc:
        return FileRecord(
            rel_safe, folder_label, size, ext,
            head_hex="", dtype=f"unreadable ({exc.errno})", within=[],
        )

    dtype = detect_type(buf)
    within = scan_within(buf) if dtype == "unknown" else []
    head_hex = hexdump(buf[:HEX_PREVIEW_BYTES])

    return FileRecord(rel_safe, folder_label, size, ext, head_hex, dtype, within)


def inspect_target(label: str, path: Path, account: Path) -> list[FileRecord]:
    records: list[FileRecord] = []
    count = 0
    try:
        for dirpath, _dirnames, filenames in os.walk(path, followlinks=False):
            for f in sorted(filenames):
                full = os.path.join(dirpath, f)
                # Only regular files (skip symlinks/sockets/etc.).
                try:
                    if not os.path.isfile(full) or os.path.islink(full):
                        continue
                except OSError:
                    continue
                records.append(inspect_file(full, account, label))
                count += 1
                if count >= MAX_FILES_PER_DIR:
                    return records
    except OSError:
        pass
    return records


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def account_label(index: int, total: int) -> str:
    return "<account>" if total == 1 else f"<account_{index}>"


def generate_report(
    root_exists: bool,
    accounts: list[Path],
    per_account: list[tuple[str, list[tuple[str, Path]], list[FileRecord]]],
) -> str:
    lines: list[str] = []
    add = lines.append

    add("# WeChat Emoticon Format — Inspection Report")
    add("")
    add(f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"- Platform: {sys.platform}")
    add("- Mode: **read-only** — no WeChat file modified; databases never opened.")
    add(f"- Bytes read per file: at most **{READ_BYTES}** (signature detection only).")
    add("- Scope: only `business/emoticon` and `cache/*/Emoticon` under each account.")
    add("- Paths are anonymised (`<account>`, `user_N`).")
    add("")

    if not root_exists:
        add("> **xwechat_files root not found.**")
        add("> Expected at "
            "`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files`.")
        add("> Confirm WeChat 4.x is installed and logged in, then re-run.")
        add("")
        return "\n".join(lines) + "\n"

    if not accounts:
        add("> xwechat_files exists, but no account folder containing")
        add("> `business/emoticon` or `cache/*/Emoticon` was found.")
        add("")
        return "\n".join(lines) + "\n"

    # ---- Per-account inspected directories ------------------------------- #
    add("## Inspected directories")
    add("")
    add("| Account | Directory | Files | Approx. size |")
    add("| ------- | --------- | ----- | ------------ |")
    for label, targets, records in per_account:
        by_folder_size: dict[str, int] = {}
        by_folder_count: dict[str, int] = {}
        for rec in records:
            by_folder_count[rec.folder] = by_folder_count.get(rec.folder, 0) + 1
            by_folder_size[rec.folder] = by_folder_size.get(rec.folder, 0) + rec.size
        for tgt_label, _path in targets:
            n = by_folder_count.get(tgt_label, 0)
            sz = by_folder_size.get(tgt_label, 0)
            add(f"| `{label}` | `{tgt_label}` | {n} | {human_size(sz)} |")
    add("")

    # Combined corpus across all accounts for the global summary.
    all_records: list[FileRecord] = []
    for _label, _targets, records in per_account:
        all_records.extend(records)

    total_files = len(all_records)
    total_size = sum(r.size for r in all_records)

    # ---- Summary --------------------------------------------------------- #
    add("## Summary")
    add("")
    add(f"- **Total files:** {total_files}")
    add(f"- **Total size:** {human_size(total_size)}")
    add("")

    # Count by detected type.
    by_type_count: dict[str, int] = {}
    by_type_size: dict[str, int] = {}
    for r in all_records:
        by_type_count[r.dtype] = by_type_count.get(r.dtype, 0) + 1
        by_type_size[r.dtype] = by_type_size.get(r.dtype, 0) + r.size

    add("### Count by detected type")
    add("")
    add("| Detected type | Files | Total size |")
    add("| ------------- | ----- | ---------- |")
    for dtype in sorted(by_type_count, key=lambda k: (-by_type_count[k], k)):
        add(f"| {dtype} | {by_type_count[dtype]} | {human_size(by_type_size[dtype])} |")
    add("")

    # Count by top-level folder (target label, per account).
    add("### Count by folder")
    add("")
    add("| Account | Folder | Files | Total size |")
    add("| ------- | ------ | ----- | ---------- |")
    for label, _targets, records in per_account:
        fc: dict[str, int] = {}
        fs: dict[str, int] = {}
        for r in records:
            fc[r.folder] = fc.get(r.folder, 0) + 1
            fs[r.folder] = fs.get(r.folder, 0) + r.size
        for folder in sorted(fc, key=lambda k: (-fs[k], k)):
            add(f"| `{label}` | `{folder}` | {fc[folder]} | {human_size(fs[folder])} |")
    add("")

    # ---- Largest N files ------------------------------------------------- #
    add(f"### Largest {LARGEST_N} files")
    add("")
    add("| # | Folder | File | Size | Ext | Detected type |")
    add("| - | ------ | ---- | ---- | --- | ------------- |")
    largest = sorted(all_records, key=lambda r: r.size, reverse=True)[:LARGEST_N]
    for i, r in enumerate(largest, 1):
        base = os.path.basename(r.rel)
        add(f"| {i} | `{r.folder}` | `{base}` | {human_size(r.size)} | "
            f"{r.ext} | {r.dtype} |")
    add("")

    # ---- One hex sample per detected type -------------------------------- #
    add("### One hex sample per detected type")
    add("")
    seen_types: set[str] = set()
    for r in all_records:
        if r.dtype in seen_types or not r.head_hex:
            continue
        seen_types.add(r.dtype)
        add(f"**{r.dtype}** — `{r.rel}` ({human_size(r.size)}, ext `{r.ext}`)")
        add("")
        add("```")
        add(r.head_hex)
        add("```")
        add("")

    # ---- Unknown files detail ------------------------------------------- #
    unknowns = [r for r in all_records if r.dtype == "unknown"]
    add(f"## Unknown files ({len(unknowns)})")
    add("")
    if not unknowns:
        add("> No unknown-format files — every readable file matched a known "
            "signature at offset 0.")
        add("")
    else:
        add("Files whose first bytes matched no known signature. For each we show "
            f"the first {HEX_PREVIEW_BYTES} bytes and any known signature found "
            f"within the first {READ_BYTES} bytes.")
        add("")
        shown = unknowns[:200]  # keep the report bounded
        for r in shown:
            add(f"#### `{r.rel}`")
            add(f"- Folder: `{r.folder}`")
            add(f"- Size: {human_size(r.size)}")
            add(f"- Extension: {r.ext}")
            if r.within:
                hits = ", ".join(f"{t} @ offset {off}" for t, off in r.within[:6])
                add(f"- Signature(s) within first {READ_BYTES} bytes: {hits}")
            else:
                add(f"- No known signature within first {READ_BYTES} bytes.")
            add(f"- First {HEX_PREVIEW_BYTES} bytes:")
            add("")
            add("  ```")
            add("  " + r.head_hex)
            add("  ```")
            add("")
        if len(unknowns) > len(shown):
            add(f"> ...and {len(unknowns) - len(shown)} more unknown files "
                "(omitted to keep the report readable).")
            add("")

    # ---- Safety recap ---------------------------------------------------- #
    add("## Safety recap")
    add("")
    add("- Only `business/emoticon` and `cache/*/Emoticon` were walked.")
    add("- Database-like files were recorded but **never opened**.")
    add(f"- At most {READ_BYTES} bytes were read per file; nothing was exported.")
    add("- FileStorage and message/contact/favourite stores were not touched.")
    add("")

    # ---- Next step ------------------------------------------------------- #
    add("## What to paste back")
    add("")
    add("1. The **Summary** section (totals, count-by-type, count-by-folder).")
    add("2. The **Largest 20 files** table.")
    add("3. The **One hex sample per detected type** block.")
    add("4. The **Unknown files** section (especially any 'Signature(s) within' lines).")
    add("")
    add("That tells us exactly which formats the exporter must handle and "
        "whether any files are wrapped/obfuscated before we write a copy-based "
        "exporter.")
    add("")

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only WeChat emoticon format inspection (macOS).",
    )
    parser.add_argument(
        "--out",
        default="emoticon_format_report.md",
        help="Markdown report path (default: emoticon_format_report.md)",
    )
    args = parser.parse_args()

    if sys.platform != "darwin":
        print("[note] This tool targets macOS; paths assume macOS WeChat 4.x.",
              file=sys.stderr)

    root_exists = XWECHAT_ROOT.exists()
    accounts = find_account_dirs(XWECHAT_ROOT)

    per_account: list[tuple[str, list[tuple[str, Path]], list[FileRecord]]] = []
    for idx, account in enumerate(accounts, 1):
        label = account_label(idx, len(accounts))
        targets = target_dirs_for_account(account)
        records: list[FileRecord] = []
        for tgt_label, tgt_path in targets:
            records.extend(inspect_target(tgt_label, tgt_path, account))
        per_account.append((label, targets, records))

    report = generate_report(root_exists, accounts, per_account)

    out_path = Path(args.out).expanduser()
    out_path.write_text(report, encoding="utf-8")

    # Short, anonymised console summary.
    print(f"Report written to: {out_path}")
    print("-" * 60)
    if not root_exists:
        print("  xwechat_files root not found — see report for guidance.")
    elif not accounts:
        print("  No account folder with emoticon data found.")
    else:
        for label, targets, records in per_account:
            total = len(records)
            size = sum(r.size for r in records)
            print(f"  {label}: {total} files, {human_size(size)}, "
                  f"{len(targets)} target dir(s)")
    print("-" * 60)
    print("Open emoticon_format_report.md and paste back the sections it lists.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
