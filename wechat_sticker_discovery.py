#!/usr/bin/env python3
"""
wechat_sticker_discovery.py

READ-ONLY diagnostic for locating WeChat sticker / custom-emotion / favourite
storage on macOS. It writes a single Markdown report and touches nothing else.

Why this exists
---------------
Before building any exporter we need to know *where* WeChat keeps stickers on
this particular machine/WeChat version. This script answers that question
without ever reading private data.

Safety guarantees (by construction)
-----------------------------------
  * It NEVER writes, moves, renames, deletes, decrypts, or modifies any WeChat
    file. The only file written is the report in the current directory.
  * It only calls stat() (for size/count) and, for a tiny SAMPLE of files,
    reads at most the first 16 bytes to identify a magic-byte signature.
  * It NEVER opens anything that looks like a chat / message / contact
    database (those files are detected and skipped, not read).
  * It searches ONLY inside known WeChat base directories, never the whole
    home folder.
  * Usernames, account hashes and wxid_* folder names are anonymised
    (user_1, user_2, ...) in every line of output.
  * It produces NO exporter. Discovery only.

Usage
-----
    python3 wechat_sticker_discovery.py
    python3 wechat_sticker_discovery.py --out my_report.md

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

# Base locations to probe. We search recursively ONLY inside these.
BASE_LOCATIONS = [
    HOME / "Library/Containers/com.tencent.xinWeChat/Data/Library/Application Support/com.tencent.xinWeChat",
    HOME / "Documents/WeChat Files",
    HOME / "Library/Application Support/com.tencent.xinWeChat",
    HOME / "Library/Containers/com.tencent.xinWeChat",
]

# WeChat 4.x and group-container variants are discovered dynamically so we do
# not hard-code fragile paths. We only glob names that clearly belong to
# WeChat / Tencent, never the whole Group Containers folder.
GROUP_CONTAINER_ROOT = HOME / "Library/Group Containers"
DYNAMIC_GLOBS = [
    (GROUP_CONTAINER_ROOT, "*xinWeChat*"),
    (GROUP_CONTAINER_ROOT, "*Tencent*WeChat*"),
    (HOME / "Library/Containers", "*xinWeChat*"),
]

# Folder/file name fragments that suggest sticker / emotion / favourite data.
STICKER_KEYWORDS = [
    "sticker",
    "emoticon",
    "customemotion",
    "emotion",
    "emoji",
    "fav.archive",
    "favitem",
    "favorite",
    "favourite",
    "filestorage",  # often holds emotion subfolders; flagged as may-contain-media
]

# Names/extensions that indicate a chat/message/contact database. These are
# never opened for byte sampling; we only note that they exist.
DB_DENYLIST = [
    "msg",
    "message",
    "contact",
    "session",
    "chat",
    "wccontact",
    "fts",
    "group",
]
DB_EXTENSIONS = {".db", ".sqlite", ".sqlite3", ".db-wal", ".db-shm"}

# Candidate dirs that frequently mix in private chat media -> warn the user.
SENSITIVE_HINTS = ["filestorage"]

# Magic-byte signatures (checked against the first 16 bytes of a file).
SIMPLE_SIGNATURES = [
    (b"\x89PNG\r\n\x1a\n", "PNG image"),
    (b"\xff\xd8\xff", "JPEG image"),
    (b"GIF87a", "GIF image"),
    (b"GIF89a", "GIF image"),
    (b"SQLite format 3\x00", "SQLite database"),
    (b"bplist", "binary plist / NSKeyedArchiver"),
    (b"<?xml", "XML / text plist"),
    (b"PK\x03\x04", "ZIP archive"),
    (b"BM", "BMP image"),
    (b"II*\x00", "TIFF image"),
    (b"MM\x00*", "TIFF image"),
]

# Bounds so the diagnostic stays fast even on huge libraries.
MAX_FILES_PER_BASE = 300_000
SAMPLE_PER_CANDIDATE = 6
MAGIC_READ_BYTES = 16

# --------------------------------------------------------------------------- #
# Anonymisation
# --------------------------------------------------------------------------- #

_ACCOUNT_PATTERNS = [
    re.compile(r"^wxid_[A-Za-z0-9]+$"),
    re.compile(r"^[0-9a-fA-F]{16,}$"),                 # md5-like account hashes
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


def anon_path(path: Path | str, base: Path | None = None) -> str:
    """Return a privacy-safe display string for a path.

    - Strips the real home directory (-> '~').
    - Replaces wxid_*/account-hash/uuid components with stable user_N labels.
    """
    p = Path(path)
    try:
        rel = p.relative_to(base) if base is not None else None
    except (ValueError, TypeError):
        rel = None

    if rel is not None:
        prefix = "<base>"
        parts = rel.parts
    else:
        try:
            rel_home = p.relative_to(HOME)
            prefix = "~"
            parts = rel_home.parts
        except ValueError:
            prefix = ""
            parts = p.parts

    safe_parts = [
        _anon_component(part) if _looks_like_account(part) else part
        for part in parts
    ]
    joined = "/".join(safe_parts)
    if prefix and joined:
        return f"{prefix}/{joined}"
    return prefix or joined or "."


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


def is_database_like(name: str) -> bool:
    lower = name.lower()
    ext = os.path.splitext(lower)[1]
    if ext in DB_EXTENSIONS:
        return True
    return any(token in lower for token in DB_DENYLIST)


def name_matches_keyword(name: str) -> bool:
    lower = name.lower()
    return any(kw in lower for kw in STICKER_KEYWORDS)


def detect_magic(first_bytes: bytes) -> str:
    if not first_bytes:
        return "empty"
    if first_bytes[0:4] == b"RIFF" and first_bytes[8:12] == b"WEBP":
        return "WEBP image"
    for sig, label in SIMPLE_SIGNATURES:
        if first_bytes.startswith(sig):
            return label
    return "unknown"


def safe_stat_size(path: str) -> int:
    try:
        return os.stat(path, follow_symlinks=False).st_size
    except OSError:
        return 0


def sample_magic(path: str, name: str) -> str:
    """Read at most MAGIC_READ_BYTES bytes to classify a file.

    Database-like files are NEVER opened; we just report that they were skipped.
    """
    if is_database_like(name):
        return "skipped (database — not opened)"
    try:
        with open(path, "rb") as fh:
            head = fh.read(MAGIC_READ_BYTES)
        return detect_magic(head)
    except OSError as exc:
        return f"unreadable ({exc.errno})"


# --------------------------------------------------------------------------- #
# Walking
# --------------------------------------------------------------------------- #

class BaseResult:
    def __init__(self, base: Path):
        self.base = base
        self.exists = False
        self.total_files = 0
        self.total_size = 0
        self.capped = False
        self.candidate_dirs: list[str] = []   # absolute paths
        self.candidate_files: list[str] = []  # absolute paths (e.g. fav.archive)
        self.error: str | None = None


def scan_base(base: Path) -> BaseResult:
    result = BaseResult(base)
    if not base.exists():
        return result
    result.exists = True

    try:
        for dirpath, dirnames, filenames in os.walk(base, followlinks=False):
            # Identify candidate directories by their own name.
            for d in dirnames:
                if name_matches_keyword(d):
                    result.candidate_dirs.append(os.path.join(dirpath, d))

            for f in filenames:
                full = os.path.join(dirpath, f)
                result.total_files += 1
                result.total_size += safe_stat_size(full)
                if name_matches_keyword(f):
                    result.candidate_files.append(full)
                if result.total_files >= MAX_FILES_PER_BASE:
                    result.capped = True
                    break
            if result.capped:
                break
    except OSError as exc:
        result.error = str(exc)

    return result


def summarize_candidate_dir(cand: str) -> dict:
    """Bounded subtree accounting + magic-byte sampling for one candidate dir."""
    file_count = 0
    total_size = 0
    samples: list[tuple[str, str]] = []  # (anon relative name, detected type)
    capped = False

    try:
        for dirpath, _dirnames, filenames in os.walk(cand, followlinks=False):
            for f in filenames:
                full = os.path.join(dirpath, f)
                file_count += 1
                total_size += safe_stat_size(full)
                if len(samples) < SAMPLE_PER_CANDIDATE:
                    detected = sample_magic(full, f)
                    rel = os.path.relpath(full, cand)
                    # rel is below the candidate dir; anonymise just in case.
                    rel_safe = "/".join(
                        _anon_component(part) if _looks_like_account(part) else part
                        for part in Path(rel).parts
                    )
                    samples.append((rel_safe, detected))
                if file_count >= MAX_FILES_PER_BASE:
                    capped = True
                    break
            if capped:
                break
    except OSError:
        pass

    return {
        "file_count": file_count,
        "total_size": total_size,
        "samples": samples,
        "capped": capped,
        "sensitive": any(h in cand.lower() for h in SENSITIVE_HINTS),
    }


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def build_base_locations() -> list[Path]:
    locations: list[Path] = list(BASE_LOCATIONS)
    seen = {str(p) for p in locations}
    for root, pattern in DYNAMIC_GLOBS:
        try:
            if not root.exists():
                continue
            for match in sorted(root.glob(pattern)):
                if str(match) not in seen and match.is_dir():
                    locations.append(match)
                    seen.add(str(match))
        except OSError:
            continue
    return locations


def generate_report(results: list[BaseResult]) -> str:
    lines: list[str] = []
    add = lines.append

    add("# WeChat Sticker Storage — Discovery Report")
    add("")
    add(f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"- Platform: {sys.platform}")
    add("- Mode: **read-only** (no WeChat file was modified; databases were not opened)")
    add("- Paths are anonymised (`~`, `<base>`, `user_N`).")
    add("")

    found_any = any(r.exists for r in results)
    if not found_any:
        add("> **No WeChat base directories were found on this machine.**")
        add("> Either WeChat is not installed, has never been logged in, or uses")
        add("> a path not covered here. See the troubleshooting notes at the end.")
        add("")

    add("## Base locations probed")
    add("")
    add("| # | Location | Exists | Files | Approx. size |")
    add("| - | -------- | ------ | ----- | ------------ |")
    for i, r in enumerate(results, 1):
        loc = anon_path(r.base)
        if r.exists:
            cap = "+" if r.capped else ""
            add(f"| {i} | `{loc}` | yes | {r.total_files}{cap} | {human_size(r.total_size)} |")
        else:
            add(f"| {i} | `{loc}` | no | – | – |")
    add("")
    if any(r.capped for r in results):
        add(f"> `+` means the file count hit the safety cap ({MAX_FILES_PER_BASE}). "
            "Totals are lower bounds.")
        add("")

    add("## Sticker / emotion / favourite candidates")
    add("")

    any_candidates = False
    for r in results:
        if not r.exists:
            continue
        if r.error:
            add(f"### `{anon_path(r.base)}`")
            add("")
            add(f"> Could not be fully scanned: `{r.error}`")
            add("")
            continue

        cand_dirs = sorted(set(r.candidate_dirs))
        cand_files = sorted(set(r.candidate_files))
        if not cand_dirs and not cand_files:
            continue

        any_candidates = True
        add(f"### Base: `{anon_path(r.base)}`")
        add("")

        for cand in cand_dirs:
            info = summarize_candidate_dir(cand)
            add(f"#### Directory: `{anon_path(cand, base=r.base)}`")
            cap = "+" if info["capped"] else ""
            add(f"- Files: **{info['file_count']}{cap}**")
            add(f"- Approx. size: **{human_size(info['total_size'])}**")
            if info["sensitive"]:
                add("- ⚠️ May also contain **private chat media** — review before exporting.")
            if info["samples"]:
                add("- Sample file signatures:")
                add("")
                add("  | Sample file | Detected type |")
                add("  | ----------- | ------------- |")
                for rel_safe, detected in info["samples"]:
                    add(f"  | `{rel_safe}` | {detected} |")
            else:
                add("- (no files sampled)")
            add("")

        if cand_files:
            add("#### Matching files (e.g. favourites archives)")
            add("")
            add("| File | Size | Detected type |")
            add("| ---- | ---- | ------------- |")
            for f in cand_files[:50]:
                size = human_size(safe_stat_size(f))
                detected = sample_magic(f, os.path.basename(f))
                add(f"| `{anon_path(f, base=r.base)}` | {size} | {detected} |")
            add("")

    if not any_candidates and found_any:
        add("> WeChat directories exist, but no folder/file name matched the")
        add("> sticker/emotion keywords. The data may use other names — paste the")
        add("> base-location table above so we can refine the keyword list.")
        add("")

    add("## How the magic-byte sampling stayed safe")
    add("")
    add(f"- At most **{MAGIC_READ_BYTES} bytes** were read from any sampled file "
        "(just enough for a format signature).")
    add("- Files that look like chat/message/contact databases were **never opened**.")
    add(f"- At most **{SAMPLE_PER_CANDIDATE} files** were sampled per candidate directory.")
    add("")

    add("## What to do with this report")
    add("")
    add("1. Skim the candidate directories above and note which ones contain")
    add("   image signatures (PNG / GIF / WEBP / JPEG).")
    add("2. The directory with the most image files and **no** `skipped (database)`")
    add("   rows is the most likely sticker store.")
    add("3. Paste this whole report back so the next step (a read-only *copy*-based")
    add("   exporter) can target the confirmed location.")
    add("")

    add("## Troubleshooting / coverage notes")
    add("")
    add("- WeChat 4.x may use a different container; dynamic globs for")
    add("  `Group Containers` and `Containers` were included automatically.")
    add("- If nothing was found, confirm WeChat is installed and has been opened")
    add("  at least once while logged in, then re-run.")
    add("- macOS may prompt for permission to read `~/Library`; allow it for the")
    add("  terminal/Python if asked.")
    add("")

    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only WeChat sticker storage discovery (macOS).",
    )
    parser.add_argument(
        "--out",
        default="wechat_structure_report.md",
        help="Markdown report path (default: wechat_structure_report.md)",
    )
    args = parser.parse_args()

    if sys.platform != "darwin":
        print("[note] This tool targets macOS; paths probed assume macOS WeChat.",
              file=sys.stderr)

    locations = build_base_locations()
    results = [scan_base(loc) for loc in locations]

    report = generate_report(results)

    out_path = Path(args.out).expanduser()
    out_path.write_text(report, encoding="utf-8")

    # Short, anonymised console summary.
    print(f"Report written to: {out_path}")
    print("-" * 56)
    for i, r in enumerate(results, 1):
        status = "found" if r.exists else "absent"
        if r.exists:
            n_cand = len(set(r.candidate_dirs)) + len(set(r.candidate_files))
            print(f"  [{i}] {status:6}  {r.total_files:>7} files  "
                  f"{human_size(r.total_size):>10}  "
                  f"{n_cand} candidate(s)  {anon_path(r.base)}")
        else:
            print(f"  [{i}] {status:6}  {'-':>7}        "
                  f"{'-':>10}  -            {anon_path(r.base)}")
    print("-" * 56)
    print("Open the Markdown report and paste it back to continue.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
