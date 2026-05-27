#!/usr/bin/env python3
"""
wechat_emoticon_db_inspect.py

READ-ONLY schema inspection for WeChat's emoticon metadata database on macOS.

Background
----------
Step 1 located the sticker directories. Step 2 showed that every file under
`business/emoticon` and `cache/*/Emoticon` is opaque (no PNG/GIF/WEBP/JPEG
signature at offset 0 or within 512 bytes) — i.e. the on-disk files are
encrypted / obfuscated / wrapped. The decryption hints (or CDN URLs, or a
name->file mapping) almost certainly live in the metadata database:

    <account>/db_storage/emoticon/emoticon.db

This script inspects ONLY that one database, read-only, to learn its schema so
we can later design a safe exporter.

Scope (the ONLY thing this script opens)
----------------------------------------
    ~/Library/Containers/com.tencent.xinWeChat/Data/Documents/
        xwechat_files/<account>/db_storage/emoticon/emoticon.db

Safety guarantees (by construction)
-----------------------------------
  * Opens ONLY `emoticon.db`. No message/contact/favourite/session database is
    ever opened. No other file is read (apart from listing filenames in
    business/emoticon for a count-only correlation, and a 16-byte magic check).
  * Opens SQLite in READ-ONLY, IMMUTABLE mode (URI `mode=ro&immutable=1`), so
    it cannot write, lock, or create -wal/-shm/-journal side files. It never
    falls back to a writable connection.
  * NEVER modifies, moves, renames, deletes, decrypts, or exports anything.
  * Does NOT dump tables. At most 3 sample rows are read from *promising*
    tables, and every value is REDACTED before printing:
        - URLs        -> scheme://host + path shape only (no query/params)
        - hashes      -> first 6 + last 4 chars only
        - account IDs -> <account> / <id>
        - key/secret  -> hidden entirely (never printed, not even partially)
        - free text / CJK / anything with spaces -> <text len=N>
        - BLOBs       -> length + first 8 bytes hex (key-like columns hidden)
  * Never inspects FileStorage.

Usage
-----
    python3 wechat_emoticon_db_inspect.py
    python3 wechat_emoticon_db_inspect.py --out emoticon_db_schema_report.md

Tip: quit WeChat before running so the database is fully checkpointed.
"""

from __future__ import annotations

import argparse
import os
import re
import sqlite3
import sys
import urllib.parse
import urllib.request
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

DB_REL = ("db_storage", "emoticon", "emoticon.db")
BUSINESS_EMOTICON_REL = ("business", "emoticon")

# Column-name fragments that suggest useful sticker metadata.
METADATA_KEYWORDS = [
    "md5", "hash", "cdn", "url", "encrypt", "aes", "key", "type", "format",
    "size", "width", "height", "thumb", "path", "file", "product", "pack",
    "group", "desc",
]

# Column-name fragments whose VALUES must never be printed (possible secrets).
KEY_COLUMN_TOKENS = [
    "aeskey", "aes", "encryptkey", "enckey", "secret", "password", "passwd",
    "token", "_iv", "salt", "privkey", "private_key",
]
# A bare "key" column is treated as key-like too (over-redaction is safe).
KEY_BARE = re.compile(r"(^|_)key($|_)", re.IGNORECASE)

# Column-name fragments that identify a person/account -> redact values.
ID_COLUMN_TOKENS = [
    "wxid", "talker", "sender", "owner", "user", "uin", "uid", "contact",
    "openid", "alias", "nickname",
]

# Table-name fragments we refuse to sample rows from (defensive — should not
# appear in emoticon.db, but we never want to print chat-like content).
TABLE_DENY_TOKENS = [
    "msg", "message", "chat", "contact", "talker", "conversation", "session",
    "favorite", "favourite",
]

URL_COLUMN_TOKENS = ["url", "cdn"]
HASH_COLUMN_TOKENS = ["md5", "hash"]

SAMPLE_ROWS = 3
HASH_HEAD, HASH_TAIL = 6, 4
BLOB_HEAD_BYTES = 8
MAX_DISTINCT_HOSTS = 20

HEX_HASH_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
ACCOUNT_RE = [
    re.compile(r"^wxid_[A-Za-z0-9]+$"),
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}$"),  # uuid-like
]
ASCII_TOKEN_RE = re.compile(r"^[A-Za-z0-9_.\-:/]+$")  # safe-to-show short tokens

# --------------------------------------------------------------------------- #
# Account anonymisation (for any account-like component in displayed paths)
# --------------------------------------------------------------------------- #

_anon_map: dict[str, str] = {}
_anon_counter = [0]
_ACCOUNT_PATH_RE = [
    re.compile(r"^wxid_[A-Za-z0-9]+$"),
    re.compile(r"^[0-9a-fA-F]{16,}$"),
    re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F-]{20,}$"),
]


def _looks_like_account_component(part: str) -> bool:
    return any(p.match(part) for p in _ACCOUNT_PATH_RE)


def _anon_component(part: str) -> str:
    if part not in _anon_map:
        _anon_counter[0] += 1
        _anon_map[part] = f"user_{_anon_counter[0]}"
    return _anon_map[part]


def anon_account_path(path: Path) -> str:
    """Show a path relative to the xwechat_files root, account-anonymised."""
    try:
        rel = path.relative_to(XWECHAT_ROOT)
        parts = ("<xwechat_files>",) + rel.parts
    except ValueError:
        try:
            parts = ("~",) + path.relative_to(HOME).parts
        except ValueError:
            parts = path.parts
    safe = [
        _anon_component(p) if _looks_like_account_component(p) else p
        for p in parts
    ]
    return "/".join(safe)


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


def col_matches(name: str, tokens: list[str]) -> bool:
    low = name.lower()
    return any(t in low for t in tokens)


def is_key_column(name: str) -> bool:
    return col_matches(name, KEY_COLUMN_TOKENS) or bool(KEY_BARE.search(name))


def is_id_column(name: str) -> bool:
    return col_matches(name, ID_COLUMN_TOKENS)


def matched_metadata_keywords(name: str) -> list[str]:
    low = name.lower()
    return [k for k in METADATA_KEYWORDS if k in low]


def quote_ident(ident: str) -> str:
    return '"' + ident.replace('"', '""') + '"'


# --------------------------------------------------------------------------- #
# Findings accumulator (drives the recommendation)
# --------------------------------------------------------------------------- #

class Findings:
    def __init__(self) -> None:
        self.url_hosts: set[str] = set()
        self.url_value_count = 0
        self.saw_key_column = False
        self.saw_url_column = False
        self.saw_hash_column = False
        self.saw_thumb_column = False
        self.saw_encrypt_column = False


# --------------------------------------------------------------------------- #
# Redaction
# --------------------------------------------------------------------------- #

def redact_url(value: str, findings: Findings) -> str:
    try:
        parsed = urllib.parse.urlparse(value)
    except ValueError:
        return "<url (unparseable)>"
    host = parsed.netloc
    if host:
        findings.url_hosts.add(host)
        findings.url_value_count += 1
    segs = [s for s in parsed.path.split("/") if s]
    shape = f"/<{len(segs)} path seg(s)>" if segs else "/"
    q = " ?<query redacted>" if parsed.query else ""
    scheme = parsed.scheme or "url"
    return f"{scheme}://{host}{shape}{q}"


def redact_hash(value: str) -> str:
    if len(value) <= HASH_HEAD + HASH_TAIL:
        return value  # too short to be sensitive; show as-is
    return f"{value[:HASH_HEAD]}…{value[-HASH_TAIL:]} (len {len(value)})"


def redact_value(col_name: str, value, findings: Findings) -> str:
    # Key-like columns: never reveal the value, even partially.
    if is_key_column(col_name):
        if isinstance(value, (bytes, bytearray)):
            return f"<hidden: key-like column, BLOB len {len(value)}>"
        if value is None:
            return "NULL"
        slen = len(str(value))
        return f"<hidden: key-like column, len {slen}>"

    if value is None:
        return "NULL"

    if isinstance(value, (bytes, bytearray)):
        head = bytes(value[:BLOB_HEAD_BYTES]).hex(" ")
        return f"<BLOB len {len(value)}, head={head}>"

    if isinstance(value, bool):
        return str(value)

    if isinstance(value, int):
        if is_id_column(col_name):
            return "<id>"
        return str(value)

    if isinstance(value, float):
        return repr(value)

    # From here, value is a string.
    s = str(value)

    if is_id_column(col_name):
        return "<id>"

    # URL?
    if "://" in s and s[:8].lower().startswith(("http", "ftp", "ws")):
        return redact_url(s, findings)

    # Account / uuid identifier?
    if any(p.match(s) for p in ACCOUNT_RE):
        return "<account>"

    # Hex hash?
    if HEX_HASH_RE.match(s):
        return redact_hash(s)

    # Filesystem-ish path?
    if "/" in s and len(s) > 3:
        ext = os.path.splitext(s)[1].lower()
        depth = len([p for p in s.split("/") if p])
        ext_part = f" ext {ext}" if ext else ""
        return f"<path depth {depth}{ext_part}>"

    # Non-ASCII (e.g. CJK names/descriptions) or contains whitespace -> redact.
    if any(ord(ch) > 126 for ch in s) or any(ch.isspace() for ch in s):
        return f"<text len {len(s)}>"

    # Short, safe-looking ASCII token (format ids, mime types, enums, ext).
    if len(s) <= 40 and ASCII_TOKEN_RE.match(s):
        return s

    return f"<text len {len(s)}>"


# --------------------------------------------------------------------------- #
# Discovery
# --------------------------------------------------------------------------- #

def find_accounts_with_db(root: Path) -> list[Path]:
    accounts: list[Path] = []
    if not root.exists():
        return accounts
    try:
        children = sorted(p for p in root.iterdir() if p.is_dir())
    except OSError:
        return accounts
    for child in children:
        if child.joinpath(*DB_REL).is_file():
            accounts.append(child)
    return accounts


def sqlite_magic_ok(db_path: Path) -> bool:
    """Read only the first 16 bytes to confirm a SQLite header."""
    try:
        with open(db_path, "rb") as fh:
            return fh.read(16) == b"SQLite format 3\x00"
    except OSError:
        return False


def open_readonly(db_path: Path):
    """Open strictly read-only/immutable. Never falls back to writable."""
    uri_path = urllib.request.pathname2url(str(db_path))
    attempts = [
        (f"file:{uri_path}?mode=ro&immutable=1", "mode=ro&immutable=1"),
        (f"file:{uri_path}?mode=ro", "mode=ro"),
    ]
    last_err: Exception | None = None
    for uri, label in attempts:
        try:
            con = sqlite3.connect(uri, uri=True, timeout=2.0)
            con.execute("SELECT 1")
            return con, label
        except sqlite3.Error as exc:
            last_err = exc
    raise last_err if last_err else sqlite3.Error("could not open read-only")


# --------------------------------------------------------------------------- #
# Schema reading
# --------------------------------------------------------------------------- #

def list_tables(con) -> list[str]:
    cur = con.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name"
    )
    return [r[0] for r in cur.fetchall()]


def table_columns(con, table: str) -> list[tuple[str, str]]:
    cur = con.execute(f"PRAGMA table_info({quote_ident(table)})")
    return [(r[1], r[2] or "") for r in cur.fetchall()]


def row_count(con, table: str):
    try:
        return con.execute(
            f"SELECT COUNT(*) FROM {quote_ident(table)}"
        ).fetchone()[0]
    except sqlite3.Error:
        return None


def sample_rows(con, table: str):
    cur = con.execute(f"SELECT * FROM {quote_ident(table)} LIMIT {SAMPLE_ROWS}")
    cols = [d[0] for d in cur.description] if cur.description else []
    return cols, cur.fetchall()


def collect_url_hosts(con, url_columns: list[tuple[str, str]], findings: Findings):
    """Read url columns to extract distinct hosts + non-null count (counts only)."""
    for table, col in url_columns:
        try:
            cur = con.execute(
                f"SELECT {quote_ident(col)} FROM {quote_ident(table)}"
            )
        except sqlite3.Error:
            continue
        for (v,) in cur:
            if isinstance(v, str) and "://" in v:
                redact_url(v, findings)  # records host + count as a side effect


def collect_hash_values(con, hash_columns: list[tuple[str, str]]):
    """Return (set_of_values_lower, per_column_distinct_counts)."""
    all_vals: set[str] = set()
    per_col: list[tuple[str, str, int | None]] = []
    for table, col in hash_columns:
        try:
            cur = con.execute(
                f"SELECT {quote_ident(col)} FROM {quote_ident(table)}"
            )
        except sqlite3.Error:
            per_col.append((table, col, None))
            continue
        distinct: set[str] = set()
        for (v,) in cur:
            if isinstance(v, str) and v:
                distinct.add(v.strip().lower())
        per_col.append((table, col, len(distinct)))
        all_vals |= distinct
    return all_vals, per_col


def correlate_filenames(business_emoticon: Path, hash_values: set[str]):
    """Count how many files under business/emoticon match a hash value.

    Reads directory entries only (no file content). Reports counts only.
    """
    total = 0
    matched = 0
    if not business_emoticon.is_dir():
        return total, matched, False
    try:
        for dirpath, _dirs, files in os.walk(business_emoticon, followlinks=False):
            for f in files:
                total += 1
                low = f.lower()
                stem = os.path.splitext(low)[0]
                if low in hash_values or stem in hash_values:
                    matched += 1
    except OSError:
        return total, matched, True
    return total, matched, False


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #

def build_recommendation(findings: Findings, matched: int, total: int) -> list[str]:
    out: list[str] = []
    strong_match = total > 0 and matched >= max(1, int(0.5 * total))
    some_match = total > 0 and matched > 0

    out.append("Based on the schema (no decryption attempted), the exporter "
               "should most likely:")
    out.append("")

    # Re-download path.
    if findings.saw_url_column and findings.url_value_count > 0:
        hosts = ", ".join(sorted(findings.url_hosts)[:MAX_DISTINCT_HOSTS]) or "(none parsed)"
        out.append(f"- **Re-download originals from CDN URLs (safest).** A URL/CDN "
                   f"column is present with {findings.url_value_count} non-null "
                   f"value(s) across {len(findings.url_hosts)} distinct host(s): "
                   f"`{hosts}`. If these are public sticker CDNs, the exporter can "
                   "fetch clean PNG/GIF/WEBP originals without ever decrypting "
                   "local files.")
    elif findings.saw_url_column:
        out.append("- A URL/CDN column exists but held no usable values in what we "
                   "read — re-download may not be viable.")
    else:
        out.append("- **Re-download not available:** no URL/CDN column was found, "
                   "so originals cannot be fetched from a link.")

    # Decrypt path.
    if findings.saw_key_column or findings.saw_encrypt_column:
        out.append("- **Decryption may be required and a key/encrypt column is "
                   "present** (value hidden in this report). If we later confirm "
                   "the algorithm (commonly AES-CBC/ECB for WeChat caches), the "
                   "exporter could decrypt the opaque files using the per-file "
                   "key from this DB. This needs your explicit go-ahead.")
    else:
        out.append("- No explicit key/encrypt column was found in the schema, so "
                   "any obfuscation is likely a fixed scheme (e.g. XOR/format "
                   "wrapper) rather than per-file keyed encryption — to be "
                   "confirmed separately.")

    # Mapping / copy path.
    if findings.saw_hash_column and some_match:
        ratio = f"{matched}/{total}"
        qualifier = "most" if strong_match else "some"
        out.append(f"- **Use the DB as a name->sticker map.** {qualifier.title()} of "
                   f"the opaque files matched an md5/hash column ({ratio} files), "
                   "so the DB can supply real names, types, and grouping for each "
                   "encrypted file the exporter copies.")
    elif findings.saw_hash_column:
        out.append("- An md5/hash column exists but did **not** match the on-disk "
                   "filenames — the mapping between DB rows and cache files may use "
                   "a different key (worth investigating before exporting).")

    if findings.saw_thumb_column:
        out.append("- A thumbnail column/BLOB exists — thumbnails may be extractable "
                   "directly for previews even if full stickers are encrypted.")

    out.append("")
    out.append("**Recommended next step:** prefer the re-download path if safe CDN "
               "URLs exist; otherwise plan a copy-only export plus a separate, "
               "user-approved decryption step using the DB's key/metadata.")
    return out


def generate_report(root_exists, accounts, sections) -> str:
    lines: list[str] = []
    add = lines.append

    add("# WeChat Emoticon DB — Schema Inspection Report")
    add("")
    add(f"- Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    add(f"- Platform: {sys.platform}")
    add("- Mode: **read-only / immutable** — DB never written, locked, or copied.")
    add("- Only `emoticon.db` was opened. No other database was touched.")
    add("- Sample rows are limited to 3 per promising table and **redacted**.")
    add("- Paths/values anonymised; key-like columns are fully hidden.")
    add("")

    if not root_exists:
        add("> **xwechat_files root not found.** Expected at "
            "`~/Library/Containers/com.tencent.xinWeChat/Data/Documents/xwechat_files`.")
        add("> Confirm WeChat 4.x is installed and logged in, then re-run.")
        add("")
        return "\n".join(lines) + "\n"

    if not accounts:
        add("> No account folder containing "
            "`db_storage/emoticon/emoticon.db` was found.")
        add("")
        return "\n".join(lines) + "\n"

    for sec in sections:
        lines.extend(sec)

    add("## What to paste back")
    add("")
    add("1. The **Tables overview** table (names, row counts, promising flag).")
    add("2. The **per-table columns** lists — especially columns flagged with "
        "`md5/hash/url/cdn/key/aes/encrypt/type/thumb`.")
    add("3. The **redacted sample rows** for promising tables.")
    add("4. The **Filename ↔ hash correlation** counts.")
    add("5. The **Recommendation** section.")
    add("")
    add("With those, we can decide between a re-download exporter, a copy-only "
        "exporter, or a user-approved decryption step — and design it precisely.")
    add("")
    return "\n".join(lines) + "\n"


def inspect_one_account(con, db_label: str, db_size: int, magic_ok: bool,
                        open_mode: str, business_emoticon: Path) -> list[str]:
    add_lines: list[str] = []
    add = add_lines.append
    findings = Findings()

    add(f"## Database: `{db_label}`")
    add("")
    add(f"- Size: {human_size(db_size)}")
    add(f"- SQLite header verified: {'yes' if magic_ok else 'no'}")
    add(f"- Open mode: `{open_mode}`")
    add("")

    tables = list_tables(con)
    if not tables:
        add("> No user tables found in this database.")
        add("")
        return add_lines

    # Per-table schema gathering.
    table_meta = []  # (table, rowcount, columns, promising, denied)
    url_columns: list[tuple[str, str]] = []
    hash_columns: list[tuple[str, str]] = []
    for t in tables:
        cols = table_columns(con, t)
        rc = row_count(con, t)
        promising = any(matched_metadata_keywords(c) for c, _ in cols)
        denied = col_matches(t, TABLE_DENY_TOKENS)
        table_meta.append((t, rc, cols, promising, denied))
        for cname, _ctype in cols:
            if col_matches(cname, URL_COLUMN_TOKENS):
                url_columns.append((t, cname))
                findings.saw_url_column = True
            if col_matches(cname, HASH_COLUMN_TOKENS):
                hash_columns.append((t, cname))
                findings.saw_hash_column = True
            if is_key_column(cname):
                findings.saw_key_column = True
            if "encrypt" in cname.lower() or "aes" in cname.lower():
                findings.saw_encrypt_column = True
            if "thumb" in cname.lower():
                findings.saw_thumb_column = True

    # Tables overview.
    add("### Tables overview")
    add("")
    add("| Table | Rows | Columns | Promising | Sampled |")
    add("| ----- | ---- | ------- | --------- | ------- |")
    for t, rc, cols, promising, denied in table_meta:
        rc_s = str(rc) if rc is not None else "?"
        sampled = "no (denylisted)" if denied else ("yes" if promising else "no")
        add(f"| `{t}` | {rc_s} | {len(cols)} | "
            f"{'yes' if promising else 'no'} | {sampled} |")
    add("")

    # Per-table detail.
    add("### Columns by table")
    add("")
    for t, rc, cols, promising, denied in table_meta:
        add(f"#### `{t}`")
        add("")
        add("| Column | Type | Notes |")
        add("| ------ | ---- | ----- |")
        for cname, ctype in cols:
            notes = []
            kws = matched_metadata_keywords(cname)
            if kws:
                notes.append("metadata: " + ", ".join(kws))
            if is_key_column(cname):
                notes.append("key-like (value hidden)")
            if is_id_column(cname):
                notes.append("id-like (redacted)")
            add(f"| `{cname}` | {ctype or '—'} | {'; '.join(notes) or '—'} |")
        add("")

        # Redacted sample rows for promising, non-denied tables.
        if promising and not denied and rc:
            try:
                scols, rows = sample_rows(con, t)
            except sqlite3.Error as exc:
                add(f"> Could not sample rows: `{exc}`")
                add("")
                continue
            add(f"Sample rows (≤{SAMPLE_ROWS}, redacted):")
            add("")
            for i, row in enumerate(rows, 1):
                add(f"- **Row {i}**")
                for cname, val in zip(scols, row):
                    add(f"    - `{cname}`: {redact_value(cname, val, findings)}")
            add("")

    # URL host extraction (counts/domains only).
    if url_columns:
        collect_url_hosts(con, url_columns, findings)

    # Filename <-> hash correlation.
    add("### Filename ↔ hash correlation")
    add("")
    hash_values, per_col = collect_hash_values(con, hash_columns)
    if not hash_columns:
        add("> No md5/hash columns found, so no filename correlation was possible.")
        add("")
    else:
        add("Distinct values per md5/hash column (counts only):")
        add("")
        add("| Table.column | Distinct values |")
        add("| ------------ | --------------- |")
        for tbl, col, n in per_col:
            add(f"| `{tbl}.{col}` | {n if n is not None else '?'} |")
        add("")
        total, matched, err = correlate_filenames(business_emoticon, hash_values)
        if err and total == 0:
            add("> Could not list files under `business/emoticon` for correlation.")
        else:
            pct = (100.0 * matched / total) if total else 0.0
            add(f"- Files under `business/emoticon`: **{total}**")
            add(f"- Files whose name/stem matches a DB hash value: "
                f"**{matched}** ({pct:.1f}%)")
            add("- (Filenames themselves are not printed.)")
        add("")

    # Recommendation.
    add("### Recommendation")
    add("")
    total_for_rec, matched_for_rec, _ = correlate_filenames(
        business_emoticon, hash_values
    )
    add_lines.extend(
        build_recommendation(findings, matched_for_rec, total_for_rec)
    )
    add_lines.append("")
    return add_lines


# --------------------------------------------------------------------------- #
# Main
# --------------------------------------------------------------------------- #

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Read-only WeChat emoticon.db schema inspection (macOS).",
    )
    parser.add_argument(
        "--out",
        default="emoticon_db_schema_report.md",
        help="Markdown report path (default: emoticon_db_schema_report.md)",
    )
    args = parser.parse_args()

    if sys.platform != "darwin":
        print("[note] This tool targets macOS; paths assume macOS WeChat 4.x.",
              file=sys.stderr)

    root_exists = XWECHAT_ROOT.exists()
    accounts = find_accounts_with_db(XWECHAT_ROOT)

    sections: list[list[str]] = []
    for account in accounts:
        db_path = account.joinpath(*DB_REL)
        business_emoticon = account.joinpath(*BUSINESS_EMOTICON_REL)
        db_label = anon_account_path(db_path)
        db_size = db_path.stat().st_size if db_path.exists() else 0
        magic_ok = sqlite_magic_ok(db_path)

        if not magic_ok:
            sections.append([
                f"## Database: `{db_label}`", "",
                "> File does not have a SQLite header — skipped (not opened as DB).",
                "",
            ])
            continue

        try:
            con, open_mode = open_readonly(db_path)
        except sqlite3.Error as exc:
            sections.append([
                f"## Database: `{db_label}`", "",
                f"> Could not open read-only: `{exc}`",
                "> No writable fallback was attempted (by design).",
                "",
            ])
            continue

        try:
            sections.append(
                inspect_one_account(
                    con, db_label, db_size, magic_ok, open_mode, business_emoticon
                )
            )
        finally:
            con.close()

    report = generate_report(root_exists, accounts, sections)
    out_path = Path(args.out).expanduser()
    out_path.write_text(report, encoding="utf-8")

    # Console summary.
    print(f"Report written to: {out_path}")
    print("-" * 60)
    if not root_exists:
        print("  xwechat_files root not found — see report.")
    elif not accounts:
        print("  No emoticon.db found under any account.")
    else:
        for account in accounts:
            db_path = account.joinpath(*DB_REL)
            print(f"  emoticon.db: {anon_account_path(db_path)} "
                  f"({human_size(db_path.stat().st_size)})")
    print("-" * 60)
    print("Open emoticon_db_schema_report.md and paste back the sections it lists.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
