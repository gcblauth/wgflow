"""Auto-detect format dispatcher.

Sniffs the upload bytes and routes to the appropriate parser. The order
of checks matters because some formats are subsets of others (a tar
archive could in principle contain a single .conf file and we want to
treat it as PiVPN, not bare-WG).

Detection order
---------------
  1. SQLite header bytes ('SQLite format 3\\x00')         → wg-easy v15
  2. Tar header (probed via tarfile.open)                → PiVPN tar
  3. Zip header bytes ('PK\\x03\\x04')                     → PiVPN zip
  4. JSON-shape with 'server' & 'clients' keys           → wg-easy v14
  5. Plain text with [Interface] section                 → bare WireGuard
  6. Anything else                                       → ValueError

Each branch raises with a specific message so the operator gets useful
feedback when an upload fails to detect.
"""
from __future__ import annotations

import io
import json
import tarfile

from . import bare_wg, parsed as P, pivpn, wg_easy


def detect_and_parse(content: bytes) -> P.ParsedImport:
    """Detect the format of `content` and dispatch to the right parser.

    Raises ValueError with a specific message if the format isn't
    recognised. Caller (the API endpoint) maps that to a 422.
    """
    if not content:
        raise ValueError("uploaded file is empty")

    # 1. SQLite v3 magic — exactly 16 bytes at start of file.
    if content.startswith(b"SQLite format 3\x00"):
        return wg_easy.parse_v15_sqlite(content)

    # 2. Tar archive — tarfile.open will succeed on tar/tar.gz/tar.bz2.
    # We have to actually try opening because tar has no fixed magic at
    # offset 0 (gzipped tars start with 0x1f 0x8b, raw tars start with
    # the file's name). tarfile is the most reliable detector.
    try:
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:*") as tar:
            # Side-effect of "is this really a tar": peek at the first
            # member. tarfile's lazy detection means errors surface here.
            first = next(iter(tar), None)
            if first is None:
                # Empty tar — very weird but technically valid. Treat
                # as PiVPN with no contents; parser will surface the
                # "no client confs found" warning.
                pass
        return pivpn.parse(content)
    except (tarfile.ReadError, tarfile.TarError):
        pass

    # 3. Zip archive — 'PK' magic + 0x03 0x04 (local file header).
    if content[:4] == b"PK\x03\x04":
        return pivpn.parse(content)

    # 4. JSON. Try parsing only if the first non-whitespace byte is '{'.
    head = content.lstrip()[:1]
    if head == b"{":
        try:
            data = json.loads(content)
            if isinstance(data, dict) and "clients" in data:
                return wg_easy.parse_v14_json(content)
            raise ValueError(
                "JSON file does not look like a wg-easy wg0.json "
                "(missing top-level 'clients' object)"
            )
        except json.JSONDecodeError as e:
            raise ValueError(f"file looks like JSON but failed to parse: {e}")

    # 5. Bare wg-quick conf — must contain [Interface] somewhere.
    try:
        text_head = content[:4096].decode("utf-8")
    except UnicodeDecodeError:
        raise ValueError(
            "file is not text and not a recognised binary format "
            "(SQLite, tar, zip)"
        )
    if "[Interface]" in text_head:
        return bare_wg.parse(content)

    raise ValueError(
        "couldn't detect file format. Expected one of: "
        "wg-easy wg0.json (v1-v14), wg-easy wg-easy.db (v15+), "
        "PiVPN tar/zip archive, or a wg-quick wg0.conf file."
    )
