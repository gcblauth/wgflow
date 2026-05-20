"""Importers for migrating from wg-easy / PiVPN / bare WireGuard.

All parsers converge on the universal IR defined in `parsed.py`. The flow:

    upload -> detector.detect_and_parse(bytes) -> ParsedImport
              (dispatches by file magic to wg_easy / pivpn / bare_wg)

Then `commit.apply(parsed, accepted_indices, adopt_server_keypair)` writes
the selected peers to the wgflow DB inside one transaction, and replays
state to the kernel.

Parsed previews live in `preview_store` (in-memory dict + 10 min TTL) so
the upload payload doesn't have to be re-sent on commit.
"""
