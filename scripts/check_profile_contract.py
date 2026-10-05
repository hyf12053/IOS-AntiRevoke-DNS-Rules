"""Verify published profiles satisfy their contracts.

Run from the repository root after the pipeline has generated ``output/``:

    python scripts/check_profile_contract.py

The normal profile must keep the install-verification path reachable, the
enhanced profile may block PPQ/VPP but never the appattest family, and the
enhanced profile must remain a superset of the normal one. Exits non-zero with a
list of violations.
"""

from __future__ import annotations

import plistlib
import subprocess
import sys
import tempfile
from pathlib import Path

# Unsafe in ANY published profile.
ALWAYS_BANNED = {
    "appattest.apple.com",  # suffix-matches the serving register./data. hosts
    "mesu.apple.com",
    "gdmf.apple.com",
    "guzzoni-apple-com.v.aaplimg.com",
    "axm-app.apple.com",
    "comm-main.ess.apple.com",
    "comm-cohort.ess.apple.com",
}

# Unsafe only while installing an app; allowed in the enhanced profile.
INSTALL_TIME_BANNED = {
    "ppq.apple.com",
    "ppq-ext.v.aaplimg.com",
    "ppq-st-ext.itunes.apple.com",
    "use1-ppq-ext-prod.apple.com",
    "usw2-ppq-ext-prod.apple.com",
    "vpp.itunes.apple.com",
}

NORMAL_PROFILE = "output/RevokeGuard_Auto-Sync.mobileconfig"
ENHANCED_PROFILE = "output/enhanced/RevokeGuard_Enhanced.mobileconfig"


def domains_of(path: str) -> list:
    """Return the SupplementalMatchDomains of a profile, signed or unsigned."""
    raw = Path(path).read_bytes()
    if raw.lstrip()[:5] != b"<?xml":
        # CMS-signed: decode to plain plist first.
        out = Path(tempfile.mkdtemp()) / "decoded.plist"
        subprocess.run(
            ["openssl", "smime", "-verify", "-inform", "DER", "-in", path,
             "-noverify", "-out", str(out)],
            check=True, capture_output=True,
        )
        raw = out.read_bytes()

    found = []
    for payload in plistlib.loads(raw).get("PayloadContent", []):
        settings = payload.get("DNSSettings") or {}
        found.extend(settings.get("SupplementalMatchDomains", []))
    return [d.strip().lower() for d in found]


def main() -> int:
    problems = []
    published = {}

    for path, banned in (
        (NORMAL_PROFILE, ALWAYS_BANNED | INSTALL_TIME_BANNED),
        (ENHANCED_PROFILE, ALWAYS_BANNED),
    ):
        current = set(domains_of(path))
        published[path] = current
        for domain in sorted(current & banned):
            problems.append(f"{path}: must not block {domain}")

    # The enhanced profile replaces the normal one on the device, so switching
    # profiles must not silently drop protection.
    missing = published[NORMAL_PROFILE] - published[ENHANCED_PROFILE]
    if missing:
        problems.append(
            "enhanced profile is missing domains the normal profile blocks: "
            f"{sorted(missing)}"
        )

    if problems:
        print("Profile contract violated:", file=sys.stderr)
        for item in problems:
            print("  " + item, file=sys.stderr)
        return 1

    print("OK: profile contracts satisfied")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
