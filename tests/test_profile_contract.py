"""Tests for scripts/check_profile_contract.py.

The script is the CI backstop for the regression that broke app installation,
so it is worth testing in its own right: a guard that silently passes is worse
than no guard.
"""

import importlib.util
import plistlib
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "check_profile_contract.py"
NORMAL = Path("output/RevokeGuard_Auto-Sync.mobileconfig")
ENHANCED = Path("output/enhanced/RevokeGuard_Enhanced.mobileconfig")


def load_module():
    spec = importlib.util.spec_from_file_location("check_profile_contract", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write_profile(path: Path, domains):
    path.parent.mkdir(parents=True, exist_ok=True)
    profile = {
        "PayloadVersion": 1,
        "PayloadType": "Configuration",
        "PayloadIdentifier": "local.test",
        "PayloadUUID": "00000000-0000-0000-0000-000000000000",
        "PayloadDisplayName": "test",
        "PayloadContent": [{
            "PayloadVersion": 1,
            "PayloadType": "com.apple.dnsSettings.managed",
            "PayloadIdentifier": "local.test.dns",
            "PayloadUUID": "11111111-1111-1111-1111-111111111111",
            "DNSSettings": {
                "DNSProtocol": "HTTPS",
                "ServerURL": "https://backend.example/dns-query",
                "SupplementalMatchDomains": list(domains),
            },
        }],
    }
    with open(path, "wb") as handle:
        plistlib.dump(profile, handle)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    """Run the guard from a temporary repository root."""
    monkeypatch.chdir(tmp_path)
    (tmp_path / "output" / "enhanced").mkdir(parents=True)
    return tmp_path


def test_accepts_valid_pair(workspace):
    module = load_module()
    write_profile(NORMAL, ["ocsp.apple.com"])
    write_profile(ENHANCED, ["ocsp.apple.com", "ppq.apple.com"])
    assert module.main() == 0


def test_rejects_ppq_in_normal_profile(workspace):
    module = load_module()
    write_profile(NORMAL, ["ocsp.apple.com", "ppq.apple.com"])
    write_profile(ENHANCED, ["ocsp.apple.com", "ppq.apple.com"])
    assert module.main() == 1


def test_rejects_appattest_in_either_profile(workspace):
    module = load_module()
    write_profile(NORMAL, ["ocsp.apple.com", "appattest.apple.com"])
    write_profile(ENHANCED, ["ocsp.apple.com", "appattest.apple.com"])
    assert module.main() == 1


def test_rejects_enhanced_that_is_not_a_superset(workspace):
    module = load_module()
    write_profile(NORMAL, ["ocsp.apple.com", "crl.apple.com"])
    write_profile(ENHANCED, ["ocsp.apple.com"])
    assert module.main() == 1


def test_decodes_cms_signed_profiles(workspace):
    """A signed profile must be inspected, not skipped."""
    import shutil
    import subprocess

    if shutil.which("openssl") is None:
        pytest.skip("openssl not available")

    module = load_module()
    unsigned = workspace / "u.plist"
    write_profile(unsigned, ["ocsp.apple.com", "ppq.apple.com"])

    key = workspace / "k.pem"
    cert = workspace / "c.pem"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
         "-keyout", str(key), "-out", str(cert), "-days", "30",
         "-subj", "/CN=test.example"],
        check=True, capture_output=True,
    )
    # Sign the same payload into both published paths.
    write_profile(NORMAL, ["ocsp.apple.com", "ppq.apple.com"])
    for path in (NORMAL, ENHANCED):
        subprocess.run(
            ["openssl", "smime", "-sign", "-signer", str(cert), "-inkey", str(key),
             "-in", str(unsigned), "-out", str(path), "-outform", "DER", "-nodetach"],
            check=True, capture_output=True,
        )

    assert (NORMAL.read_bytes().lstrip()[:5]) != b"<?xml"
    assert module.main() == 1, "signed profile with PPQ in normal was not caught"
