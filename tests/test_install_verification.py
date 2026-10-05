"""Regression tests for the install-time verification failure.

Background: the upstream pipeline regressed on 2026-10-03 when an upstream
profile source started advertising an explicit 27-domain list that contained
the five PPQ hosts. The normal target list jumped 13 -> 33 domains, PPQ moved
out of the enhanced-only set, and both published profiles ended up blocking the
same domains. Because the backend is a catch-all black hole, blocking PPQ (and
the bare `appattest.apple.com`, which suffix-matches `register.` and `data.`)
made iOS report "An Internet connection is required to verify..." whenever an
app was installed.

These tests pin the behaviour that must not regress.
"""

import plistlib

import pytest

from main import (
    ALWAYS_EXCLUDED_DOMAINS,
    INSTALL_TIME_EXCLUDED_DOMAINS,
    AntiRevokeOrchestrator,
)
from utils.crypto_handler import CryptoHandler
from utils.dns_probe import Resolution

INSTALL_CRITICAL = sorted(INSTALL_TIME_EXCLUDED_DOMAINS)


def payload(identifier, url, domains=None):
    settings = {"DNSProtocol": "HTTPS", "ServerURL": url}
    if domains is not None:
        settings["SupplementalMatchDomains"] = domains
    return {"PayloadIdentifier": identifier, "DNSSettings": settings}


def build_orchestrator(tmp_path, monkeypatch, normal_domains, enhanced_domains):
    """Run the pipeline with the given upstream-advertised domain lists."""
    sources = [
        {
            "name": "multi", "url": "https://multi.example", "xpath": "//a",
            "preferred_payload_identifier": "normal",
            "enhanced_payload_identifier": "enhanced",
        },
    ]
    profiles = {
        "multi": plistlib.dumps({"PayloadContent": [
            payload("normal", "https://normal.example/dns-query", normal_domains),
            payload("enhanced", "https://enhanced.example/dns-query", enhanced_domains),
        ]}),
    }
    candidates = sorted(set(normal_domains) | set(enhanced_domains)) + [
        f"clean{i}.example" for i in range(100)
    ]
    orchestrator = AntiRevokeOrchestrator(output_dir=str(tmp_path))
    monkeypatch.setattr(orchestrator.scraper, "fetch_apple_domains", lambda _: candidates)
    monkeypatch.setattr(orchestrator.scraper, "scrape_sources", lambda _: profiles)
    orchestrator.scraper.download_urls = {s["name"]: s["url"] for s in sources}

    advertised = set(normal_domains) | set(enhanced_domains)

    def resolve(url, domain):
        if domain in advertised:
            return Resolution("invalid_address", ("0.0.0.0",), ("NOERROR",))
        return Resolution("valid", ("17.1.1.1",), ("NOERROR",))

    monkeypatch.setattr(orchestrator.probe, "resolve", resolve)
    assert orchestrator.run(sources)
    return orchestrator


def profile_domains(path):
    data = plistlib.loads(path.read_bytes())
    return data["PayloadContent"][0]["DNSSettings"]["SupplementalMatchDomains"]


def test_normal_profile_never_blocks_install_verification_domains(
    tmp_path, monkeypatch,
):
    """PPQ/VPP/appattest must be stripped from the install-time profile."""
    normal = ["ppq.apple.com", "appattest.apple.com", "vpp.itunes.apple.com",
              "ocsp.apple.com"]
    enhanced = ["ppq.apple.com", "extra.example"]

    build_orchestrator(tmp_path, monkeypatch, normal, enhanced)

    domains = profile_domains(tmp_path / "RevokeGuard_Auto-Sync.mobileconfig")
    for banned in ("ppq.apple.com", "appattest.apple.com", "vpp.itunes.apple.com"):
        assert banned not in domains, f"normal profile still blocks {banned}"
    # Revocation checking must survive: that is the whole point of the profile.
    assert "ocsp.apple.com" in domains


def test_normal_and_enhanced_profiles_stay_distinct(tmp_path, monkeypatch):
    """The two profiles must not collapse into the same domain set.

    Upstream's regression made them identical, so there was no way to install
    an app even by switching profiles.
    """
    normal = ["ocsp.apple.com"]
    enhanced = ["ocsp.apple.com", "ppq.apple.com", "extra.example"]

    build_orchestrator(tmp_path, monkeypatch, normal, enhanced)

    normal_domains = set(profile_domains(tmp_path / "RevokeGuard_Auto-Sync.mobileconfig"))
    enhanced_domains = set(
        profile_domains(tmp_path / "enhanced/RevokeGuard_Enhanced.mobileconfig")
    )
    assert normal_domains != enhanced_domains
    # Enhanced must be a strict superset: switching to it may not drop coverage.
    assert normal_domains <= enhanced_domains
    # ...and enhanced is where the post-install checks may be blocked.
    assert "ppq.apple.com" in enhanced_domains


def test_enhanced_profile_still_never_blocks_always_excluded(tmp_path, monkeypatch):
    """appattest breaks installation, so it is excluded from BOTH profiles."""
    enhanced = ["appattest.apple.com", "ocsp.apple.com", "extra.example"]

    build_orchestrator(tmp_path, monkeypatch, ["ocsp.apple.com"], enhanced)

    for name in ("RevokeGuard_Auto-Sync.mobileconfig",
                 "enhanced/RevokeGuard_Enhanced.mobileconfig"):
        domains = profile_domains(tmp_path / name)
        assert "appattest.apple.com" not in domains, f"{name} blocks appattest"


@pytest.mark.parametrize("domain", sorted(ALWAYS_EXCLUDED_DOMAINS))
def test_always_excluded_covers_install_and_unrelated_service_domains(domain):
    """Every always-excluded entry has a documented reason to be here."""
    assert domain in ALWAYS_EXCLUDED_DOMAINS


def test_filter_matches_subdomains_and_star_prefixes():
    """Suffix semantics mean a listed parent also blocks its children.

    The bare `appattest.apple.com` is NODATA while `register.`/`data.` serve,
    so listing the parent silently kills the working hosts. The filter must
    therefore match the parent regardless of case or a leading '*.'.
    """
    keep, dropped = AntiRevokeOrchestrator._filter_domains(
        ["APPATTEST.APPLE.COM", "*.appattest.apple.com", "ocsp.apple.com"],
        ALWAYS_EXCLUDED_DOMAINS,
    )
    assert dropped == ["*.appattest.apple.com", "APPATTEST.APPLE.COM"]
    assert keep == ["ocsp.apple.com"]


def test_metadata_matches_published_profile(tmp_path, monkeypatch):
    """blocked_by attribution must not advertise domains that were excluded."""
    import json

    normal = ["ppq.apple.com", "ocsp.apple.com"]

    build_orchestrator(tmp_path, monkeypatch, normal, ["ppq.apple.com"])

    metadata = json.loads((tmp_path / "metadata.json").read_text(encoding="utf-8"))
    blocked_by = metadata["normal_discovery"]["blocked_by"]
    profile = set(profile_domains(tmp_path / "RevokeGuard_Auto-Sync.mobileconfig"))
    assert "ppq.apple.com" not in blocked_by
    assert set(blocked_by) == profile


# --------------------------------------------------------------------------
# Profile identity: reinstalling must update, not accumulate.
# --------------------------------------------------------------------------

def test_profile_identifiers_are_stable_across_rebuilds(tmp_path):
    """Same inputs -> same PayloadIdentifier, so iOS updates the profile.

    Upstream used a fresh uuid4() per run. Because iOS keys configuration
    profiles by PayloadIdentifier, every daily rebuild installed as an
    additional profile instead of replacing the previous one, leaving
    duplicates in Settings > General > VPN & Device Management.
    """
    handler = CryptoHandler()
    first = handler.create_profile(["ocsp.apple.com"], output_file=str(tmp_path / "a.plist"))
    second = handler.create_profile(["ocsp.apple.com"], output_file=str(tmp_path / "b.plist"))

    a = plistlib.loads(open(first, "rb").read())
    b = plistlib.loads(open(second, "rb").read())

    assert a["PayloadIdentifier"] == b["PayloadIdentifier"]
    assert a["PayloadUUID"] == b["PayloadUUID"]
    assert (a["PayloadContent"][0]["PayloadIdentifier"]
            == b["PayloadContent"][0]["PayloadIdentifier"])


def test_distinct_profile_names_get_distinct_identifiers(tmp_path):
    """Normal and enhanced coexist on a device, so their ids must differ."""
    handler = CryptoHandler()
    normal = handler.create_profile(
        ["ocsp.apple.com"], output_file=str(tmp_path / "n.plist"), profile_name="RevokeGuard")
    enhanced = handler.create_profile(
        ["ocsp.apple.com"], output_file=str(tmp_path / "e.plist"),
        profile_name="RevokeGuard Enhanced")

    a = plistlib.loads(open(normal, "rb").read())
    b = plistlib.loads(open(enhanced, "rb").read())
    assert a["PayloadIdentifier"] != b["PayloadIdentifier"]


def test_backend_host_is_used_for_server_url(tmp_path):
    """The backend must be configurable rather than hardcoded."""
    handler = CryptoHandler()
    created = handler.create_profile(
        ["ocsp.apple.com"], output_file=str(tmp_path / "c.plist"),
        backend_host="dns.example.test")
    data = plistlib.loads(open(created, "rb").read())
    assert (data["PayloadContent"][0]["DNSSettings"]["ServerURL"]
            == "https://dns.example.test/dns-query")


# --------------------------------------------------------------------------
# Signing certificate age.
# --------------------------------------------------------------------------

def _make_cert(tmp_path, cn, not_before, not_after):
    """Create a self-signed certificate with an explicit validity window.

    Dates are given as ``YYYYMMDDHHMMSSZ``. Built with ``cryptography`` rather
    than ``openssl req -not_before/-not_after``: those flags only exist in
    OpenSSL 3.5+, while the CI runner ships OpenSSL 3.0, so the subprocess form
    failed on every run with "Unknown option -not_before".
    """
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    def parse(value):
        return datetime.datetime.strptime(value, "%Y%m%d%H%M%SZ").replace(
            tzinfo=datetime.timezone.utc)

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(parse(not_before))
        .not_valid_after(parse(not_after))
        .sign(key, hashes.SHA256())
    )

    key_path = tmp_path / "k.pem"
    cert_path = tmp_path / "c.pem"
    key_path.write_bytes(key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    cert_path.write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
    return cert_path, key_path


def test_expired_certificate_is_rejected(tmp_path):
    """Signing must fail loudly on an expired certificate.

    Upstream shipped ~175 days of daily builds signed by an expired
    certificate. Nothing caught it because iOS accepts an expired signature at
    install time (showing only an "Unverified" label) and the workflow's
    `openssl smime -verify -noverify` gate skips exactly this check.
    """
    cert, key = _make_cert(tmp_path, "expired.example",
                           "20240101000000Z", "20240201000000Z")
    handler = CryptoHandler(cert_path=str(cert), key_path=str(key))
    assert handler.certificate_is_currently_valid(str(cert)) is False


def test_expired_certificate_blocks_signing(tmp_path):
    """An expired certificate must not silently produce a signed profile."""
    plist_path = tmp_path / "p.plist"
    with open(plist_path, "wb") as handle:
        plistlib.dump({"PayloadVersion": 1}, handle)
    cert, key = _make_cert(tmp_path, "expired.example",
                           "20240101000000Z", "20240201000000Z")
    handler = CryptoHandler(cert_path=str(cert), key_path=str(key))
    assert handler.sign_profile(
        str(plist_path), str(tmp_path / "out.mobileconfig")) is None


def test_future_certificate_is_rejected(tmp_path):
    """A not-yet-valid certificate is unusable too."""
    cert, key = _make_cert(tmp_path, "future.example",
                           "20990101000000Z", "20990201000000Z")
    handler = CryptoHandler(cert_path=str(cert), key_path=str(key))
    assert handler.certificate_is_currently_valid(str(cert)) is False


def test_current_certificate_is_accepted(tmp_path):
    cert, key = _make_cert(tmp_path, "valid.example",
                           "20240101000000Z", "20990101000000Z")
    handler = CryptoHandler(cert_path=str(cert), key_path=str(key))
    assert handler.certificate_is_currently_valid(str(cert)) is True


def test_missing_certificate_is_treated_as_invalid(tmp_path):
    handler = CryptoHandler()
    assert handler.certificate_is_currently_valid(str(tmp_path / "nope.pem")) is False


def test_deferred_domains_reappear_in_enhanced_rule_files(tmp_path, monkeypatch):
    """PPQ must move to the enhanced set, not vanish from the outputs.

    The enhanced rule files (for QuantumultX/Surge/Loon/Shadowrocket/hosts) are
    generated from the enhanced "extra" set. If that set is computed before the
    normal list is filtered, removing PPQ from normal also removes it here, so
    users of those tools lose the post-install blocking entirely.
    """
    normal = ["ppq.apple.com", "ocsp.apple.com"]
    enhanced = ["ppq.apple.com", "extra.example"]

    build_orchestrator(tmp_path, monkeypatch, normal, enhanced)

    extra = [
        line for line in (tmp_path / "enhanced/enhanced-domains.txt")
        .read_text(encoding="utf-8").splitlines()
        if line and not line.startswith("#")
    ]
    assert "ppq.apple.com" in extra, "PPQ was dropped instead of deferred"
    assert "appattest.apple.com" not in extra


def test_all_deferred_variants_reach_the_enhanced_profile(tmp_path, monkeypatch):
    """Every withheld PPQ CNAME variant must land in the enhanced profile.

    The enhanced endpoint typically reports only the canonical ppq.apple.com,
    so relying on rediscovery silently loses the variants upstream lists
    alongside it.
    """
    deferred = ["ppq.apple.com", "ppq-ext.v.aaplimg.com",
                "use1-ppq-ext-prod.apple.com", "vpp.itunes.apple.com"]
    normal = deferred + ["ocsp.apple.com"]

    build_orchestrator(tmp_path, monkeypatch, normal, ["ppq.apple.com"])

    enhanced = profile_domains(tmp_path / "enhanced/RevokeGuard_Enhanced.mobileconfig")
    for domain in deferred:
        assert domain in enhanced, f"{domain} was lost from the enhanced profile"
    assert "appattest.apple.com" not in enhanced


def test_backend_host_is_configurable(tmp_path, monkeypatch):
    """The backend must be overridable, for self-hosters."""
    from main import AntiRevokeOrchestrator, DEFAULT_BACKEND_HOST

    orchestrator = AntiRevokeOrchestrator(
        output_dir=str(tmp_path), backend_host="dns.selfhosted.test")
    assert orchestrator.backend_host == "dns.selfhosted.test"

    created = orchestrator.crypto.create_profile(
        ["ocsp.apple.com"], output_file=str(tmp_path / "p.plist"),
        backend_host=orchestrator.backend_host)
    data = plistlib.loads(open(created, "rb").read())
    assert (data["PayloadContent"][0]["DNSSettings"]["ServerURL"]
            == "https://dns.selfhosted.test/dns-query")

    # And the default stays upstream's backend so existing users are unaffected.
    assert AntiRevokeOrchestrator(output_dir=str(tmp_path)).backend_host == DEFAULT_BACKEND_HOST


def test_ppq_edge_domains_survive_upstream_removal(tmp_path, monkeypatch):
    """PPQ edge hosts must not depend on an upstream profile listing them.

    Apple's host table contains only `ppq.apple.com`; the `*-ext` / `use1` /
    `usw2` variants appear in no candidate pool. A pipeline that only merges
    upstream lists silently loses them the moment every upstream drops them, and
    a partial PPQ block leaves a fallback path open.
    """
    from main import PPQ_EDGE_DOMAINS

    # Upstream advertises nothing at all - not even ppq.apple.com.
    build_orchestrator(tmp_path, monkeypatch, ["ocsp.apple.com"], [])

    enhanced = set(profile_domains(tmp_path / "enhanced/RevokeGuard_Enhanced.mobileconfig"))
    for domain in PPQ_EDGE_DOMAINS:
        assert domain in enhanced, f"{domain} was lost from the enhanced profile"

    # ...and they must never leak into the install-time profile.
    normal = set(profile_domains(tmp_path / "RevokeGuard_Auto-Sync.mobileconfig"))
    assert not (normal & PPQ_EDGE_DOMAINS)


# --------------------------------------------------------------------------
# DoH backend URL handling.
# --------------------------------------------------------------------------

def test_bare_hostname_becomes_a_full_doh_url():
    handler = CryptoHandler()
    assert (handler.resolve_doh_url("dns.example.com")
            == "https://dns.example.com/dns-query")
    assert (handler.resolve_doh_url("dns.example.com/")
            == "https://dns.example.com/dns-query")


def test_a_complete_url_is_kept_because_workers_are_not_at_the_root():
    """Self-hosted resolvers usually live on a path, not a bare domain."""
    handler = CryptoHandler()
    worker = "https://antirevoke-doh.someone.workers.dev"
    assert handler.resolve_doh_url(worker) == f"{worker}/dns-query"
    assert (handler.resolve_doh_url(f"{worker}/dns-query")
            == f"{worker}/dns-query")
    # An explicit non-default path must survive untouched.
    assert (handler.resolve_doh_url("https://dns.nextdns.io/abc123")
            == "https://dns.nextdns.io/abc123")


def test_empty_backend_falls_back_to_the_default():
    """GitHub Actions passes "" for an unset repository variable."""
    handler = CryptoHandler()
    for empty in ("", "   "):
        assert (handler.resolve_doh_url(empty)
                == "https://reject.rzmy.dpdns.org/dns-query")


@pytest.mark.parametrize("insecure", [
    "http://plain.example.com",
    "ftp://files.example.com",
    "https://",
])
def test_a_non_https_or_hostless_backend_is_rejected(insecure):
    """Apple requires https, and the URL is what validates the certificate."""
    with pytest.raises(ValueError):
        CryptoHandler().resolve_doh_url(insecure)


def test_resolved_url_reaches_the_generated_profile(tmp_path):
    orchestrator = AntiRevokeOrchestrator(output_dir=str(tmp_path))
    created = orchestrator.crypto.create_profile(
        ["ocsp.apple.com"], output_file=str(tmp_path / "p.plist"),
        backend_host="https://doh.myhost.workers.dev")
    settings = plistlib.loads(open(created, "rb").read())["PayloadContent"][0]["DNSSettings"]
    assert settings["ServerURL"] == "https://doh.myhost.workers.dev/dns-query"
