"""Regression tests for the 2026-10-20 Sideloading (NexRevokeDNS) migration.

Sideloading renamed its DNS payload identifiers from ``novadev.nexdns.*`` to
``novadev.nexrevokedns.*`` and started publishing a broad
``SupplementalMatchDomains`` routing scope that includes Apple's app-attestation
hosts, provider connectivity checks and localhost helpers. Treating that scope
as the block list would have re-broken app installation, so the mode-specific
deny lists must be used instead. These tests pin that behaviour.
"""

import plistlib

from main import (
    ALWAYS_EXCLUDED_DOMAINS,
    PROVIDER_ONLY_DOMAIN_SUFFIXES,
    AntiRevokeOrchestrator,
)
from utils.dns_probe import DomainDiscoveryReport
from utils.scraper import ProfileScraper


def payload(identifier, url, domains):
    return {
        "PayloadIdentifier": identifier,
        "DNSSettings": {
            "DNSProtocol": "HTTPS",
            "ServerURL": url,
            "SupplementalMatchDomains": domains,
        },
    }


def build_profiles(payloads):
    return plistlib.dumps({"PayloadContent": payloads})


def test_extract_plain_domains_accepts_common_list_formats():
    content = b"""
    # comment
    ! adblock comment
    ocsp.apple.com
    ||backloop.dev^
    *.ppq.apple.com
    0.0.0.0 hosts.example
    invalid line without a host
    """

    assert ProfileScraper.extract_plain_domains(content) == [
        "backloop.dev",
        "hosts.example",
        "ocsp.apple.com",
        "ppq.apple.com",
    ]


def test_deny_list_overrides_the_routing_scope(tmp_path):
    """The profile's match-domain scope must not be published as the block list."""
    routing_scope = [
        "appattest.apple.com",
        "register.appattest.apple.com",
        "dns-check.novadev.vip",
        "backloop.dev",
        "ocsp.apple.com",
    ]
    source = {
        "name": "sideloading",
        "url": "https://sideloading.example/dns/",
        "xpath": "//a",
        "preferred_payload_identifiers": [
            "novadev.nexrevokedns.whileinstalling",
            "novadev.nexdns.whileinstalling",
        ],
        "enhanced_payload_identifiers": [
            "novadev.nexrevokedns.afterinstalling",
            "novadev.nexdns.afterinstalling",
        ],
        "domain_list_url": "https://sideloading.example/dns/denylist.txt",
        "enhanced_domain_list_url": (
            "https://sideloading.example/dns/denylist-ppq.txt"
        ),
    }
    profiles = {
        "sideloading": build_profiles([
            payload(
                "novadev.nexrevokedns.whileinstalling",
                "https://dns.example/dns-query",
                routing_scope,
            ),
            payload(
                "novadev.nexrevokedns.afterinstalling",
                "https://dns.example/ppq/dns-query",
                routing_scope,
            ),
        ])
    }
    orchestrator = AntiRevokeOrchestrator(output_dir=str(tmp_path))
    orchestrator.scraper.download_urls = {
        "sideloading": "https://sideloading.example/dns/profile.mobileconfig"
    }
    orchestrator.scraper.domain_lists = {
        "sideloading": ("ocsp.apple.com", "dns-check.novadev.vip")
    }
    orchestrator.scraper.enhanced_domain_lists = {
        "sideloading": (
            "ocsp.apple.com",
            "ppq.apple.com",
            "ppq-check.novadev.vip",
        )
    }

    selected, enhanced = orchestrator.extract_selected_endpoints(profiles, [source])

    # Current namespace wins over the legacy one.
    assert selected[0].payload_identifier == "novadev.nexrevokedns.whileinstalling"
    assert enhanced.payload_identifier == "novadev.nexrevokedns.afterinstalling"
    # The deny list replaced the routing scope, and provider hosts were removed.
    assert selected[0].domains == ("ocsp.apple.com",)
    assert enhanced.domains == ("ocsp.apple.com", "ppq.apple.com")


def test_legacy_payload_identifier_is_a_fallback(tmp_path):
    """A rollback on the upstream side must not break the run."""
    source = {
        "name": "sideloading",
        "url": "https://sideloading.example/dns/",
        "xpath": "//a",
        "preferred_payload_identifiers": [
            "novadev.nexrevokedns.whileinstalling",
            "novadev.nexdns.whileinstalling",
        ],
        "enhanced_payload_identifiers": [
            "novadev.nexrevokedns.afterinstalling",
            "novadev.nexdns.afterinstalling",
        ],
    }
    profiles = {
        "sideloading": build_profiles([
            payload(
                "novadev.nexdns.whileinstalling",
                "https://old.example/dns-query",
                ["ocsp.apple.com"],
            ),
            payload(
                "novadev.nexdns.afterinstalling",
                "https://old.example/ppq/dns-query",
                ["ppq.apple.com"],
            ),
        ])
    }
    orchestrator = AntiRevokeOrchestrator(output_dir=str(tmp_path))
    orchestrator.scraper.download_urls = {"sideloading": "https://x"}

    selected, enhanced = orchestrator.extract_selected_endpoints(profiles, [source])

    assert selected[0].payload_identifier == "novadev.nexdns.whileinstalling"
    assert enhanced.payload_identifier == "novadev.nexdns.afterinstalling"


def test_provider_owned_domains_are_removed_from_reports():
    report = DomainDiscoveryReport(
        target_domains=(
            "certs.apple.com",
            "applejr.net",
            "khoindvn.com",
            "vuvankhoi.com",
            "sub.novadev.vip",
        ),
        blocked_by={
            "certs.apple.com": ("khoindvn",),
            "applejr.net": ("applejr",),
            "khoindvn.com": ("khoindvn",),
            "vuvankhoi.com": ("khoindvn",),
            "sub.novadev.vip": ("applejr",),
        },
        inconclusive_domains=(),
        endpoint_stats={},
        reference_queries=0,
    )

    filtered, removed = AntiRevokeOrchestrator._filter_provider_domains(report)

    assert filtered.target_domains == ("certs.apple.com",)
    assert removed == (
        "applejr.net",
        "khoindvn.com",
        "vuvankhoi.com",
        "sub.novadev.vip",
    )
    assert set(filtered.blocked_by) == {"certs.apple.com"}
    for suffix in ("applejr.net", "khoindvn.com", "vuvankhoi.com"):
        assert suffix in PROVIDER_ONLY_DOMAIN_SUFFIXES


def test_exclusions_match_subdomains():
    """The appattest suffix trap must also catch register./data. hosts."""
    keep, dropped = AntiRevokeOrchestrator._filter_domains(
        [
            "register.appattest.apple.com",
            "data.appattest.apple.com",
            "ocsp.apple.com",
        ],
        ALWAYS_EXCLUDED_DOMAINS,
    )

    assert keep == ["ocsp.apple.com"]
    assert dropped == [
        "data.appattest.apple.com",
        "register.appattest.apple.com",
    ]
