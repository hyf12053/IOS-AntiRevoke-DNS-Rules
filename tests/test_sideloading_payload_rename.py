"""Regression tests for the 2026-10-25 Sideloading payload rename.

Sideloading has now renamed its DNS payload namespace twice in six days:

* before 2026-10-20: ``novadev.nexdns.whileinstalling`` / ``.afterinstalling``
* 2026-10-20:        ``novadev.nexrevokedns.whileinstalling`` / ``.afterinstalling``
* 2026-10-25:        ``nexsideloading.nexrevokedns.duringinstall`` / ``.afterinstall``

The 10-20 rename broke four consecutive daily runs (2026-10-20/21/22/23) because
the identifiers were pinned exactly. These tests pin the second line of defence:
when the namespace changes again, the mode *suffix* still selects the right
payload and the run only logs a warning.
"""

import plistlib

import pytest

from main import PROFILE_SOURCES, AntiRevokeOrchestrator
from utils.crypto_handler import CryptoHandler

SOURCE = next(item for item in PROFILE_SOURCES if item["name"] == "sideloading")


def payload(identifier, url, domains=None):
    settings = {"DNSProtocol": "HTTPS", "ServerURL": url}
    if domains is not None:
        settings["SupplementalMatchDomains"] = domains
    return {"PayloadIdentifier": identifier, "DNSSettings": settings}


def endpoints(payloads):
    return CryptoHandler().extract_dns_endpoints(
        {"PayloadContent": payloads}, "sideloading"
    )


def test_current_upstream_identifiers_are_selected():
    """The identifiers observed live on 2026-10-26 must be the pinned ones."""
    found = endpoints([
        payload("nexsideloading.nexrevokedns.afterinstall",
                "https://dns.sideloading.net/ppq/dns-query"),
        payload("nexsideloading.nexrevokedns.duringinstall",
                "https://dns.sideloading.net/dns-query"),
    ])

    normal = AntiRevokeOrchestrator._select_endpoint(SOURCE, found)
    enhanced = AntiRevokeOrchestrator._select_endpoint(SOURCE, found, mode="enhanced")

    assert normal.payload_identifier == "nexsideloading.nexrevokedns.duringinstall"
    assert normal.url == "https://dns.sideloading.net/dns-query"
    assert enhanced.payload_identifier == "nexsideloading.nexrevokedns.afterinstall"
    assert enhanced.url == "https://dns.sideloading.net/ppq/dns-query"


@pytest.mark.parametrize(
    "normal_id,enhanced_id",
    [
        # A hypothetical next rename: prefix changes, mode suffix stays.
        ("futurebrand.nexrevokedns.duringinstall",
         "futurebrand.nexrevokedns.afterinstall"),
        # The 2026-10-20 namespace, still served by some mirrors.
        ("novadev.nexrevokedns.whileinstalling",
         "novadev.nexrevokedns.afterinstalling"),
    ],
)
def test_mode_suffix_marker_survives_a_namespace_rename(normal_id, enhanced_id):
    found = endpoints([
        payload(enhanced_id, "https://dns.example/ppq/dns-query"),
        payload(normal_id, "https://dns.example/dns-query"),
    ])

    normal = AntiRevokeOrchestrator._select_endpoint(SOURCE, found)
    enhanced = AntiRevokeOrchestrator._select_endpoint(SOURCE, found, mode="enhanced")

    assert normal.payload_identifier == normal_id
    assert enhanced.payload_identifier == enhanced_id


def test_marker_never_swaps_the_modes():
    """Only the normal payload is present: enhanced must fail, not borrow it."""
    found = endpoints([
        payload("nexsideloading.nexrevokedns.duringinstall",
                "https://dns.sideloading.net/dns-query"),
    ])

    with pytest.raises(RuntimeError, match="no longer contains any preferred payload"):
        AntiRevokeOrchestrator._select_endpoint(SOURCE, found, mode="enhanced")


def test_marker_matches_a_component_not_a_prefix_of_one():
    """``duringinstall`` must not match ``duringinstallment``.

    The marker is compared against whole dot-separated components, so a future
    upstream that appends a version component (``…duringinstall.v2``) still
    matches, while a look-alike word does not.
    """
    found = endpoints([
        payload("brand.nexrevokedns.duringinstall.v2",
                "https://dns.example/dns-query"),
    ])

    assert AntiRevokeOrchestrator._select_endpoint(
        SOURCE, found
    ).payload_identifier == "brand.nexrevokedns.duringinstall.v2"

    look_alike = endpoints([
        payload("brand.nexrevokedns.duringinstallment",
                "https://dns.example/dns-query"),
    ])
    with pytest.raises(RuntimeError, match="no longer contains any preferred payload"):
        AntiRevokeOrchestrator._select_endpoint(SOURCE, look_alike)


def test_error_message_lists_what_the_profile_actually_contains():
    """A failed run must be diagnosable from the log alone."""
    found = endpoints([
        payload("somebrand.unrelated.mode", "https://dns.example/dns-query"),
    ])

    with pytest.raises(RuntimeError) as excinfo:
        AntiRevokeOrchestrator._select_endpoint(SOURCE, found)

    message = str(excinfo.value)
    assert "somebrand.unrelated.mode" in message
    assert "nexsideloading.nexrevokedns.duringinstall" in message
