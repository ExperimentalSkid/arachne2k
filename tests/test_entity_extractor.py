from entity_extractor import (canonical_profile_identity, extract_indicators, extract_public_aliases,
                              normalize_public_alias, parse_profile_identity,
                              public_alias_skeleton)


def test_extracts_public_indicators_safely():
    onion = "a" * 56 + ".onion"
    text = ("Contact @ExampleUser analyst@example.org "
            "1BoatSLRHtKNngkdXEeobR76b53LETtpyT 0x52908400098527886E0F7030069857D2E4169EE7 "
            "-----BEGIN PGP PUBLIC KEY BLOCK----- SECRETBODY -----END PGP PUBLIC KEY BLOCK----- "
            "password=hunter2 https://example.org/path http://" + onion + "/")
    result = extract_indicators(text)
    kinds = {item["type"] for item in result}
    assert {"telegram_handle", "onion_domain", "email", "wallet_btc", "wallet_eth", "pgp_key_block", "clearnet_url"} <= kinds
    assert all("SECRETBODY" not in item["context"] and "hunter2" not in item["context"] for item in result)


def test_openpgp_provider_pivot_requires_an_explicit_labeled_fingerprint():
    fingerprint = "0123 4567 89AB CDEF 0123 4567 89AB CDEF 0123 4567"
    result = extract_indicators(
        f"PGP fingerprint: {fingerprint} unrelated "
        "AAAABBBBCCCCDDDDEEEEFFFF0000111122223333")
    pivots = [item for item in result if item["type"] == "pgp_fingerprint"]

    assert len(pivots) == 1
    assert pivots[0]["normalized_value"] == "0123456789ABCDEF0123456789ABCDEF01234567"
    assert pivots[0]["context"] == "[REDACTED PGP FINGERPRINT]"

    unlabeled = extract_indicators("0123456789ABCDEF0123456789ABCDEF01234567")
    assert not any(item["type"] == "pgp_fingerprint" for item in unlabeled)


def test_unicode_alias_identity_is_not_replaced_by_review_skeleton():
    assert normalize_public_alias(" @NíghtFöx ") == "níghtföx"
    assert public_alias_skeleton("NíghtFöx") == "nightfox"
    # A lookalike may share a skeleton, but canonical identity remains distinct.
    assert normalize_public_alias("Аlice") != normalize_public_alias("Alice")
    assert public_alias_skeleton("Аlice") == public_alias_skeleton("Alice")


def test_profile_identity_distinguishes_named_slugs_and_numeric_ids():
    named = parse_profile_identity("http://example.onion/user/NightFox")
    numeric = parse_profile_identity(
        "http://example.onion/memberlist.php?mode=viewprofile&u=417")
    user_id = parse_profile_identity("http://example.onion/profile.php?user_id=88")

    assert named == {"value": "NightFox", "kind": "named", "source": "path", "key": "user"}
    assert numeric["value"] == "417" and numeric["kind"] == "numeric" and numeric["key"] == "u"
    assert user_id["value"] == "88" and user_id["kind"] == "numeric"
    assert canonical_profile_identity("http://example.onion/user/NightFox") == "path:user:nightfox"
    assert canonical_profile_identity(
        "http://example.onion/memberlist.php?mode=viewprofile&u=417") == "query:u:417"


def test_flat_profile_links_require_named_slug_agreement_and_reject_digit_leading():
    aliases = extract_public_aliases(
        "Author: NightFox Author: 4Runner",
        [
            {"url": "http://example.onion/user/OtherFox", "anchor_text": "NightFox"},
            {"url": "http://example.onion/memberlist.php?mode=viewprofile&u=17",
             "anchor_text": "Alice77"},
            {"url": "http://example.onion/user/NightFox", "anchor_text": "NightFox"},
        ],
    )
    by_name = {item["normalized_alias"]: item for item in aliases}

    assert "4runner" not in by_name
    assert "alice77" not in by_name
    assert by_name["nightfox"]["auto_store_eligible"] is True
    assert by_name["nightfox"]["profile_url"].endswith("/user/NightFox")


def test_flat_alias_evidence_keeps_distinct_matching_profile_identities():
    aliases = extract_public_aliases(
        "Author: @NightFox",
        [
            {"url": "http://example.onion/user/NightFox", "anchor_text": "NightFox"},
            {"url": "http://example.onion/vendor/NightFox", "anchor_text": "NightFox"},
            {"url": "http://example.onion/user/NightFox", "anchor_text": "NightFox"},
        ],
    )
    matching = [item for item in aliases if item["normalized_alias"] == "nightfox"]

    assert len(matching) == 2
    assert {item["profile_url"] for item in matching} == {
        "http://example.onion/user/NightFox",
        "http://example.onion/vendor/NightFox",
    }
    assert all(item["auto_store_eligible"] for item in matching)
