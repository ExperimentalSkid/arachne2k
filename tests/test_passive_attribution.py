from passive_attribution import LIMITATIONS, score_passive_attribution


def indicator(kind, value, source):
    return {"type": kind, "normalized_value": value, "source_type": source}


def test_scoring_confidence_and_limitations():
    base = [indicator("telegram_handle","@x","telegram"), indicator("telegram_handle","@x","onion")]
    assert score_passive_attribution(base, [], [])["confidence_score"] == 25
    wallets = [indicator("wallet_btc","w","telegram"), indicator("wallet_btc","w","onion")]
    assert score_passive_attribution(wallets, [], [])["confidence_score"] == 25
    urls = [{"url":"http://a/","content_hash":"h"},{"url":"http://b/","content_hash":"h"}]
    assert score_passive_attribution([], urls, [])["confidence_score"] == 20
    many = base + wallets + [indicator("email","e","telegram"), indicator("email","e","onion"), indicator("pgp_key_block","p","telegram"), indicator("pgp_key_block","p","onion")]
    result = score_passive_attribution(many, urls, [])
    assert result["confidence_score"] == 100 and result["confidence_level"] == "HIGH"
    assert score_passive_attribution([], [], [])["confidence_level"] == "LOW"
    assert "does not reveal" in LIMITATIONS

