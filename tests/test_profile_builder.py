import storage
from profile_builder import refresh_site_profile, refresh_site_profiles


def test_simple_profile_is_created_for_known_url(isolated_db):
    url = "http://" + "a" * 56 + ".onion/directory"
    storage.insert_or_update_onion_url(url, "a" * 56 + ".onion", source_type="manual_seed")
    assert refresh_site_profiles() == 1
    with storage.get_db() as db:
        profile = db.execute("SELECT * FROM site_profiles WHERE url=?", (url,)).fetchone()
    assert profile["category"] == "Needs classification"
    assert "does not yet have enough" in profile["explanation"]
    assert refresh_site_profile(url) is True
