from pathlib import Path

import report_builder
import storage


def test_cluster_report_includes_categories_and_preview_reference(isolated_db, tmp_path, monkeypatch):
    reports = tmp_path / "reports"
    monkeypatch.setattr(report_builder, "REPORTS_DIR", reports)
    url = "http://" + "a" * 56 + ".onion/directory"
    cluster_id = storage.create_or_update_mirror_cluster(
        url, "Hidden Service Directory", "content-hash", "fuzzy-hash", [], 5, 5, "BAJO", "test"
    )
    storage.upsert_page_preview(url, str(reports / "previews" / "preview.png"))
    output = Path(report_builder.build_cluster_report(cluster_id, "pytest"))
    content = output.read_text(encoding="utf-8")
    assert "Hidden Service Directory" in content
    assert "Preview available" in content
    assert "passive shared indicators" in content


def test_restricted_item_report_contains_metadata_but_no_unsafe_fields(isolated_db, tmp_path, monkeypatch):
    import pytest
    reports = tmp_path / "reports"
    monkeypatch.setattr(report_builder, "REPORTS_DIR", reports)
    url = "http://" + "a" * 56 + ".onion/porn"
    from universal_classifier import classify
    policy = classify(
        url, title="Adult content",
        visible_text="Pornography and explicit sexual adult content",
    )
    policy.update(
        analyst_category=policy["primary_category"],
        classification_evidence_source="analyst",
    )
    storage.insert_or_update_onion_url(url, policy=policy)
    with storage.get_db() as db:
        db.execute("UPDATE onion_urls SET title=?,reasons=? WHERE url=?", ("unsafe title", "unsafe raw text", url))
    with pytest.raises(ValueError, match="Adult-filtered"):
        report_builder.build_url_report(url, "pytest")
    with storage.get_db() as db:
        assert db.execute("SELECT COUNT(*) FROM evidence_reports").fetchone()[0] == 0
