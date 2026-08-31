from scripts.check_markdown_links import check_markdown_links


def test_repository_local_markdown_links_resolve():
    assert check_markdown_links() == []


def test_markdown_link_checker_reports_missing_and_escaping_targets(tmp_path):
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "guide.md").write_text(
        "[missing](missing.md)\n[escape](../../outside.md)\n[web](https://example.com)\n",
        encoding="utf-8",
    )

    errors = check_markdown_links(tmp_path)

    assert any("missing local link: missing.md" in error for error in errors)
    assert any("link escapes repository: ../../outside.md" in error for error in errors)
    assert not any("example.com" in error for error in errors)
