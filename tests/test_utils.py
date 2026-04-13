from znuzhgfw.core.utils import (
    ScanConfig,
    classify_url,
    is_placeholder_url,
    normalize_url,
    should_scan_target,
    should_enqueue_url,
)


def test_normalize_url_sorts_query_and_strips_tracking() -> None:
    url = "https://Example.com/path/?b=2&utm_source=test&a=1#frag"
    assert normalize_url(url) == "https://example.com/path?a=1&b=2"


def test_classify_url_marks_static_assets() -> None:
    target = classify_url("https://example.com/assets/app.css?ver=1.2.3")
    assert target.category == "stylesheet"
    assert target.is_static is True


def test_classify_url_keeps_json_as_dynamic_surface() -> None:
    target = classify_url("https://example.com/api/search.json?q=test")
    assert target.category == "data-endpoint"
    assert target.is_static is False
    assert should_scan_target(target, ScanConfig()) is True


def test_classify_url_marks_auth_and_common_pages() -> None:
    target = classify_url("https://example.com/login?next=%2Fadmin")
    assert target.category == "document"
    assert "auth-endpoint" in target.tags
    assert "common-page" in target.tags


def test_placeholder_urls_are_filtered() -> None:
    assert is_placeholder_url("searchItem.Url") is True
    assert is_placeholder_url("javascript:void(0)") is True
    assert is_placeholder_url("mailto:test@example.com") is True
    assert is_placeholder_url("/real-path") is False


def test_static_assets_not_enqueued_by_default() -> None:
    config = ScanConfig()
    asset = classify_url("https://example.com/static/app.js")
    assert should_enqueue_url(asset, config) is False


def test_static_assets_can_be_included_or_scanned() -> None:
    asset = classify_url("https://example.com/static/logo.svg")
    assert should_enqueue_url(asset, ScanConfig(include_static=True)) is True
    assert should_enqueue_url(asset, ScanConfig(scan_assets=True)) is True
