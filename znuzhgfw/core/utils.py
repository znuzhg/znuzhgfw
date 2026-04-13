from __future__ import annotations

import re
from dataclasses import dataclass, field
from hashlib import sha1
from typing import Any, Iterable, Mapping
from urllib.parse import parse_qs, urlencode, urljoin, urlsplit, urlunsplit

import requests


SEVERITY_ORDER = {
    "INFO": 0,
    "LOW": 1,
    "MEDIUM": 2,
    "HIGH": 3,
    "CRITICAL": 4,
}
CONFIDENCE_ORDER = {
    "LOW": 0,
    "MEDIUM": 1,
    "HIGH": 2,
}
PROOF_ORDER = {
    "pattern": 0,
    "heuristic": 1,
    "reflected": 2,
    "verified": 3,
}

TRACKING_PARAMS = {
    "fbclid",
    "gclid",
    "mc_cid",
    "mc_eid",
    "ref",
    "ref_src",
    "source",
}
LOW_SIGNAL_PARAMS = {
    "_",
    "cache",
    "cachebuster",
    "cb",
    "hash",
    "timestamp",
    "ts",
    "v",
    "ver",
    "version",
}
SSTI_CANDIDATE_PARAMS = {
    "category",
    "filter",
    "id",
    "lang",
    "name",
    "page",
    "q",
    "query",
    "search",
    "sort",
    "template",
    "view",
}
LFI_CANDIDATE_PARAMS = {
    "download",
    "doc",
    "file",
    "folder",
    "include",
    "lang",
    "load",
    "page",
    "path",
    "template",
    "view",
}
REDIRECT_CANDIDATE_PARAMS = {
    "callback",
    "continue",
    "dest",
    "destination",
    "next",
    "redir",
    "redirect",
    "return",
    "returnto",
    "target",
    "url",
}
RATE_LIMIT_HINTS = (
    "api",
    "auth",
    "forgot",
    "graphql",
    "login",
    "oauth",
    "password",
    "query",
    "reset",
    "search",
    "signin",
    "token",
)
AUTH_HINTS = (
    "auth",
    "login",
    "logout",
    "otp",
    "password",
    "register",
    "reset",
    "session",
    "signin",
    "signup",
    "token",
)
COMMON_ENDPOINT_HINTS = (
    "/admin",
    "/login",
    "/signin",
    "/user/login",
    "/wp-admin",
    "/wp-login.php",
)
PLACEHOLDER_TOKENS = (
    "{{",
    "}}",
    "${",
    "<%",
    "%>",
    "searchitem.url",
    "notificationitem.weburl",
    "undefined",
)
NON_HTTP_SCHEMES = ("javascript:", "mailto:", "tel:", "data:")

IMAGE_EXTENSIONS = {
    ".gif",
    ".ico",
    ".jpeg",
    ".jpg",
    ".png",
    ".svg",
    ".webp",
}
STYLESHEET_EXTENSIONS = {".css"}
JAVASCRIPT_EXTENSIONS = {".js", ".mjs"}
FONT_EXTENSIONS = {".eot", ".ttf", ".woff", ".woff2"}
DATA_EXTENSIONS = {".json", ".xml"}
FEED_EXTENSIONS = {".rss"}
BINARY_EXTENSIONS = {
    ".7z",
    ".bz2",
    ".gz",
    ".mp3",
    ".mp4",
    ".pdf",
    ".rar",
    ".tar",
    ".zip",
}
DYNAMIC_PAGE_EXTENSIONS = {
    ".asp",
    ".aspx",
    ".cfm",
    ".cgi",
    ".do",
    ".jsp",
    ".jspx",
    ".php",
}
STATIC_CATEGORIES = {
    "binary-download",
    "feed-asset",
    "image",
    "javascript",
    "static-asset",
    "stylesheet",
}
TEXT_LIKE_CONTENT_TYPES = (
    "application/javascript",
    "application/json",
    "application/ld+json",
    "application/xml",
    "application/xhtml+xml",
    "text/",
)


@dataclass(slots=True, frozen=True)
class ScanConfig:
    include_static: bool = False
    scan_assets: bool = False
    dedupe: bool = True
    confidence_threshold: str = "LOW"
    proof_threshold: str = "pattern"
    max_urls: int | None = None
    skip_rate_limit: bool = False
    skip_headers: bool = False
    skip_dirscan: bool = False
    strip_tracking_params: bool = True


@dataclass(slots=True)
class URLInfo:
    url: str
    normalized_url: str
    host: str
    host_url: str
    scheme: str
    path: str
    query: dict[str, list[str]]
    extension: str
    category: str
    tags: tuple[str, ...] = ()
    content_type: str = ""
    depth: int = 0

    @property
    def is_document(self) -> bool:
        return self.category == "document"

    @property
    def is_static(self) -> bool:
        return self.category in STATIC_CATEGORIES

    @property
    def has_query(self) -> bool:
        return bool(self.query)

    @property
    def is_dynamic(self) -> bool:
        return not self.is_static


@dataclass(slots=True)
class ScanContext:
    target: URLInfo
    response: requests.Response | None
    text: str = ""
    html: str = ""
    status_code: int = 0
    content_type: str = ""

    @property
    def is_document(self) -> bool:
        return self.target.is_document

    @property
    def is_static(self) -> bool:
        return self.target.is_static

    @property
    def is_dynamic(self) -> bool:
        return self.target.is_dynamic


def make_session(user_agent: str = "Mozilla/5.0 ZNUZHG-FW") -> requests.Session:
    session = requests.Session()
    session.headers.update({"User-Agent": user_agent})
    return session


def normalize_severity(value: str) -> str:
    return (value or "INFO").upper()


def normalize_confidence(value: str) -> str:
    return (value or "LOW").upper()


def normalize_proof_level(value: str) -> str:
    lowered = (value or "pattern").lower()
    return lowered if lowered in PROOF_ORDER else "pattern"


def level_at_least(value: str, threshold: str, order: Mapping[str, int]) -> bool:
    return order.get(value, 0) >= order.get(threshold, 0)


def stronger_level(current: str, new_value: str, order: Mapping[str, int]) -> str:
    return new_value if order.get(new_value, 0) > order.get(current, 0) else current


def merge_unique_strings(existing: list[str], values: Iterable[str], limit: int = 8) -> list[str]:
    for value in values:
        clean = str(value or "").strip()
        if clean and clean not in existing:
            existing.append(clean)
        if len(existing) >= limit:
            break
    return existing


def hash_value(*parts: Any) -> str:
    joined = "|".join(str(part) for part in parts if part not in (None, "", [], {}))
    return sha1(joined.encode("utf-8")).hexdigest()


def normalize_url(url: str, *, strip_tracking: bool = True) -> str:
    raw = (url or "").strip()
    if not raw:
        return ""

    parsed = urlsplit(raw)
    scheme = (parsed.scheme or "http").lower()
    netloc = parsed.netloc.lower()
    if scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]
    if scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]

    path = re.sub(r"/{2,}", "/", parsed.path or "/")
    if not path.startswith("/"):
        path = f"/{path}"
    if path != "/" and path.endswith("/"):
        path = path.rstrip("/")

    query_items: list[tuple[str, str]] = []
    for key, values in parse_qs(parsed.query, keep_blank_values=True).items():
        normalized_key = key.strip()
        if strip_tracking and (
            normalized_key.lower().startswith("utm_")
            or normalized_key.lower() in TRACKING_PARAMS
        ):
            continue
        for value in values or [""]:
            query_items.append((normalized_key, value))

    query_items.sort(key=lambda item: (item[0], item[1]))
    query = urlencode(query_items, doseq=True)
    return urlunsplit((scheme, netloc, path, query, ""))


def get_query_params(url: str) -> dict[str, list[str]]:
    return parse_qs(urlsplit(url).query, keep_blank_values=True)


def inject_param_to_url(url: str, param: str, value: str) -> str:
    parsed = urlsplit(url)
    query = parse_qs(parsed.query, keep_blank_values=True)
    if not query:
        return url
    query[param] = [value]
    new_query = urlencode(query, doseq=True)
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, new_query, ""))


def is_placeholder_url(raw_link: str) -> bool:
    lowered = (raw_link or "").strip().lower()
    if not lowered or lowered in {"#", "/", "javascript:void(0)", "javascript:void(0);"}:
        return True
    if lowered.startswith(NON_HTTP_SCHEMES):
        return True
    return any(token in lowered for token in PLACEHOLDER_TOKENS)


def response_is_text_like(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return any(token in lowered for token in TEXT_LIKE_CONTENT_TYPES)


def response_is_html(content_type: str) -> bool:
    lowered = (content_type or "").lower()
    return "text/html" in lowered or "application/xhtml+xml" in lowered


def classify_url(
    url: str,
    *,
    content_type: str | None = None,
    depth: int = 0,
    strip_tracking: bool = True,
) -> URLInfo:
    normalized_url = normalize_url(url, strip_tracking=strip_tracking)
    parsed = urlsplit(normalized_url)
    path = parsed.path or "/"
    path_lower = path.lower()
    file_name = path_lower.rsplit("/", 1)[-1]
    extension = ""
    if "." in file_name:
        extension = f".{file_name.rsplit('.', 1)[-1]}"

    content_type_lower = (content_type or "").split(";", 1)[0].strip().lower()
    category = "document"

    if file_name == "manifest.json" or file_name.startswith("favicon"):
        category = "static-asset"
    elif extension in STYLESHEET_EXTENSIONS or "text/css" in content_type_lower:
        category = "stylesheet"
    elif extension in JAVASCRIPT_EXTENSIONS or "javascript" in content_type_lower:
        category = "javascript"
    elif extension in IMAGE_EXTENSIONS or content_type_lower.startswith("image/"):
        category = "image"
    elif extension in FONT_EXTENSIONS or content_type_lower.startswith("font/"):
        category = "static-asset"
    elif (
        path_lower.endswith("/feed")
        or extension in FEED_EXTENSIONS
        or "rss" in content_type_lower
        or "atom" in content_type_lower
    ):
        category = "feed-asset"
    elif (
        extension in DATA_EXTENSIONS
        or content_type_lower in {"application/json", "application/xml", "text/xml"}
    ):
        category = "data-endpoint"
    elif (
        extension in BINARY_EXTENSIONS
        or content_type_lower.startswith("audio/")
        or content_type_lower.startswith("video/")
        or content_type_lower
        in {"application/octet-stream", "application/pdf", "application/zip"}
    ):
        category = "binary-download"
    elif content_type_lower and response_is_html(content_type_lower):
        category = "document"
    elif extension and extension not in DYNAMIC_PAGE_EXTENSIONS:
        category = "static-asset"

    tags: list[str] = []
    if parsed.query:
        tags.append("query-bearing-dynamic-url")
    if any(hint in path_lower for hint in AUTH_HINTS):
        tags.append("auth-endpoint")
    if any(path_lower == hint or path_lower.startswith(f"{hint}/") for hint in COMMON_ENDPOINT_HINTS):
        tags.append("common-page")

    host_url = urlunsplit((parsed.scheme, parsed.netloc, "/", "", ""))
    return URLInfo(
        url=url,
        normalized_url=normalized_url,
        host=parsed.netloc,
        host_url=host_url,
        scheme=parsed.scheme,
        path=path,
        query=parse_qs(parsed.query, keep_blank_values=True),
        extension=extension,
        category=category,
        tags=tuple(sorted(set(tags))),
        content_type=content_type_lower,
        depth=depth,
    )


def should_enqueue_url(target: URLInfo, config: ScanConfig, *, is_base_target: bool = False) -> bool:
    if is_base_target:
        return True
    if target.is_static and not (config.include_static or config.scan_assets):
        return False
    return True


def should_scan_target(target: URLInfo, config: ScanConfig) -> bool:
    return target.is_dynamic or config.scan_assets


def is_candidate_param(name: str, purpose: str = "generic") -> bool:
    lowered = (name or "").strip().lower()
    if not lowered:
        return False
    if lowered.startswith("utm_") or lowered in LOW_SIGNAL_PARAMS or lowered in TRACKING_PARAMS:
        return False

    if purpose == "ssti":
        return lowered in SSTI_CANDIDATE_PARAMS
    if purpose == "lfi":
        return lowered in LFI_CANDIDATE_PARAMS
    if purpose == "redirect":
        return lowered in REDIRECT_CANDIDATE_PARAMS
    if purpose == "xss":
        return True
    if purpose == "sqli":
        return True
    return True


def is_rate_limit_candidate(target: URLInfo) -> bool:
    if target.is_static:
        return False

    path_lower = target.path.lower()
    if "auth-endpoint" in target.tags:
        return True
    if any(token in path_lower for token in RATE_LIMIT_HINTS):
        return True
    if any(
        candidate in {"email", "login", "password", "q", "query", "search", "username"}
        for candidate in target.query
    ):
        return True
    return False


def is_sensitive_method_target(target: URLInfo) -> bool:
    return target.is_document and (
        target.path == "/" or "auth-endpoint" in target.tags or "common-page" in target.tags
    )


def build_context(
    url: str,
    response: requests.Response | None,
    *,
    depth: int = 0,
    strip_tracking: bool = True,
) -> ScanContext:
    content_type = ""
    text = ""
    if response is not None:
        content_type = response.headers.get("Content-Type", "")
        if response_is_text_like(content_type):
            try:
                text = response.text
            except Exception:
                text = ""

    target = classify_url(
        url,
        content_type=content_type,
        depth=depth,
        strip_tracking=strip_tracking,
    )
    html = text if response_is_html(content_type) else ""
    return ScanContext(
        target=target,
        response=response,
        text=text,
        html=html,
        status_code=response.status_code if response is not None else 0,
        content_type=content_type,
    )


def merge_evidence(
    existing: dict[str, Any],
    incoming: Mapping[str, Any] | None,
    *,
    limit: int = 6,
) -> dict[str, Any]:
    if not incoming:
        return existing

    for key, value in incoming.items():
        if value in (None, "", [], {}):
            continue
        if key not in existing:
            existing[key] = value
            continue

        current = existing[key]
        if current == value:
            continue

        current_items = current if isinstance(current, list) else [current]
        new_items = value if isinstance(value, list) else [value]
        merged = [str(item) for item in current_items if str(item).strip()]
        merge_unique_strings(merged, (str(item) for item in new_items), limit=limit)
        existing[key] = merged

    return existing


def extract_forms(html: str, base_url: str) -> list[dict[str, Any]]:
    forms = []
    form_pattern = re.compile(r"<form(.*?)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    input_pattern = re.compile(
        r"<input[^>]*name=[\"'](.*?)[\"'][^>]*>",
        re.IGNORECASE | re.DOTALL,
    )
    method_pattern = re.compile(r"method=[\"'](.*?)[\"']", re.IGNORECASE)
    action_pattern = re.compile(r"action=[\"'](.*?)[\"']", re.IGNORECASE)

    for form_match in form_pattern.finditer(html or ""):
        form_tag = form_match.group(1)
        form_body = form_match.group(2)
        method_match = method_pattern.search(form_tag)
        action_match = action_pattern.search(form_tag)
        method = method_match.group(1).upper() if method_match else "GET"
        action_raw = action_match.group(1) if action_match else ""
        action_url = urljoin(base_url, action_raw)
        inputs = sorted(set(input_pattern.findall(form_body)))
        forms.append({"method": method, "action": action_url, "inputs": inputs})

    return forms
