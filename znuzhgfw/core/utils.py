import re
from urllib.parse import urlparse, urljoin, urlencode, parse_qs

import requests


def make_session(user_agent: str = "Mozilla/5.0 ZNUZHG-FW"):
    s = requests.Session()
    s.headers.update({"User-Agent": user_agent})
    return s


def inject_param_to_url(url: str, param: str, value: str) -> str:
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    if not qs:
        return url
    qs[param] = [value]
    new_query = urlencode(qs, doseq=True)
    return parsed._replace(query=new_query).geturl()


def extract_forms(html: str, base_url: str):
    """
    Çok basit form keşfi:
    - action
    - method
    - input name
    """
    forms = []
    form_pattern = re.compile(r"<form(.*?)>(.*?)</form>", re.IGNORECASE | re.DOTALL)
    input_pattern = re.compile(
        r"<input[^>]*name=[\"'](.*?)[\"'][^>]*>", re.IGNORECASE | re.DOTALL
    )
    method_pattern = re.compile(r"method=[\"'](.*?)[\"']", re.IGNORECASE)
    action_pattern = re.compile(r"action=[\"'](.*?)[\"']", re.IGNORECASE)

    for form_match in form_pattern.finditer(html):
        form_tag = form_match.group(1)
        form_body = form_match.group(2)

        method_match = method_pattern.search(form_tag)
        action_match = action_pattern.search(form_tag)
        method = method_match.group(1).upper() if method_match else "GET"
        action_raw = action_match.group(1) if action_match else ""
        action_url = urljoin(base_url, action_raw)

        inputs = input_pattern.findall(form_body)
        forms.append(
            {
                "method": method,
                "action": action_url,
                "inputs": list(set(inputs)),
            }
        )

    return forms
