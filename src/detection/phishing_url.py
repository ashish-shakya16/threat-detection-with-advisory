"""Local phishing URL analysis.

Parses a URL and scores lexical and structural phishing indicators. The URL
is never opened, fetched, or sent to a third party, so this cannot be used to
reach internal services (no SSRF) and does not leak private links.

Verdicts:
    High-risk URL indicators   score >= 60
    Suspicious URL             score >= 25
    No known phishing indicators

There is no phishing-feed or domain-reputation lookup, so a URL is never
reported as confirmed phishing, and "no indicators" does not mean safe.
"""

import ipaddress
import re
from typing import Any, Dict, List, Tuple
from urllib.parse import unquote, urlsplit

MAX_URL_LENGTH = 2048

# brand keyword -> legitimate registered domains
BRANDS = {
    'paypal': ['paypal.com'],
    'microsoft': ['microsoft.com', 'live.com', 'office.com', 'microsoftonline.com', 'outlook.com'],
    'office365': ['office.com', 'microsoft.com'],
    'outlook': ['outlook.com', 'live.com', 'office.com'],
    'google': ['google.com', 'google.co.in', 'gmail.com', 'youtube.com'],
    'gmail': ['gmail.com', 'google.com'],
    'apple': ['apple.com', 'icloud.com'],
    'icloud': ['icloud.com', 'apple.com'],
    'amazon': ['amazon.com', 'amazon.in', 'amazon.co.uk'],
    'netflix': ['netflix.com'],
    'facebook': ['facebook.com', 'fb.com'],
    'instagram': ['instagram.com'],
    'whatsapp': ['whatsapp.com'],
    'linkedin': ['linkedin.com'],
    'dropbox': ['dropbox.com'],
    'adobe': ['adobe.com'],
    'sbi': ['sbi.co.in', 'onlinesbi.sbi'],
    'hdfc': ['hdfcbank.com'],
    'icici': ['icicibank.com'],
    'paytm': ['paytm.com'],
}
SHORTENERS = {'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'cutt.ly', 'rb.gy', 'shorturl.at'}
SUSPICIOUS_TLDS = {'zip', 'mov', 'top', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'click', 'link', 'work', 'rest',
                   'fit', 'support', 'country', 'kim', 'cam', 'icu', 'buzz', 'monster'}
TWO_LEVEL_SUFFIXES = {'co.uk', 'co.in', 'co.jp', 'com.au', 'com.br', 'org.uk', 'gov.in', 'ac.in', 'net.in',
                      'org.in', 'co.nz', 'com.cn', 'com.mx'}
LURE_WORDS = {'login', 'signin', 'logon', 'verify', 'verification', 'account', 'update', 'secure', 'security',
              'password', 'wallet', 'banking', 'confirm', 'suspend', 'unlock', 'billing', 'invoice', 'gift', 'prize'}
HOMOGLYPHS = str.maketrans({'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '@': 'a', '$': 's'})


def _registered_domain(host: str) -> str:
    labels = host.split('.')
    if len(labels) >= 3 and '.'.join(labels[-2:]) in TWO_LEVEL_SUFFIXES:
        return '.'.join(labels[-3:])
    return '.'.join(labels[-2:])


def _edit_distance(a: str, b: str) -> int:
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        for j, cb in enumerate(b, 1):
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + (ca != cb)))
        previous = current
    return previous[-1]


def analyze_url(raw_url: str) -> Dict[str, Any]:
    """Return a verdict, score, evidence and advice. Raises ValueError for invalid input."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError('A URL is required')
    url = raw_url.strip()
    if len(url) > MAX_URL_LENGTH:
        raise ValueError(f'URL must be {MAX_URL_LENGTH} characters or fewer')
    if not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*://', url):
        url = 'http://' + url
    parts = urlsplit(url)
    if parts.scheme.lower() not in ('http', 'https'):
        raise ValueError('Only http and https URLs can be analysed')
    host = (parts.hostname or '').lower().rstrip('.')
    if not host:
        raise ValueError('The URL has no host name')

    findings: List[Tuple[int, str, str]] = []  # (weight, indicator, detail)

    def add(weight, indicator, detail):
        findings.append((weight, indicator, detail))

    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None

    if '@' in (parts.netloc or ''):
        add(50, 'Credentials-style URL', 'Text before "@" hides the real destination, which is '
                                         f'"{host}".')
    if ip is not None:
        add(30, 'IP address instead of a domain', f'The link points straight to {host}. Legitimate sign-in '
                                                    'pages almost always use a domain name.')
        if ip.is_private or ip.is_loopback:
            add(5, 'Private network address', 'The address is on a private network.')

    registered = host if ip else _registered_domain(host)
    domain_label = registered.split('.')[0] if not ip else ''

    if host.startswith('xn--') or '.xn--' in host:
        add(30, 'Internationalised (punycode) domain', 'The domain uses encoded characters that can imitate '
                                                       'normal letters.')
    tld = host.rsplit('.', 1)[-1] if not ip else ''
    if tld in SUSPICIOUS_TLDS:
        add(15, 'Frequently abused top-level domain', f'".{tld}" domains are disproportionately used for abuse.')
    if registered in SHORTENERS:
        add(25, 'Link shortener', 'The real destination is hidden behind a shortening service.')

    if not ip:
        subdomain_count = max(len(host.split('.')) - len(registered.split('.')), 0)
        if subdomain_count >= 3:
            add(15, 'Many subdomains', f'{subdomain_count} subdomain levels before "{registered}".')
        if domain_label.count('-') >= 2 and not domain_label.startswith('xn--'):
            add(10, 'Hyphenated domain', f'"{registered}" contains several hyphens.')

        lowered_path = unquote(parts.path + '?' + parts.query).lower()
        host_tokens = set(re.split(r'[.\-]', host))
        path_tokens = set(re.findall(r'[a-z0-9]+', lowered_path))
        for brand, legitimate in BRANDS.items():
            if registered in legitimate:
                continue
            normalized = domain_label.translate(HOMOGLYPHS)
            if domain_label != brand and (normalized == brand or (len(brand) >= 5 and 0 < _edit_distance(domain_label, brand) <= 1)):
                add(45, 'Look-alike domain', f'"{registered}" imitates {brand} ({", ".join(legitimate)}).')
            elif brand in host_tokens or (len(brand) >= 5 and brand in host):
                add(35, 'Brand name outside its official domain',
                    f'"{brand}" appears in "{host}", but {brand} uses {", ".join(legitimate)}.')
            elif brand in path_tokens:
                add(15, 'Brand name in the path', f'"{brand}" appears in the path of a non-{brand} site.')

    words = set(re.findall(r'[a-z]+', unquote(url).lower()))
    lures = sorted(words & LURE_WORDS)
    if lures:
        add(min(5 * len(lures), 15), 'Account or payment wording', f"Contains: {', '.join(lures)}.")
    if parts.scheme.lower() == 'http':
        add(10, 'Not encrypted (http)', 'The page would be loaded without HTTPS.')
    if parts.port and parts.port not in (80, 443):
        add(10, 'Unusual port', f'Uses port {parts.port}.')
    if len(url) > 120:
        add(5, 'Very long URL', f'{len(url)} characters long.')
    if re.search(r'(https?%3a|https?://).*(https?%3a|https?://)', url.lower()):
        add(10, 'Embedded second URL', 'Contains another URL, often used for redirects.')
    if url.count('%') >= 5:
        add(5, 'Heavy percent-encoding', 'Many encoded characters can hide the real text.')

    score = min(sum(weight for weight, _, _ in findings), 100)
    if score >= 60:
        verdict = 'High-risk URL indicators'
    elif score >= 25:
        verdict = 'Suspicious URL'
    else:
        verdict = 'No known phishing indicators'

    if verdict == 'No known phishing indicators':
        recommendations = ['Still check that the address is exactly the one you expect before entering any password.']
    else:
        recommendations = [
            'Do not enter passwords, one-time codes or payment details on this page.',
            'Open the service by typing its official address yourself instead of using this link.',
            'If you already entered a password, change it from a trusted device and enable multi-factor authentication.',
            'Report the message that contained the link to your IT or security team.',
        ]

    return {
        'url': url,
        'host': host,
        'registered_domain': registered,
        'score': score,
        'verdict': verdict,
        'evidence': [{'indicator': name, 'detail': detail, 'weight': weight}
                     for weight, name, detail in sorted(findings, reverse=True)],
        'recommendations': recommendations,
        'limitations': (
            'Checked locally against structural and wording indicators only. The link was not opened and '
            'was not compared with a phishing feed or domain-reputation service, so a URL with no indicators '
            'is not proven safe.'
        ),
    }
