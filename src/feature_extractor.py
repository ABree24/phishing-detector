import re
import tldextract
from urllib.parse import urlparse

def extract_features(url):
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.domain
    hostname = parsed.hostname or ''

    features = {
        'url_length': len(url),
        'hostname_length': len(hostname),
        'num_dots': url.count('.'),
        'num_hyphens': url.count('-'),
        'num_subdomains': len(ext.subdomain.split('.')) if ext.subdomain else 0,
        'has_ip': 1 if re.match(r'\d+\.\d+\.\d+\.\d+', hostname) else 0,
        'has_at_symbol': 1 if '@' in url else 0,
        'has_double_slash': 1 if '//' in parsed.path else 0,
        'is_https': 1 if parsed.scheme == 'https' else 0,
        'num_digits_domain': sum(c.isdigit() for c in domain),
        'suspicious_words': sum(
            1 for w in ['login', 'verify', 'account', 'secure', 'update', 'confirm', 'bank']
            if w in url.lower()
        ),
        'domain_length': len(domain),
    }

    return features