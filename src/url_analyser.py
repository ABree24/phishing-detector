import re
import ssl
import socket
import requests
import tldextract
import whois
from urllib.parse import urlparse
from datetime import datetime

# Known URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'bl.ink', 'tiny.cc'
]

def check_ssl(hostname):
    """Check if site has a valid trusted SSL certificate."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return 1   # trusted
        return 0               # untrusted
    except ssl.SSLCertVerificationError:
        return 0               # untrusted
    except Exception:
        return -1              # no HTTPS at all

def check_domain_age(domain):
    """Check how old the domain is via WHOIS."""
    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if creation:
            age_days = (datetime.now() - creation).days
            if age_days > 365:
                return 1       # old domain - safe
            else:
                return -1      # young domain - suspicious
    except Exception:
        pass
    return -1                  # can't verify - treat as suspicious

def check_redirects(url):
    """Count how many redirects the URL goes through."""
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        redirect_count = len(response.history)
        return 0 if redirect_count <= 2 else 1
    except Exception:
        return 0

def analyse_url(url):
    """
    Automatically extract all features from a URL.
    Returns a dict of feature values AND a dict of human-readable explanations.
    """
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    hostname = parsed.hostname or ''
    domain = ext.domain
    subdomain = ext.subdomain

    findings = {}    # human readable explanations
    features = {}    # model feature values

    # ── 1. IP Address in URL ──
    has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))
    features['Having_IP_Address'] = -1 if has_ip else 1
    findings['Having_IP_Address'] = (
        f"🔴 URL uses a raw IP address ({hostname}) instead of a domain name — strong phishing signal."
        if has_ip else
        f"🟢 URL uses a proper domain name ({hostname})."
    )

    # ── 2. URL Length ──
    url_len = len(url)
    if url_len < 54:
        features['URL_Length'] = 1
        findings['URL_Length'] = f"🟢 URL length is short ({url_len} chars) — normal."
    elif url_len <= 75:
        features['URL_Length'] = 0
        findings['URL_Length'] = f"🟡 URL length is medium ({url_len} chars) — slightly suspicious."
    else:
        features['URL_Length'] = -1
        findings['URL_Length'] = f"🔴 URL is very long ({url_len} chars) — phishing URLs are often padded to hide the real domain."

    # ── 3. URL Shortener ──
    is_shortened = any(s in hostname for s in URL_SHORTENERS)
    features['Shortining_Service'] = -1 if is_shortened else 1
    findings['Shortining_Service'] = (
        f"🔴 Uses a URL shortener ({hostname}) — hides the real destination."
        if is_shortened else
        f"🟢 Not using a URL shortener."
    )

    # ── 4. @ Symbol ──
    has_at = '@' in url
    features['Having_At_Symbol'] = -1 if has_at else 1
    findings['Having_At_Symbol'] = (
        "🔴 URL contains @ symbol — browsers ignore everything before @ and redirect to what follows."
        if has_at else
        "🟢 No @ symbol in URL."
    )

    # ── 5. Double Slash Redirect ──
    has_double_slash = '//' in parsed.path
    features['Double_Slash_Redirect'] = -1 if has_double_slash else 1
    findings['Double_Slash_Redirect'] = (
        "🔴 URL path contains // — used to redirect to a different domain."
        if has_double_slash else
        "🟢 No double slash redirect detected."
    )

    # ── 6. Hyphen in Domain ──
    has_hyphen = '-' in domain
    features['Prefix_Suffix'] = -1 if has_hyphen else 1
    findings['Prefix_Suffix'] = (
        f"🔴 Domain '{domain}' contains a hyphen — attackers use this to mimic real domains e.g. paypal-secure.com."
        if has_hyphen else
        f"🟢 Domain '{domain}' has no hyphen."
    )

    # ── 7. Subdomains ──
    # www is a standard subdomain and should not be flagged
    clean_subdomain = subdomain.replace('www', '').strip('.')

    if not subdomain or subdomain == 'www':
        features['Having_Sub_Domain'] = 1
        findings['Having_Sub_Domain'] = "🟢 No suspicious subdomains detected."
    elif '.' not in clean_subdomain and clean_subdomain == '':
        features['Having_Sub_Domain'] = 1
        findings['Having_Sub_Domain'] = "🟢 Only standard www subdomain detected — normal."
    elif '.' not in subdomain:
        features['Having_Sub_Domain'] = 0
        findings['Having_Sub_Domain'] = f"🟡 One subdomain detected ({subdomain}) — slightly suspicious."
    else:
        features['Having_Sub_Domain'] = -1
        findings['Having_Sub_Domain'] = f"🔴 Multiple subdomains detected ({subdomain}) — often used to fake legitimacy e.g. login.verify.paypal.fakesite.com."

    # ── 8. SSL Certificate ──
    ssl_result = check_ssl(hostname) if hostname else -1
    features['SSLfinal_State'] = ssl_result
    if ssl_result == 1:
        findings['SSLfinal_State'] = "🟢 Valid trusted SSL certificate found."
    elif ssl_result == 0:
        findings['SSLfinal_State'] = "🟡 SSL certificate exists but is untrusted or self-signed."
    else:
        findings['SSLfinal_State'] = "🔴 No valid HTTPS — site has no SSL certificate or connection failed."

    # ── 9. Domain Registration Length ──
    full_domain = ext.registered_domain
    age_result = check_domain_age(full_domain) if full_domain else -1
    features['Domain_Reg_Length'] = age_result
    findings['Domain_Reg_Length'] = (
        "🟢 Domain has been registered for over a year — sign of legitimacy."
        if age_result == 1 else
        "🟡 Domain age could not be verified via WHOIS — this may be a network timeout rather than a red flag."
    )

    # Also update the feature value to neutral if unverified
    if age_result == -1:
        features['Domain_Reg_Length'] = 0

    # ── 10. Redirects ──
    redirect_result = check_redirects(url)
    features['Redirect'] = redirect_result
    findings['Redirect'] = (
        "🟢 Few or no redirects detected."
        if redirect_result == 0 else
        "🔴 Multiple redirects detected — used to obscure the final destination."
    )

    return features, findings