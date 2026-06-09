import re
import ssl
import socket
import requests
import tldextract
import whois
from urllib.parse import urlparse, urljoin
from datetime import datetime
from html.parser import HTMLParser

# Known URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'bl.ink', 'tiny.cc'
]

# Common suspicious keywords used in phishing URLs or page content
SUSPICIOUS_KEYWORDS = [
    'login', 'verify', 'secure', 'account', 'update',
    'confirm', 'bank', 'ebay', 'paypal', 'signin', 'security'
]


def normalize_url(url):
    url = url.strip()
    if not re.match(r'^(https?://)', url, re.I):
        url = 'http://' + url
    return url


def is_same_domain(url, base_domain):
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ''
        return tldextract.extract(hostname).registered_domain == base_domain
    except Exception:
        return False


class HTMLFeatureParser(HTMLParser):
    def __init__(self, base_url, base_domain):
        super().__init__(convert_charrefs=True)
        self.base_url = base_url
        self.base_domain = base_domain
        self.anchor_hrefs = []
        self.resource_urls = []
        self.favicon_urls = []
        self.form_actions = []
        self.has_iframe = False
        self.contains_onmouseover = False
        self.contains_contextmenu = False
        self.suspicious_js = False
        self.title = ''
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = {name.lower(): value for name, value in attrs if value}
        href = attrs.get('href', '').strip()
        src = attrs.get('src', '').strip()
        action = attrs.get('action', '').strip()
        rel = attrs.get('rel', '').lower() if attrs.get('rel') else ''

        if 'onmouseover' in attrs:
            self.contains_onmouseover = True
        if 'oncontextmenu' in attrs:
            self.contains_contextmenu = True

        if tag == 'title':
            self._in_title = True

        if tag == 'a' and href:
            self.anchor_hrefs.append(urljoin(self.base_url, href))

        if tag in ('img', 'script', 'iframe', 'embed', 'audio', 'video', 'source') and src:
            self.resource_urls.append(urljoin(self.base_url, src))

        if tag == 'link' and href:
            self.resource_urls.append(urljoin(self.base_url, href))
            if 'icon' in rel:
                self.favicon_urls.append(urljoin(self.base_url, href))

        if tag == 'form':
            if action:
                self.form_actions.append(urljoin(self.base_url, action))
            else:
                self.form_actions.append('')

        if tag == 'iframe':
            self.has_iframe = True

    def handle_endtag(self, tag):
        if tag == 'title':
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            self.title += data

        lowered = data.lower()
        if 'window.open' in lowered or 'alert(' in lowered or 'prompt(' in lowered:
            self.suspicious_js = True

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)

    def handle_comment(self, data):
        lowered = data.lower()
        if 'window.open' in lowered or 'alert(' in lowered or 'prompt(' in lowered:
            self.suspicious_js = True

    def handle_decl(self, decl):
        pass

    def handle_pi(self, data):
        pass

    def unknown_decl(self, data):
        pass


def safe_fetch_html(url):
    try:
        response = requests.get(
            url,
            timeout=8,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True
        )
        if response.status_code == 200:
            return response.text
    except Exception:
        pass
    return ''


def get_page_features(html, base_url, base_domain):
    parser = HTMLFeatureParser(base_url, base_domain)
    parser.feed(html)
    parser.close()

    def external_ratio(urls):
        total = 0
        external = 0
        for link in urls:
            if not link:
                continue
            parsed = urlparse(link)
            if parsed.scheme not in ('http', 'https'):
                continue
            total += 1
            if not is_same_domain(link, base_domain):
                external += 1
        return (external / total) if total else None

    anchor_ratio = external_ratio(parser.anchor_hrefs)
    resource_ratio = external_ratio(parser.resource_urls)

    results = {
        'URL_of_Anchor': 0,
        'Request_URL': 0,
        'Links_in_Tags': 0,
        'Favicon': 0,
        'SFH': 1,
        'Submitting_to_Email': 1,
        'Abnormal_URL': 0,
        'On_Mouseover': 1,
        'RightClick': 1,
        'PopUpWindow': 1,
        'Iframe': 1,
        'Page_Title': parser.title.strip(),
    }

    if anchor_ratio is None:
        results['URL_of_Anchor'] = 0
    elif anchor_ratio <= 0.3:
        results['URL_of_Anchor'] = 1
    elif anchor_ratio <= 0.7:
        results['URL_of_Anchor'] = 0
    else:
        results['URL_of_Anchor'] = -1

    if resource_ratio is None:
        results['Request_URL'] = 0
        results['Links_in_Tags'] = 0
    elif resource_ratio <= 0.3:
        results['Request_URL'] = 1
        results['Links_in_Tags'] = 1
    elif resource_ratio <= 0.7:
        results['Request_URL'] = 0
        results['Links_in_Tags'] = 0
    else:
        results['Request_URL'] = -1
        results['Links_in_Tags'] = -1

    if parser.favicon_urls:
        favicon_url = parser.favicon_urls[0]
        results['Favicon'] = -1 if not is_same_domain(favicon_url, base_domain) else 1
    else:
        results['Favicon'] = 0

    if parser.form_actions:
        if any(action.startswith('mailto:') for action in parser.form_actions):
            results['Submitting_to_Email'] = -1
        if any(action == '' or action == '#' or action.lower().startswith('javascript:')
               for action in parser.form_actions):
            results['SFH'] = 0
        elif any(not is_same_domain(action, base_domain) for action in parser.form_actions):
            results['SFH'] = -1
        else:
            results['SFH'] = 1
    else:
        results['SFH'] = 1
        results['Submitting_to_Email'] = 1

    if parser.title:
        title_lower = parser.title.strip().lower()
        if base_domain and base_domain not in title_lower:
            results['Abnormal_URL'] = -1
        else:
            results['Abnormal_URL'] = 1
    else:
        results['Abnormal_URL'] = 0

    results['On_Mouseover'] = -1 if parser.contains_onmouseover else 1
    results['RightClick'] = -1 if parser.contains_contextmenu else 1
    results['PopUpWindow'] = -1 if parser.suspicious_js else 1
    results['Iframe'] = -1 if parser.has_iframe else 1

    return results


def check_ssl(hostname):
    """Check if site has a valid trusted SSL certificate."""
    if not hostname:
        return -1

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    return 1
        return 0
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        return -1


def get_domain_age_days(domain):
    try:
        record = whois.whois(domain)
        creation = record.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        if isinstance(creation, datetime):
            return (datetime.now() - creation).days
    except Exception:
        pass
    return None


def check_redirects(url):
    """Count how many redirects the URL goes through."""
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=8,
            headers={'User-Agent': 'Mozilla/5.0'}
        )
        redirect_count = len(response.history)
        return 0 if redirect_count <= 1 else 1
    except Exception:
        return 0


def analyse_url(url):
    """
    Automatically extract all model features from a URL.
    Returns a dict of feature values and a dict of human-readable explanations.
    """
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    if not hostname:
        raise ValueError('Unable to parse hostname from URL.')

    ext = tldextract.extract(hostname)
    domain = ext.domain or ''
    registered_domain = ext.registered_domain or hostname
    scheme = parsed.scheme.lower()
    base_url = f"{scheme}://{hostname}"

    findings = {}
    features = {}

    # 1. IP Address in URL
    has_ip = bool(re.match(r'\d+\.\d+\.\d+\.\d+', hostname))
    features['Having_IP_Address'] = -1 if has_ip else 1
    findings['Having_IP_Address'] = (
        f"🔴 URL uses a raw IP address ({hostname}) instead of a domain name — strong phishing signal."
        if has_ip else
        f"🟢 URL uses a proper domain name ({hostname})."
    )

    # 2. URL Length
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

    # 3. URL Shortener
    is_shortened = any(short in hostname.lower() for short in URL_SHORTENERS)
    features['Shortining_Service'] = -1 if is_shortened else 1
    findings['Shortining_Service'] = (
        f"🔴 Uses a URL shortener ({hostname}) — hides the real destination."
        if is_shortened else
        "🟢 Not using a URL shortener."
    )

    # 4. @ Symbol
    has_at = '@' in url
    features['Having_At_Symbol'] = -1 if has_at else 1
    findings['Having_At_Symbol'] = (
        "🔴 URL contains @ symbol — browsers ignore everything before @ and redirect to what follows."
        if has_at else
        "🟢 No @ symbol in URL."
    )

    # 5. Double Slash Redirect
    has_double_slash = '//' in parsed.path
    features['Double_Slash_Redirect'] = -1 if has_double_slash else 1
    findings['Double_Slash_Redirect'] = (
        "🔴 URL path contains // — used to redirect to a different domain."
        if has_double_slash else
        "🟢 No double slash redirect detected."
    )

    # 6. Hyphen in Domain
    has_hyphen = '-' in domain
    features['Prefix_Suffix'] = -1 if has_hyphen else 1
    findings['Prefix_Suffix'] = (
        f"🔴 Domain '{domain}' contains a hyphen — attackers use this to mimic real domains e.g. paypal-secure.com."
        if has_hyphen else
        f"🟢 Domain '{domain}' has no hyphen."
    )

    # 7. Subdomains
    subdomain_parts = [part for part in (ext.subdomain or '').split('.') if part and part != 'www']
    if not subdomain_parts:
        features['Having_Sub_Domain'] = 1
        findings['Having_Sub_Domain'] = "🟢 No suspicious subdomains detected."
    elif len(subdomain_parts) == 1:
        features['Having_Sub_Domain'] = 0
        findings['Having_Sub_Domain'] = f"🟡 One subdomain detected ({'.'.join(subdomain_parts)}) — slightly suspicious."
    else:
        features['Having_Sub_Domain'] = -1
        findings['Having_Sub_Domain'] = f"🔴 Multiple subdomains detected ({'.'.join(subdomain_parts)}) — often used to fake legitimacy."

    # 8. SSL Certificate
    ssl_result = check_ssl(hostname) if scheme == 'https' else -1
    features['SSLfinal_State'] = ssl_result
    if ssl_result == 1:
        findings['SSLfinal_State'] = "🟢 Valid trusted SSL certificate found."
    elif ssl_result == 0:
        findings['SSLfinal_State'] = "🟡 SSL certificate exists but is untrusted or self-signed."
    else:
        findings['SSLfinal_State'] = "🔴 No valid HTTPS — site has no SSL certificate or connection failed."

    # 9. Domain Registration Length
    age_days = get_domain_age_days(registered_domain) if registered_domain else None
    if age_days is None:
        features['Domain_Reg_Length'] = 0
        findings['Domain_Reg_Length'] = "🟡 Domain age could not be verified via WHOIS — may be due to privacy or network issues."
    else:
        features['Domain_Reg_Length'] = 1 if age_days > 365 else -1
        findings['Domain_Reg_Length'] = (
            "🟢 Domain has been registered for over a year — sign of legitimacy."
            if age_days > 365 else
            "🔴 Domain registration is recent — phishing domains are often newly created."
        )

    # 10. Redirects
    redirect_result = check_redirects(url)
    features['Redirect'] = redirect_result
    findings['Redirect'] = (
        "🟢 Few or no redirects detected."
        if redirect_result == 0 else
        "🔴 Multiple redirects detected — used to obscure the final destination."
    )

    # Additional page-based features
    html = safe_fetch_html(url)
    page_features = get_page_features(html, url, registered_domain)
    features.update({
        'Favicon': page_features['Favicon'],
        'Port': -1 if parsed.port and parsed.port not in (80, 443) else 1,
        'HTTPS_Token': -1 if 'https' in (parsed.hostname or '').lower() else 1,
        'Request_URL': page_features['Request_URL'],
        'URL_of_Anchor': page_features['URL_of_Anchor'],
        'Links_in_Tags': page_features['Links_in_Tags'],
        'SFH': page_features['SFH'],
        'Submitting_to_Email': page_features['Submitting_to_Email'],
        'Abnormal_URL': page_features['Abnormal_URL'],
        'On_Mouseover': page_features['On_Mouseover'],
        'RightClick': page_features['RightClick'],
        'PopUpWindow': page_features['PopUpWindow'],
        'Iframe': page_features['Iframe'],
    })

    findings['Favicon'] = (
        "🟢 Favicon is hosted on the same domain."
        if features['Favicon'] == 1 else
        "🟡 No favicon was detected." if features['Favicon'] == 0 else
        "🔴 Favicon comes from a different domain — may be trying to appear legitimate."
    )
    findings['Port'] = (
        f"🟡 URL uses non-standard port {parsed.port}." if parsed.port and parsed.port not in (80, 443)
        else "🟢 URL uses a standard port."
    )
    findings['HTTPS_Token'] = (
        "🔴 The hostname contains 'https' in the domain, which is often a phishing trick."
        if features['HTTPS_Token'] == -1 else
        "🟢 No misleading HTTPS token found in the hostname."
    )
    findings['Request_URL'] = (
        "🟢 Most page resources load from the same domain."
        if features['Request_URL'] == 1 else
        "🟡 Some resources load from external domains."
        if features['Request_URL'] == 0 else
        "🔴 Most resources load from other domains — suspicious."
    )
    findings['URL_of_Anchor'] = (
        "🟢 Most links point to the same domain."
        if features['URL_of_Anchor'] == 1 else
        "🟡 Many links are external."
        if features['URL_of_Anchor'] == 0 else
        "🔴 Most links point to external domains — common phishing behavior."
    )
    findings['Links_in_Tags'] = (
        "🟢 Tag resources load from the same origin."
        if features['Links_in_Tags'] == 1 else
        "🟡 Tag resources are mixed internal and external."
        if features['Links_in_Tags'] == 0 else
        "🔴 Tag resources come largely from external domains."
    )
    findings['SFH'] = (
        "🟢 Form submission target is on the same domain."
        if features['SFH'] == 1 else
        "🟡 Form handler is blank or javascript-based."
        if features['SFH'] == 0 else
        "🔴 Form submits to an external domain."
    )
    findings['Submitting_to_Email'] = (
        "🟢 Form submission is normal."
        if features['Submitting_to_Email'] == 1 else
        "🔴 Form submission uses email (mailto:) — suspicious."
    )
    findings['Abnormal_URL'] = (
        "🟢 Page title matches the domain."
        if features['Abnormal_URL'] == 1 else
        "🟡 Page title is unavailable."
        if features['Abnormal_URL'] == 0 else
        "🔴 Page title does not mention the domain — may be an abnormal URL."
    )
    findings['On_Mouseover'] = (
        "🔴 The page uses onmouseover scripts — a common phishing tactic."
        if features['On_Mouseover'] == -1 else
        "🟢 No dangerous onmouseover behavior detected."
    )
    findings['RightClick'] = (
        "🔴 Right-click is disabled or blocked."
        if features['RightClick'] == -1 else
        "🟢 Right-click appears enabled."
    )
    findings['PopUpWindow'] = (
        "🔴 The page uses pop-up or alert scripting."
        if features['PopUpWindow'] == -1 else
        "🟢 No pop-up scripting detected."
    )
    findings['Iframe'] = (
        "🔴 The page contains iframes."
        if features['Iframe'] == -1 else
        "🟢 No iframes detected."
    )

    # 11-30 fallback values for infos not automatically extracted
    features.setdefault('Age_of_Domain', 1 if age_days and age_days > 180 else 0)
    features.setdefault('DNS_Record', 1 if check_dns_record(hostname) else -1)
    features.setdefault('Web_Traffic', 1)
    features.setdefault('Page_Rank', 1)
    features.setdefault('Google_Index', 1)
    features.setdefault('Links_Pointing_to_Page', 1)
    if any(keyword in url.lower() for keyword in SUSPICIOUS_KEYWORDS) or any(
            keyword in page_features['Page_Title'].lower() for keyword in SUSPICIOUS_KEYWORDS):
        features.setdefault('Statistical_Report', -1)
    else:
        features.setdefault('Statistical_Report', 1)

    return features, findings


def check_dns_record(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except Exception:
        return False
