import re
import ssl
import socket
import requests
import tldextract
import whois
from urllib.parse import urlparse, urljoin
from datetime import datetime
from html.parser import HTMLParser
import threading
import logging

logger = logging.getLogger(__name__)

# Known URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly',
    'short.link', 'buff.ly', 'rebrand.ly', 'bl.ink', 'tiny.cc'
]

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
        attrs_dict = {name.lower(): (value or '') for name, value in attrs}
        href = attrs_dict.get('href', '').strip()
        src = attrs_dict.get('src', '').strip()
        action = attrs_dict.get('action', '').strip()
        rel = attrs_dict.get('rel', '').lower()

        if 'onmouseover' in attrs_dict:
            self.contains_onmouseover = True
        if 'oncontextmenu' in attrs_dict:
            self.contains_contextmenu = True

        if tag == 'title':
            self._in_title = True

        if tag == 'a' and href and not href.startswith('#'):
            try:
                self.anchor_hrefs.append(urljoin(self.base_url, href))
            except Exception:
                pass

        if tag in ('img', 'script', 'embed', 'audio', 'video', 'source') and src:
            try:
                self.resource_urls.append(urljoin(self.base_url, src))
            except Exception:
                pass

        if tag == 'link' and href:
            try:
                full_url = urljoin(self.base_url, href)
                self.resource_urls.append(full_url)
                if 'icon' in rel:
                    self.favicon_urls.append(full_url)
            except Exception:
                pass

        if tag == 'form':
            if action:
                try:
                    self.form_actions.append(urljoin(self.base_url, action))
                except Exception:
                    self.form_actions.append(action)
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


def safe_fetch_html(url):
    """Fetch HTML from URL with error logging.
    
    Returns:
        HTML content (truncated to 100KB) or empty string on failure
    """
    try:
        response = requests.get(
            url,
            timeout=5,
            headers={'User-Agent': 'Mozilla/5.0'},
            allow_redirects=True,
            verify=True
        )
        if response.status_code == 200:
            return response.text[:100000]
        else:
            logger.warning(f"Failed to fetch {url}: HTTP {response.status_code}")
    except requests.exceptions.Timeout:
        logger.warning(f"Timeout fetching HTML from {url}")
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request error fetching {url}: {str(e)}")
    except Exception as e:
        logger.warning(f"Unexpected error fetching HTML from {url}: {str(e)}")
    return ''


def get_page_features(html, base_url, base_domain):
    """Extract features from HTML content with proper error handling.
    
    Args:
        html: HTML content string
        base_url: Base URL for resolving relative URLs
        base_domain: Registered domain for same-domain checks
        
    Returns:
        Dictionary of extracted features
    """
    parser = HTMLFeatureParser(base_url, base_domain)
    try:
        parser.feed(html)
        parser.close()
    except Exception as e:
        logger.warning(f"Error parsing HTML from {base_url}: {str(e)}")
        # Parser state may be incomplete, but continue with partial results

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

    # Anchor links
    if anchor_ratio is None:
        results['URL_of_Anchor'] = 0
    elif anchor_ratio <= 0.3:
        results['URL_of_Anchor'] = 1
    elif anchor_ratio <= 0.7:
        results['URL_of_Anchor'] = 0
    else:
        results['URL_of_Anchor'] = -1

    # External resources
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

    # Favicon
    if parser.favicon_urls:
        favicon_url = parser.favicon_urls[0]
        results['Favicon'] = -1 if not is_same_domain(favicon_url, base_domain) else 1
    else:
        results['Favicon'] = 0

    # Form actions
    if parser.form_actions:
        if any(a.startswith('mailto:') for a in parser.form_actions):
            results['Submitting_to_Email'] = -1
        if any(a == '' or a == '#' or a.lower().startswith('javascript:')
               for a in parser.form_actions):
            results['SFH'] = 0
        elif any(not is_same_domain(a, base_domain) for a in parser.form_actions if a):
            results['SFH'] = -1
        else:
            results['SFH'] = 1
    else:
        results['SFH'] = 1
        results['Submitting_to_Email'] = 1

    # Page title
    if parser.title:
        title_lower = parser.title.strip().lower()
        results['Abnormal_URL'] = 1 if base_domain and base_domain.lower() in title_lower else -1
    else:
        results['Abnormal_URL'] = 0

    results['On_Mouseover'] = -1 if parser.contains_onmouseover else 1
    results['RightClick'] = -1 if parser.contains_contextmenu else 1
    results['PopUpWindow'] = -1 if parser.suspicious_js else 1
    results['Iframe'] = -1 if parser.has_iframe else 1

    return results


def check_ssl(hostname):
    if not hostname:
        return -1
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                return 1 if cert else 0
    except ssl.SSLCertVerificationError:
        return 0
    except Exception:
        return -1


def get_domain_age_days(domain: str):
    """Get domain registration age in days.
    
    Args:
        domain: Domain name to check
        
    Returns:
        Age in days, or None if lookup fails
    """
    result = [None]
    error_info = [None]

    def fetch_whois():
        try:
            record = whois.whois(domain)
            creation = record.creation_date
            if isinstance(creation, list):
                creation = creation[0]
            if isinstance(creation, datetime):
                result[0] = (datetime.now() - creation).days
                logger.info(f"Domain {domain} age: {result[0]} days")
            else:
                logger.warning(f"Unexpected creation_date type for {domain}: {type(creation)}")
        except socket.timeout:
            logger.warning(f"WHOIS timeout for {domain}")
            error_info[0] = "timeout"
        except socket.gaierror as e:
            logger.warning(f"DNS error during WHOIS lookup for {domain}: {str(e)}")
            error_info[0] = "dns_error"
        except Exception as e:
            logger.warning(f"WHOIS lookup failed for {domain}: {str(e)}")
            error_info[0] = str(e)

    thread = threading.Thread(target=fetch_whois, daemon=True)
    thread.start()
    thread.join(timeout=4)
    
    if error_info[0] and result[0] is None:
        logger.info(f"Failed to get domain age for {domain}: {error_info[0]}")
    
    return result[0]


def check_redirects(url: str) -> int:
    """Check if URL has suspicious redirects.
    
    Args:
        url: URL to check
        
    Returns:
        0 if normal/few redirects, 1 if many redirects, 0 on error
    """
    try:
        response = requests.get(
            url,
            allow_redirects=True,
            timeout=5,
            headers={'User-Agent': 'Mozilla/5.0'},
            verify=True
        )
        redirect_count = len(response.history)
        logger.info(f"URL {url[:50]} has {redirect_count} redirects")
        return 0 if redirect_count <= 1 else 1
    except requests.exceptions.Timeout:
        logger.warning(f"Redirect check timeout for {url}")
        return 0
    except requests.exceptions.RequestException as e:
        logger.warning(f"Request error checking redirects for {url}: {str(e)}")
        return 0
    except Exception as e:
        logger.warning(f"Unexpected error checking redirects for {url}: {str(e)}")
        return 0


def check_dns_record(hostname: str) -> bool:
    """Check if DNS record exists for hostname.
    
    Args:
        hostname: Hostname to check
        
    Returns:
        True if DNS record found, False otherwise
    """
    try:
        socket.gethostbyname(hostname)
        logger.info(f"DNS record found for {hostname}")
        return True
    except socket.gaierror:
        logger.warning(f"DNS record not found for {hostname}")
        return False
    except Exception as e:
        logger.warning(f"Error checking DNS for {hostname}: {str(e)}")
        return False


def analyse_url(url):
    """
    Automatically extract all model features from a URL with timeout protection.
    Returns (features dict, findings dict).
    """
    result = [None, None]
    error = [None]

    def do_analysis():
        try:
            result[0], result[1] = _analyse_url_impl(url)
        except Exception as e:
            error[0] = str(e)

    thread = threading.Thread(target=do_analysis, daemon=True)
    thread.start()
    thread.join(timeout=15)

    if error[0]:
        raise ValueError(error[0])
    if result[0] is None:
        raise TimeoutError("URL analysis took too long — try again or check the URL.")

    return result[0], result[1]


def _analyse_url_impl(url):
    url = normalize_url(url)
    parsed = urlparse(url)
    hostname = parsed.hostname or ''
    if not hostname:
        raise ValueError('Unable to parse hostname from URL.')

    ext = tldextract.extract(hostname)
    domain = ext.domain or ''
    registered_domain = ext.registered_domain or hostname
    scheme = parsed.scheme.lower()

    findings = {}
    features = {}

    # ── 1. IP Address ──
    has_ip = bool(re.match(r'^\d+\.\d+\.\d+\.\d+$', hostname))
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
    is_shortened = any(s in hostname.lower() for s in URL_SHORTENERS)
    features['Shortining_Service'] = -1 if is_shortened else 1
    findings['Shortining_Service'] = (
        f"🔴 Uses a URL shortener ({hostname}) — hides the real destination."
        if is_shortened else
        "🟢 Not using a URL shortener."
    )

    # ── 4. @ Symbol ──
    has_at = '@' in url
    features['Having_At_Symbol'] = -1 if has_at else 1
    findings['Having_At_Symbol'] = (
        "🔴 URL contains @ symbol — browsers ignore everything before @ and redirect to what follows."
        if has_at else
        "🟢 No @ symbol in URL."
    )

    # ── 5. Double Slash ──
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
    subdomain_parts = [p for p in (ext.subdomain or '').split('.') if p and p != 'www']
    if not subdomain_parts:
        features['Having_Sub_Domain'] = 1
        findings['Having_Sub_Domain'] = "🟢 No suspicious subdomains detected."
    elif len(subdomain_parts) == 1:
        features['Having_Sub_Domain'] = 0
        findings['Having_Sub_Domain'] = f"🟡 One subdomain detected ({'.'.join(subdomain_parts)}) — slightly suspicious."
    else:
        features['Having_Sub_Domain'] = -1
        findings['Having_Sub_Domain'] = f"🔴 Multiple subdomains detected ({'.'.join(subdomain_parts)}) — often used to fake legitimacy."

    # ── 8. SSL Certificate ──
    ssl_result = check_ssl(hostname) if scheme == 'https' else -1
    features['SSLfinal_State'] = ssl_result
    findings['SSLfinal_State'] = (
        "🟢 Valid trusted SSL certificate found." if ssl_result == 1 else
        "🟡 SSL certificate exists but is untrusted or self-signed." if ssl_result == 0 else
        "🔴 No valid HTTPS — site has no SSL certificate or connection failed."
    )

    # ── 9. Domain Age ──
    age_days = get_domain_age_days(registered_domain) if registered_domain else None
    if age_days is None:
        features['Domain_Reg_Length'] = 0
        findings['Domain_Reg_Length'] = "🟡 Domain age could not be verified via WHOIS — may be due to privacy settings or network issues."
    elif age_days > 365:
        features['Domain_Reg_Length'] = 1
        findings['Domain_Reg_Length'] = f"🟢 Domain has been registered for over a year ({age_days} days) — sign of legitimacy."
    else:
        features['Domain_Reg_Length'] = -1
        findings['Domain_Reg_Length'] = f"🔴 Domain registration is recent ({age_days} days) — phishing domains are often newly created."

    # ── 10. Redirects ──
    redirect_result = check_redirects(url)
    features['Redirect'] = redirect_result
    findings['Redirect'] = (
        "🟢 Few or no redirects detected." if redirect_result == 0 else
        "🔴 Multiple redirects detected — used to obscure the final destination."
    )

    # ── 11-23. Page-based features ──
    html = safe_fetch_html(url)
    page = get_page_features(html, url, registered_domain)

    # Favicon
    features['Favicon'] = page['Favicon']
    findings['Favicon'] = (
        "🟢 Favicon is hosted on the same domain." if page['Favicon'] == 1 else
        "🟡 No favicon was detected." if page['Favicon'] == 0 else
        "🔴 Favicon comes from a different domain — may be trying to appear legitimate."
    )

    # Port
    features['Port'] = -1 if (parsed.port and parsed.port not in (80, 443)) else 1
    findings['Port'] = (
        f"🟡 URL uses non-standard port {parsed.port} — suspicious."
        if features['Port'] == -1 else
        "🟢 URL uses a standard port."
    )

    # HTTPS token in domain name
    features['HTTPS_Token'] = -1 if 'https' in hostname.lower() else 1
    findings['HTTPS_Token'] = (
        "🔴 The hostname contains 'https' in the domain name — a common phishing trick."
        if features['HTTPS_Token'] == -1 else
        "🟢 No misleading HTTPS token found in the hostname."
    )

    # Request URL
    features['Request_URL'] = page['Request_URL']
    findings['Request_URL'] = (
        "🟢 Most page resources load from the same domain." if page['Request_URL'] == 1 else
        "🟡 Some resources load from external domains." if page['Request_URL'] == 0 else
        "🔴 Most resources load from other domains — suspicious."
    )

    # Anchor links
    features['URL_of_Anchor'] = page['URL_of_Anchor']
    findings['URL_of_Anchor'] = (
        "🟢 Most links point to the same domain." if page['URL_of_Anchor'] == 1 else
        "🟡 Many links are external." if page['URL_of_Anchor'] == 0 else
        "🔴 Most links point to external domains — common phishing behavior."
    )

    # Links in tags
    features['Links_in_Tags'] = page['Links_in_Tags']
    findings['Links_in_Tags'] = (
        "🟢 Tag resources load from the same origin." if page['Links_in_Tags'] == 1 else
        "🟡 Tag resources are mixed internal and external." if page['Links_in_Tags'] == 0 else
        "🔴 Tag resources come largely from external domains."
    )

    # SFH
    features['SFH'] = page['SFH']
    findings['SFH'] = (
        "🟢 Form submission target is on the same domain." if page['SFH'] == 1 else
        "🟡 Form handler is blank or javascript-based." if page['SFH'] == 0 else
        "🔴 Form submits data to an external domain — strong phishing signal."
    )

    # Submitting to email
    features['Submitting_to_Email'] = page['Submitting_to_Email']
    findings['Submitting_to_Email'] = (
        "🟢 Form submission is normal." if page['Submitting_to_Email'] == 1 else
        "🔴 Form uses mailto: submission — suspicious."
    )

    # Abnormal URL
    features['Abnormal_URL'] = page['Abnormal_URL']
    findings['Abnormal_URL'] = (
        "🟢 Page title matches the domain." if page['Abnormal_URL'] == 1 else
        "🟡 Page title is unavailable." if page['Abnormal_URL'] == 0 else
        "🔴 Page title does not mention the domain — may be an abnormal URL."
    )

    # On mouseover
    features['On_Mouseover'] = page['On_Mouseover']
    findings['On_Mouseover'] = (
        "🔴 The page uses onmouseover scripts — a common phishing tactic."
        if page['On_Mouseover'] == -1 else
        "🟢 No dangerous onmouseover behavior detected."
    )

    # Right click
    features['RightClick'] = page['RightClick']
    findings['RightClick'] = (
        "🔴 Right-click is disabled — phishing sites do this to prevent inspection."
        if page['RightClick'] == -1 else
        "🟢 Right-click appears enabled."
    )

    # Popup
    features['PopUpWindow'] = page['PopUpWindow']
    findings['PopUpWindow'] = (
        "🔴 The page uses pop-up or alert scripting — suspicious."
        if page['PopUpWindow'] == -1 else
        "🟢 No pop-up scripting detected."
    )

    # iFrame
    features['Iframe'] = page['Iframe']
    findings['Iframe'] = (
        "🔴 The page contains iframes — can be used to embed malicious content."
        if page['Iframe'] == -1 else
        "🟢 No iframes detected."
    )

    # ── 24-30. Remaining features ──
    features['Age_of_Domain'] = (
        1 if age_days and age_days > 180 else
        -1 if age_days is not None else 0
    )

    features['DNS_Record'] = 1 if check_dns_record(hostname) else -1

    # Web traffic, page rank, google index, links — not automatically detectable
    # Use neutral value (0) instead of optimistic value (1) to avoid biasing toward "legitimate"
    # A better approach would be to implement actual lookups using APIs or remove these features
    features['Web_Traffic'] = 0
    features['Page_Rank'] = 0
    features['Google_Index'] = 0
    features['Links_Pointing_to_Page'] = 0
    logger.debug("External features (Web_Traffic, Page_Rank, etc.) set to neutral (0) - API integration recommended")

    # Statistical report — flag if URL or page title contains suspicious keywords
    page_title = page.get('Page_Title', '').lower()
    has_suspicious = (
        any(kw in url.lower() for kw in SUSPICIOUS_KEYWORDS) or
        any(kw in page_title for kw in SUSPICIOUS_KEYWORDS)
    )
    features['Statistical_Report'] = -1 if has_suspicious else 1

    return features, findings