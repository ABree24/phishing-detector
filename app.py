import streamlit as st
import joblib
import pandas as pd
import plotly.graph_objects as go
import requests
import time
import os
from dotenv import load_dotenv

load_dotenv()
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# ── Page config ──
st.set_page_config(
    page_title="Phishing Detector",
    page_icon="assets/phishing.png",
    layout="centered"
)

# ── Constants ──
CORRECT_ORDER = [
    'Having_IP_Address', 'URL_Length', 'Shortining_Service',
    'Having_At_Symbol', 'Double_Slash_Redirect', 'Prefix_Suffix',
    'Having_Sub_Domain', 'SSLfinal_State', 'Domain_Reg_Length',
    'Favicon', 'Port', 'HTTPS_Token', 'Request_URL',
    'URL_of_Anchor', 'Links_in_Tags', 'SFH',
    'Submitting_to_Email', 'Abnormal_URL', 'Redirect',
    'On_Mouseover', 'RightClick', 'PopUpWindow', 'Iframe',
    'Age_of_Domain', 'DNS_Record', 'Web_Traffic',
    'Page_Rank', 'Google_Index', 'Links_Pointing_to_Page',
    'Statistical_Report'
]

ALL_FEATURE_DEFAULTS = {
    'Having_IP_Address':      1,
    'URL_Length':             1,
    'Shortining_Service':     1,
    'Having_At_Symbol':       1,
    'Double_Slash_Redirect':  1,
    'Prefix_Suffix':          1,
    'Having_Sub_Domain':      1,
    'SSLfinal_State':         1,
    'Domain_Reg_Length':      1,
    'Favicon':                1,
    'Port':                   1,
    'HTTPS_Token':            1,
    'Request_URL':            1,
    'URL_of_Anchor':          1,
    'Links_in_Tags':          1,
    'SFH':                    1,
    'Submitting_to_Email':    1,
    'Abnormal_URL':           1,
    'Redirect':               0,
    'On_Mouseover':           1,
    'RightClick':             1,
    'PopUpWindow':            1,
    'Iframe':                 1,
    'Age_of_Domain':          1,
    'DNS_Record':             1,
    'Web_Traffic':            1,
    'Page_Rank':              1,
    'Google_Index':           1,
    'Links_Pointing_to_Page': 1,
    'Statistical_Report':     1,
}

TOP_FEATURES = {
    'SSLfinal_State': {
        'label': '1. Does the site have a valid SSL certificate?',
        'help': 'Check if the browser shows a padlock. Trusted = green padlock from a known authority.',
        'options': {'Trusted — green padlock (1)': 1, 'Untrusted / self-signed (0)': 0, 'No HTTPS at all (-1)': -1}
    },
    'URL_of_Anchor': {
        'label': '2. Do links on the page point to external or mismatched domains?',
        'help': 'On a real site, most links point back to the same domain. Phishing pages load content from random external URLs.',
        'options': {'Mostly internal links (1)': 1, 'Mix of internal and external (0)': 0, 'Mostly external links (-1)': -1}
    },
    'Prefix_Suffix': {
        'label': '3. Does the domain name contain a hyphen?',
        'help': 'Attackers use hyphens to mimic real domains e.g. paypal-secure.com instead of paypal.com.',
        'options': {'No hyphen (1)': 1, 'Has hyphen (-1)': -1}
    },
    'Web_Traffic': {
        'label': '4. How well known is this website?',
        'help': 'Legitimate sites usually have measurable traffic. Brand new or obscure sites with no traffic history are suspicious.',
        'options': {'Well known site (1)': 1, 'Low traffic (0)': 0, 'No traffic data (-1)': -1}
    },
    'Having_Sub_Domain': {
        'label': '5. How many subdomains does the URL have?',
        'help': 'Phishing URLs often use multiple subdomains like login.verify.paypal.fakesite.com to look legitimate.',
        'options': {'None (1)': 1, 'One subdomain (0)': 0, 'Multiple subdomains (-1)': -1}
    },
    'Links_in_Tags': {
        'label': '6. Do the meta and script tags load from external domains?',
        'help': 'Legitimate sites load their own scripts. Phishing pages pull resources from unrelated external servers.',
        'options': {'Mostly internal (1)': 1, 'Mixed (0)': 0, 'Mostly external (-1)': -1}
    },
    'Request_URL': {
        'label': '7. Does the page load images/videos from external domains?',
        'help': 'A phishing page is often just a screenshot of a real site — images are hotlinked from the real domain.',
        'options': {'Loads from same domain (1)': 1, 'Loads mostly from external (-1)': -1}
    },
    'SFH': {
        'label': '8. Where does the login or contact form submit data?',
        'help': 'SFH = Server Form Handler. Legitimate forms submit to the same domain. Phishing forms send your data elsewhere.',
        'options': {'Submits to same domain (1)': 1, 'Blank or empty action (0)': 0, 'Submits to external domain (-1)': -1}
    },
    'Domain_Reg_Length': {
        'label': '9. How long is the domain registered for?',
        'help': 'Legitimate businesses register domains for years. Phishing sites are often registered for only a few months.',
        'options': {'Registered for over 1 year (1)': 1, 'Registered for less than 1 year (-1)': -1}
    },
    'Having_IP_Address': {
        'label': '10. Does the URL use an IP address instead of a domain name?',
        'help': 'A URL like http://192.168.1.1/login is a red flag. Real sites use domain names, not raw IP addresses.',
        'options': {'Uses a domain name (1)': 1, 'Uses an IP address (-1)': -1}
    },
}

# ── Load model ──
@st.cache_resource
def load_model():
    return joblib.load('models/phishing_model.pkl')

model = load_model()

# ── Helper: run model prediction ──
def run_model(feature_dict):
    full_input = ALL_FEATURE_DEFAULTS.copy()
    full_input.update(feature_dict)
    input_df = pd.DataFrame([full_input])[CORRECT_ORDER]
    input_array = input_df.values
    prediction = model.predict(input_array)[0]
    probability = model.predict_proba(input_array)[0]
    phishing_prob = probability[1] * 100
    return prediction, phishing_prob

# ── Helper: show result banner and gauge ──
def show_result(prediction, phishing_prob):
    res_col1, res_col2 = st.columns([1, 1])
    with res_col1:
        if prediction == 1:
            st.error("### ⚠️ HIGH RISK — Likely Phishing")
            st.markdown(f"The model is **{phishing_prob:.1f}% confident** this site shows phishing characteristics.")
        else:
            st.success("### ✅ LOW RISK — Likely Legitimate")
            st.markdown(f"The model is **{(100 - phishing_prob):.1f}% confident** this site appears legitimate.")
    with res_col2:
        fig = go.Figure(go.Indicator(
            mode="gauge+number",
            value=phishing_prob,
            title={'text': "Phishing Risk %"},
            gauge={
                'axis': {'range': [0, 100]},
                'bar': {'color': "#E74C3C"},
                'steps': [
                    {'range': [0,  40], 'color': "#D5F5E3"},
                    {'range': [40, 70], 'color': "#FDEBD0"},
                    {'range': [70,100], 'color': "#FADBD8"},
                ],
            }
        ))
        fig.update_layout(height=250, margin=dict(t=40, b=0, l=20, r=20))
        st.plotly_chart(fig, use_container_width=True)

# ── Helper: VirusTotal scan ──
def check_virustotal(url):
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}
    try:
        submit = requests.post(
            "https://www.virustotal.com/api/v3/urls",
            headers=headers,
            data={"url": url},
            timeout=10
        )
        if submit.status_code != 200:
            return None, "Could not submit URL to VirusTotal."
        analysis_id = submit.json()["data"]["id"]
        time.sleep(3)
        result = requests.get(
            f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
            headers=headers,
            timeout=10
        )
        if result.status_code != 200:
            return None, "Could not retrieve VirusTotal results."
        return result.json()["data"]["attributes"]["stats"], None
    except requests.exceptions.Timeout:
        return None, "VirusTotal request timed out."
    except Exception as e:
        return None, f"VirusTotal error: {str(e)}"

# ══════════════════════════════════════
# HEADER
# ══════════════════════════════════════
st.image("assets/phishing.png", width=100)
st.markdown("# Phishing Website Detector")
st.markdown("Two ways to check a website — auto analyse a URL or answer manually.")
st.markdown("---")

# ══════════════════════════════════════
# TABS
# ══════════════════════════════════════
tab1, tab2 = st.tabs(["🔗 Auto URL Analyser", "📋 Manual Checklist"])

# ══════════════════════════════════════
# TAB 1 — Auto URL Analyser
# ══════════════════════════════════════
with tab1:
    st.subheader("🔗 Auto URL Analyser")
    st.markdown("Paste any URL and the app will automatically analyse it for phishing signals.")
    st.caption("⚠️ Never visit a suspicious URL directly — paste it here instead.")

    # Use session state to trigger analysis so Enter key doesn't fire prematurely
    if "auto_analyse_triggered" not in st.session_state:
        st.session_state.auto_analyse_triggered = False

    auto_url = st.text_input(
        "Paste URL to analyse:",
        placeholder="https://example.com",
        key="auto_url_input"
    )

    auto_btn = st.button("🚀 Auto Analyse", use_container_width=True, key="auto_btn")

    # Only trigger on button click, not on Enter
    if auto_btn:
        st.session_state.auto_analyse_triggered = True
        st.session_state.auto_url_value = auto_url

    if st.session_state.auto_analyse_triggered and st.session_state.get("auto_url_value"):
        url_to_analyse = st.session_state.auto_url_value
        if not url_to_analyse.strip():
            st.warning("Please enter a URL above.")
            st.session_state.auto_analyse_triggered = False
        else:
            with st.spinner("Analysing URL... checking SSL, domain age, redirects — this takes about 10 seconds..."):
                try:
                    from src.url_analyser import analyse_url
                    auto_features, findings = analyse_url(url_to_analyse)
                    prediction, phishing_prob = run_model(auto_features)

                    st.markdown("## Result")
                    show_result(prediction, phishing_prob)

                    st.markdown("### 🔍 What We Found")
                    st.caption("Here is what the automatic analysis detected about this URL:")
                    for key, explanation in findings.items():
                        if explanation.startswith("🔴"):
                            st.error(explanation)
                        elif explanation.startswith("🟡"):
                            st.warning(explanation)
                        else:
                            st.success(explanation)

                except TimeoutError as e:
                    st.error(f"⏱️ Analysis timed out: {str(e)}")
                    st.caption("The site may be slow or unreachable. Try again or use the Manual Checklist tab.")
                except Exception as e:
                    st.error(f"Could not analyse URL: {str(e)}")
                    st.caption("Make sure the URL starts with http:// or https://")

            st.session_state.auto_analyse_triggered = False

# ══════════════════════════════════════
# TAB 2 — Manual Checklist
# ══════════════════════════════════════
with tab2:
    st.subheader("📋 Manual Website Characteristics")
    st.caption("Answer each question based on what you observe about the website.")

    user_inputs = {}
    for feature_key, meta in TOP_FEATURES.items():
        choice = st.selectbox(
            label=meta['label'],
            options=list(meta['options'].keys()),
            help=meta['help'],
            key=f"manual_{feature_key}"
        )
        user_inputs[feature_key] = meta['options'][choice]

    st.markdown("---")

    if st.button("🔍 Analyse Website", use_container_width=True, key="manual_btn"):
        prediction, phishing_prob = run_model(user_inputs)

        st.markdown("## Result")
        show_result(prediction, phishing_prob)

        st.markdown("### 🚩 Red Flags Detected")
        red_flags   = [TOP_FEATURES[k]['label'].split('. ')[1] for k, v in user_inputs.items() if v == -1]
        yellow_flags = [TOP_FEATURES[k]['label'].split('. ')[1] for k, v in user_inputs.items() if v == 0]

        if red_flags:
            for label in red_flags:
                st.error(f"🔴 {label}")
        if yellow_flags:
            for label in yellow_flags:
                st.warning(f"🟡 {label}")
        if not red_flags and not yellow_flags:
            st.success("🟢 No red flags detected across all 10 checks.")

# ══════════════════════════════════════
# VIRUSTOTAL — Always visible below tabs
# ══════════════════════════════════════
st.markdown("---")
st.markdown("### 🦠 VirusTotal Cross-Check")
st.caption("Optionally cross-reference with 70+ antivirus engines.")

if "vt_triggered" not in st.session_state:
    st.session_state.vt_triggered = False

vt_url = st.text_input(
    "Enter the website URL to scan:",
    placeholder="https://example.com",
    key="vt_url_input"
)

vt_btn = st.button("🔎 Scan with VirusTotal", key="vt_btn")

# Only trigger on button click, not on Enter
if vt_btn:
    st.session_state.vt_triggered = True
    st.session_state.vt_url_value = vt_url

if st.session_state.vt_triggered and st.session_state.get("vt_url_value"):
    url_to_scan = st.session_state.vt_url_value
    if not url_to_scan.strip():
        st.warning("Please enter a URL above to scan.")
        st.session_state.vt_triggered = False
    elif not VIRUSTOTAL_API_KEY:
        st.error("VirusTotal API key not found. Check your Streamlit secrets or .env file.")
        st.session_state.vt_triggered = False
    else:
        with st.spinner("Submitting to VirusTotal... this takes about 5 seconds"):
            stats, error = check_virustotal(url_to_scan)

        if error:
            st.error(f"Error: {error}")
        else:
            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total = malicious + suspicious + harmless + undetected

            if malicious > 5:
                st.error(f"⚠️ FLAGGED — {malicious} out of {total} engines detected this as malicious.")
            elif malicious > 0:
                st.warning(f"🟡 SUSPICIOUS — {malicious} engines flagged this. Proceed with caution.")
            else:
                st.success(f"✅ CLEAN — 0 out of {total} engines flagged this URL.")

            vt_col1, vt_col2, vt_col3, vt_col4 = st.columns(4)
            vt_col1.metric("🔴 Malicious",  malicious)
            vt_col2.metric("🟡 Suspicious", suspicious)
            vt_col3.metric("🟢 Harmless",   harmless)
            vt_col4.metric("⚪ Undetected", undetected)
            st.caption(f"Scanned by {total} antivirus engines via VirusTotal API.")

        st.session_state.vt_triggered = False

# ── Footer ──
st.markdown("---")
st.caption("Built with Python · scikit-learn · Streamlit | UCI Phishing Dataset | 89% accuracy on 11,055 samples")