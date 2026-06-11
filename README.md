# 🎣 Phishing Website Detector

> A machine learning system that analyses website characteristics to detect phishing attempts.
> Built as a cybersecurity portfolio project using Python, scikit-learn, and Streamlit.

## 🔴 Live Demo
👉 **[Try the app here](https://phishing-detector-abree.streamlit.app/)** 

---

## Project Overview

Phishing attacks are one of the most common cybersecurity threats, tricking users into
revealing credentials on fake websites. This project builds a two-layer detection system:

**Layer 1 — Machine Learning Model**
A Random Forest classifier trained on the UCI Phishing Dataset (11,055 samples) achieving
89% accuracy. The model analyses 30 website characteristics to determine whether a site
is likely phishing or legitimate.

**Layer 2 — VirusTotal Integration**
Real-time cross-referencing against 90+ antivirus engines via the VirusTotal API.

**Two ways to use it:**
- 🔗 **Auto URL Analyser** — paste any URL for instant automatic analysis with plain
  English explanations of every finding
- 📋 **Manual Checklist** — answer 10 questions about a site for a structured assessment
---

## How It Works

The classifier is a **Random Forest** trained on the
[UCI Machine Learning Phishing Dataset](https://archive.ics.uci.edu/ml/datasets/phishing+websites).
Each website is represented by 30 binary/ternary features encoding structural and
behavioural characteristics of the URL and page.

### Top Features by Importance

| Feature | Importance | What It Means |
|---|---|---|
| SSLfinal_State | 32% | Valid SSL certificate from trusted authority |
| URL_of_Anchor | 21% | % of links pointing to external domains |
| Prefix_Suffix | 6.5% | Hyphen used in domain name |
| Web_Traffic | 5.5% | Site has measurable traffic rank |
| Having_Sub_Domain | 5.4% | Multiple subdomains in URL |

![Feature Importance Chart](data/feature_importance.png)

---

## Model Performance

Trained on 8,844 samples, tested on 2,211 samples (80/20 split):
precision    recall  f1-score   support
   Legit       0.90      0.84      0.87       980
Phishing       0.88      0.92      0.90      1231
accuracy                           0.89      2211
**Confusion Matrix:**
- ✅ 828 legitimate sites correctly identified
- ✅ 1,136 phishing sites correctly identified
- ⚠️ 95 phishing sites missed (false negatives)
- ⚠️ 152 legitimate sites incorrectly flagged (false positives)

> The model is tuned to prioritise catching phishing sites (high recall) over avoiding
> false alarms — in security, missing a real threat is more costly than a false positive.

---

## Tech Stack

| Tool | Purpose |
|---|---|
| Python 3.9+ | Core language |
| pandas & numpy | Data wrangling |
| scikit-learn | Model training and evaluation |
| matplotlib & seaborn | Visualisations |
| Streamlit | Web application |
| plotly | Interactive gauge chart |
| joblib | Model serialisation |

---

## Installation

> The raw data files are not included in this repo due to size.
> Download the UCI dataset from the link above and place it in the `data/` folder.

```bash
# 1. Clone the repo
git clone https://github.com/ABree24/phishing-detector.git
cd phishing-detector

# 2. Create and activate virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure API Keys

## Local Development (.env file)

Create a `.env` file in the project root:

```bash
VIRUSTOTAL_API_KEY=your_virustotal_api_key_here
```

Get your VirusTotal API key for free at: https://www.virustotal.com/gui/home/upload

⚠️ **IMPORTANT:** Never commit `.env` to Git. It's already in `.gitignore`.

## Streamlit Cloud Deployment

For Streamlit Cloud, add secrets via the app settings:
1. Go to your Streamlit Cloud app dashboard
2. Click "Settings" → "Secrets"
3. Add:
   ```
   VIRUSTOTAL_API_KEY = "your_key_here"
   ```

The app will automatically read from `st.secrets` if available.

# 5. Prepare the data
python notebooks/02_feature_engineering.py

# 6. Train the model
python src/model_trainer.py

# 7. Run the app
streamlit run app.py
```

---

## 🔒 Security & Privacy

This app has been audited for security issues and fixed in v2.0:

### ✅ What's Secure
- **HTTPS Required**: All external API calls use `verify=True` for SSL verification
- **Error Handling**: No sensitive errors exposed to users; exceptions logged server-side
- **Input Validation**: All URLs validated before analysis
- **API Keys**: Stored in environment variables, never hardcoded
- **No Data Retention**: URLs are not stored; analysis is ephemeral
- **Safe Deserialization**: Model loading uses safe joblib practices

### ⚠️ What to Know
- The **VirusTotal scan is optional** — if the API fails, local analysis continues
- **Rate limiting**: Free VirusTotal tier allows ~4 requests/minute
- **Timeout protection**: All external requests have sensible timeouts to prevent hanging
- **Logging**: Errors and requests are logged for debugging (no full URLs in logs)

### 🔐 For Production Deployment
- Use HTTPS enforcement at the load balancer level
- Implement rate limiting per user (IP address or authentication)
- Monitor error logs for security anomalies
- Rotate API keys regularly
- Consider adding authentication for admin access
- Log all analysis requests for audit trails

---

## 📊 Configuration

Core settings are in `config.py`. Update these if needed:

```python
# URL Length thresholds (characters)
URL_LENGTH_SHORT = 54      # Normal URLs are <54 chars
URL_LENGTH_MEDIUM = 75     # Suspicious: 54-75 chars

# Domain age (days)
DOMAIN_AGE_NORMAL_DAYS = 365  # Domains >1 year are normal

# Timeouts (seconds)
HTTP_TIMEOUT_SECONDS = 5
WHOIS_TIMEOUT_SECONDS = 4
VIRUSTOTAL_TIMEOUT_SECONDS = 10

# Other settings...
```

---

## 🐛 Troubleshooting

**"Model file not found"**
- Ensure `models/phishing_model.pkl` exists
- Run `python src/model_trainer.py` to generate it

**"VirusTotal API key not found"**
- For local: Create `.env` file with `VIRUSTOTAL_API_KEY=xxx`
- For Streamlit Cloud: Add to Secrets in dashboard settings

**"WHOIS lookup failed"**
- This is often normal (domain privacy enabled)
- Analysis continues with local features

**"HTML parsing error"**
- Check your internet connection
- The site may be blocking requests; try another URL

**"Timeout during analysis"**
- The website may be slow or unreachable
- Try the Manual Checklist tab instead

---

## 📈 Model Information

### Training Details
- **Dataset**: UCI Phishing Websites Dataset (11,055 samples)
- **Algorithm**: Random Forest (100 estimators)
- **Train/Test Split**: 80/20
- **Features**: 30 structural and behavioral characteristics
- **Accuracy**: 89% on test set
- **Bias**: Model prioritizes recall (catching phishing) over precision

### Feature Categories
1. **URL Features** (5): IP address, length, shortener, @ symbol, double slash
2. **Domain Features** (4): Prefix/suffix, subdomains, SSL cert, registration length
3. **Page Features** (15): HTML structure, external resources, forms, scripts
4. **Reputation Features** (6): Web traffic, PageRank, Google index, DNS record, etc.

### Limitations
- ✗ Cannot detect zero-day phishing (brand new, never-seen-before attacks)
- ✗ Relies on public WHOIS data (won't work for privacy-protected domains)
- ✗ Cannot analyze password-protected sites
- ✗ May have regional biases based on training data
- ✓ Best used as a **layer in a defense-in-depth strategy**, not the only check

---

## 💡 What I Learned

- **Data quality matters more than model complexity** — I initially achieved 100% accuracy
  which turned out to be caused by class imbalance and data leakage between two poorly
  matched datasets. Switching to the UCI benchmark dataset gave a realistic 89%.

- **Feature importance tells a security story** — SSL certificate state being the strongest
  predictor (32%) makes intuitive sense; phishing sites either skip HTTPS or use untrusted
  certificates because they can't obtain legitimate ones for domains they don't own.

- **False negatives vs false positives** — In security contexts, missing a phishing attack
  (false negative) is more dangerous than flagging a legitimate site (false positive). This
  influenced how I evaluated and communicate the model's performance.

- **Clean Git hygiene** — Learned to properly configure `.gitignore` to exclude large data
  files and virtual environments, and handled a secret scanning alert caused by attacker
  Telegram tokens embedded inside PhishTank phishing URLs.

---

## Future Improvements

- Add live URL input using WHOIS
- Retrain with a larger, more recent phishing dataset
- Add email header analysis as a second detection mode
- Experiment with XGBoost and compare performance against Random Forest

---

## Project Structure
phishing-detector/
├── assets/             # Images and icons
├── models/             # Saved model files (.pkl)
├── notebooks/          # Data prep and visualisation scripts
├── src/                # Core modules
│   ├── feature_extractor.py
│   └── model_trainer.py
├── app.py              # Streamlit web application
├── requirements.txt    # Dependencies
└── README.md
---

*Built by ABree24 · UCI Phishing Dataset · scikit-learn · Streamlit*