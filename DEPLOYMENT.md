# 🚀 Phishing Detector - Deployment Guide

This document contains complete deployment instructions for production environments.

## Table of Contents
1. [Local Development](#local-development)
2. [Streamlit Cloud](#streamlit-cloud)
3. [Docker Deployment](#docker-deployment-optional)
4. [Environment Variables](#environment-variables)
5. [Security Checklist](#security-checklist)
6. [Monitoring & Maintenance](#monitoring--maintenance)

---

## Local Development

### Prerequisites
- Python 3.9 or higher
- Git
- Virtual environment tool (venv or conda)

### Setup Steps

```bash
# 1. Clone repository
git clone https://github.com/yourusername/phishing-detector.git
cd phishing-detector

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # macOS/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Create .env file
echo VIRUSTOTAL_API_KEY=your_key_here > .env

# 5. Train model (if not already present)
python src/model_trainer.py

# 6. Run application
streamlit run app.py
```

The app will be available at: `http://localhost:8501`

### Development Tips
- Use `streamlit run app.py --logger.level=debug` for verbose logging
- Clear Streamlit cache with `streamlit cache clear`
- Hot reload is automatic - just save files

---

## Streamlit Cloud

### Prerequisites
- Streamlit Cloud account (free at https://streamlit.io/cloud)
- GitHub repository (public or connected private repo)
- VirusTotal API key (free tier available)

### Deployment Steps

#### 1. Push to GitHub
```bash
git add .
git commit -m "Prepare for deployment"
git push origin main
```

⚠️ **IMPORTANT**: Ensure `.env` is in `.gitignore` and not in repository history!

#### 2. Connect Streamlit Cloud
1. Go to https://share.streamlit.io/
2. Click "New app" → "From existing repo"
3. Select your repository, branch, and `app.py`
4. Click "Deploy"

#### 3. Configure Secrets
1. Navigate to your app's settings (gear icon)
2. Click "Secrets"
3. Add:
   ```
   VIRUSTOTAL_API_KEY = "your_virustotal_api_key"
   ```
4. Save

#### 4. Verify Deployment
- App automatically rebuilds when you push to main branch
- Check app logs for errors
- Test URL analyzer feature with a known URL

### Post-Deployment Monitoring
```bash
# Monitor logs (if Streamlit supports live logs)
streamlit logs

# Check app health
curl https://your-app.streamlit.app/health 2>/dev/null || echo "Status: Running"
```

---

## Docker Deployment (Optional)

For self-hosted deployment using Docker:

### 1. Create Dockerfile
```dockerfile
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app
COPY . .

# Expose port
EXPOSE 8501

# Run Streamlit
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
```

### 2. Build & Run
```bash
# Build image
docker build -t phishing-detector .

# Run container with env file
docker run -p 8501:8501 --env-file .env phishing-detector

# Or with environment variable
docker run -p 8501:8501 -e VIRUSTOTAL_API_KEY="your_key" phishing-detector
```

### 3. Docker Compose (Optional)
Create `docker-compose.yml`:
```yaml
version: '3.8'
services:
  app:
    build: .
    ports:
      - "8501:8501"
    environment:
      - VIRUSTOTAL_API_KEY=${VIRUSTOTAL_API_KEY}
    volumes:
      - ./logs:/app/logs
```

Run with: `docker-compose up`

---

## Environment Variables

### Required Variables
| Variable | Description | Source |
|----------|-------------|--------|
| `VIRUSTOTAL_API_KEY` | VirusTotal API key for scanning | https://www.virustotal.com/gui/home/upload |

### Optional Variables (Advanced)
| Variable | Default | Purpose |
|----------|---------|---------|
| `LOG_LEVEL` | `INFO` | Logging verbosity (DEBUG/INFO/WARNING/ERROR) |
| `HTTP_TIMEOUT_SECONDS` | `5` | Timeout for HTTP requests |
| `WHOIS_TIMEOUT_SECONDS` | `4` | Timeout for WHOIS lookups |
| `VIRUSTOTAL_TIMEOUT_SECONDS` | `10` | Timeout for VirusTotal API |

### .env File Example
```bash
# Required
VIRUSTOTAL_API_KEY=750d6d5741152b1b0ee7c03cd0b7249bf676b7e6b936bf3d5821ea0fdae9aea5

# Optional (uncomment to customize)
# LOG_LEVEL=DEBUG
# HTTP_TIMEOUT_SECONDS=10
```

---

## Security Checklist

### Before Deployment
- [ ] API key has been revoked from git history (use `git-filter-branch` or `BFG`)
- [ ] `.env` file is in `.gitignore`
- [ ] No secrets in code comments or strings
- [ ] Requirements.txt has no security vulnerabilities (`pip-audit`)
- [ ] All external API calls use `verify=True` for SSL
- [ ] Error messages don't expose sensitive information

### During Deployment
- [ ] Deploy over HTTPS (Streamlit Cloud does this automatically)
- [ ] Set strong API key with appropriate permissions (read-only for VirusTotal)
- [ ] Use environment variables, never hardcoded secrets
- [ ] Enable monitoring/logging
- [ ] Set up alerts for errors

### After Deployment
- [ ] Test full workflow end-to-end
- [ ] Verify error handling works (test with invalid URLs)
- [ ] Check logs for anomalies
- [ ] Monitor API quota usage
- [ ] Document any custom configurations

### API Key Management
```bash
# Rotate API key periodically (monthly recommended)
# 1. Generate new key in VirusTotal dashboard
# 2. Update .env or Streamlit Secrets
# 3. Revoke old key
# 4. Test app with new key
# 5. Monitor for any issues
```

---

## Monitoring & Maintenance

### Log Locations
- **Streamlit Cloud**: View in Settings → Logs
- **Docker**: `docker logs container_name`
- **Local Development**: Console output

### Key Metrics to Monitor
1. **API Success Rate**: % of successful VirusTotal scans
2. **Response Time**: URL analysis duration (target: <15s)
3. **Error Rate**: Failed analyses / total analyses
4. **Rate Limiting**: Check for VirusTotal rate limit errors

### Common Issues & Solutions

#### VirusTotal API Error
```
Error: Could not submit URL to VirusTotal
Cause: API key invalid, quota exceeded, or rate limited
Fix: Check API key, wait for rate limit to reset, increase quota
```

#### WHOIS Lookup Failed
```
Domain age could not be verified via WHOIS
Cause: Normal - domain privacy enabled
Action: Analysis continues with other features
```

#### Timeout During Analysis
```
Analysis timed out
Cause: Slow website, network issues
Fix: Recommend user try another URL or use Manual Checklist
```

#### Model File Not Found
```
Model file not found at models/phishing_model.pkl
Cause: Model wasn't trained
Fix: Run python src/model_trainer.py
```

### Health Check

Create a simple health check endpoint:
```python
@app.get("/health")
def health():
    return {
        "status": "ok",
        "model_loaded": model is not None,
        "api_key_configured": bool(VIRUSTOTAL_API_KEY)
    }
```

### Performance Optimization
1. **Cache Results**: Store analysis results to reduce API calls
2. **Batch Processing**: Queue multiple URL scans
3. **Database**: Add SQLite/PostgreSQL for persistent storage
4. **CDN**: Cache static assets
5. **Rate Limiting**: Implement per-user limits

### Backup & Recovery
```bash
# Backup model
cp models/phishing_model.pkl models/phishing_model.pkl.backup

# Backup requirements
pip freeze > requirements.frozen.txt

# Daily backup (cron job)
0 2 * * * cp -r /app/models /backups/models_$(date +%Y%m%d)
```

---

## Troubleshooting Deployment

### App won't start
```bash
# Check Python version
python --version  # Should be 3.9+

# Check dependencies
pip install -r requirements.txt

# Run syntax check
python -m py_compile app.py src/*.py

# Check for import errors
python -c "import streamlit; import joblib; import pandas"
```

### API Key issues
```bash
# Verify key exists
echo $VIRUSTOTAL_API_KEY  # Should show key (or empty in production)

# Test API key with curl
curl -H "x-apikey: $VIRUSTOTAL_API_KEY" https://www.virustotal.com/api/v3/urls
```

### Performance issues
```bash
# Check logs for slow operations
grep "took" app.log

# Monitor resource usage
# Linux: top, ps
# Docker: docker stats
# Streamlit Cloud: Settings → Logs

# Profile slow functions
python -m cProfile -s cumulative app.py
```

---

## Support & Further Help

- **Streamlit Docs**: https://docs.streamlit.io/
- **VirusTotal API**: https://developers.virustotal.com/
- **Project Issues**: GitHub Issues
- **Community**: Streamlit Discourse

---

*Last Updated: 2026-06-11*
