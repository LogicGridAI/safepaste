README.md
# SafePaste Enterprise

> Zero-trust DLP that intercepts clipboard data before it reaches AI tools like ChatGPT, Claude, and Gemini.

[![Chrome Web Store](https://img.shields.io/badge/Chrome-Web%20Store-blue?logo=googlechrome)](https://safepaste.app)
[![Firefox Add-ons](https://img.shields.io/badge/Firefox-Add--ons-orange?logo=firefox)](https://addons.mozilla.org/en-US/firefox/addon/safepaste-enterprise/)
[![PyPI](https://img.shields.io/badge/PyPI-safepaste--enterprise-blue?logo=pypi)](https://pypi.org/project/safepaste-enterprise/)
[![Docker Hub](https://img.shields.io/badge/Docker-logicgridai%2Fsafepaste-blue?logo=docker)](https://hub.docker.com/r/logicgridai/safepaste)
[![Version](https://img.shields.io/badge/version-3.2.1-green)](https://github.com/LogicGridAI/safepaste/releases/tag/v3.2.1)

---

## What it does

SafePaste Enterprise intercepts your clipboard **in memory** before any text reaches an AI platform. Secrets vault in RAM and are replaced with labelled placeholders. AI responses are revealed locally via green lock badges — your real values never leave your device.

```
BEFORE                                    AFTER (SafePaste)
─────────────────────────────────         ─────────────────────────────────
OPENAI_API_KEY=sk-proj-abc...xyz          OPENAI_API_KEY=[OPENAI_KEY_1]
AWS_ACCESS_KEY_ID=AKIA1234ABCD            AWS_ACCESS_KEY_ID=[AWS_1]
Authorization: Bearer eyJhb...            Authorization: Bearer [BEARER_1]
Contact: jane.doe@acme.com                Contact: [EMAIL_1]
Server: 203.0.113.42                      Server: [IP_1]
```

---

## Three ways to use it

### 1. Browser Extension (Chrome / Firefox / Edge)

Works silently on ChatGPT, Claude, Gemini, Copilot, Perplexity, and all major AI platforms.

- [Chrome Web Store](https://safepaste.app)
- [Firefox Add-ons](https://addons.mozilla.org/en-US/firefox/addon/safepaste-enterprise/)
- [Microsoft Edge Add-ons](https://safepaste.app)

### 2. Python CLI (Linux pipelines, CI/CD, log shipping)

```bash
pip install safepaste-enterprise

# Mask secrets from any pipe
cat /var/log/app.log | safepaste --mask

# Unmask AI response locally
cat ai_response.txt | safepaste --unmask

# Activate Pro license
safepaste --unlock "YOUR-LICENSE-KEY"

# Corporate proxy / airgapped environments
safepaste --unlock "YOUR-LICENSE-KEY" --proxy http://proxy.corp.com:8080

# Or via environment variable
export SAFEPASTE_PROXY=http://proxy.corp.com:8080
safepaste --mask < logs.txt
```

### 3. Docker (zero-install, Kubernetes sidecar)

```bash
# Pull the image
docker pull logicgridai/safepaste:latest

# Basic pipe — mask secrets
cat /var/log/app.log | docker run --rm -i logicgridai/safepaste --mask

# Pro tier with persistent vault
cat report.txt | docker run --rm -i \
  -v ~/.safepaste:/home/safepaste/.safepaste \
  logicgridai/safepaste --mask

# Enterprise — Redis multi-pod vault
docker run --rm -i \
  -e SAFEPASTE_REDIS_URL="redis://:password@redis-host:6379/0" \
  logicgridai/safepaste --mask < logs.txt
```

#### Kubernetes sidecar

```yaml
containers:
  - name: safepaste
    image: logicgridai/safepaste:3.2.2
    env:
      - name: SAFEPASTE_LICENSE_KEY
        valueFrom:
          secretKeyRef:
            name: safepaste-secret
            key: license-key
      - name: SAFEPASTE_PROXY
        value: "http://proxy.corp.com:8080"
    resources:
      requests:
        memory: "64Mi"
        cpu: "50m"
      limits:
        memory: "128Mi"
        cpu: "100m"
    securityContext:
      runAsNonRoot: true
      runAsUser: 1000
      allowPrivilegeEscalation: false
```

---

## Patterns — 19 across 8 countries

| Country | Patterns |
|---|---|
| United States | SSN, Green Card |
| European Union | IBAN |
| United Kingdom | NINO |
| Nigeria | NIN, Bank Account, Phone |
| Canada | SIN |
| India | Aadhaar, PAN |
| South Africa | National ID |
| Australia | TFN |
| Brazil | CPF |
| Singapore | NRIC |
| Global | OpenAI/Anthropic/Google API keys, AWS Access Key ID, Bearer tokens, Slack webhooks, Email addresses, IPv4 |

---

## Enterprise deployment

### Firewall whitelist
```
api.safepaste.app:443
```

### CrowdStrike / EDR users
SafePaste writes vault data to `~/.safepaste/` — whitelist this path in your EDR policy to prevent false positive alerts.

- No persistence mechanism
- No network listener
- No privilege escalation
- Exits cleanly after each pipe operation

### K8s secret setup
```bash
kubectl create secret generic safepaste-secret \
  --from-literal=license-key=YOUR-LICENSE-KEY \
  --from-literal=redis-url=redis://:password@redis:6379/0
```

---

## Pricing

| Tier | Price | Features |
|---|---|---|
| Free | $0 | IP + API key redaction |
| Pro | $7.99/month or $69/year | Full 19-pattern vault + unmask |
| Team Pilot | $149 flat / 10 seats | Team deployment |
| Enterprise | $25/user/month (min 10) | MDM/GPO, SIEM, Admin Dashboard |

→ [Get a license at safepaste.app](https://safepaste.app)

---

## Privacy

Paste content never leaves your device. License activation sends only a hashed instance ID to a Cloudflare Worker at `api.safepaste.app` — no paste data, ever.

Full privacy policy: [safepaste.app/privacy](https://safepaste.app/privacy)

---

## Roadmap — v4.0

- Crypto wallet patterns (Bitcoin, Ethereum, Solana, seed phrases)
- `.env` file detection and full-file redaction
- Custom enterprise regex (self-serve + managed)
- RBAC department profiles (Finance / HR / IT)
- MDM/GPO deployment via chrome.storage.managed
- SIEM webhook integration
- Central Admin Dashboard

---

## Built by

[LogicGrid AI, LLC](https://safepaste.app) — support@logicgrid.ai