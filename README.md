# 🛡️ FraudNot

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED.svg)
![Telegram](https://img.shields.io/badge/Telegram-Bot-2CA5E0.svg)
![AI](https://img.shields.io/badge/AI-Reka_Vision-purple.svg)

**FraudNot** is an autonomous, multimodal Telegram bot designed to protect Singapore residents from digital fraud in real time. Acting as a forensic scam detection engine, FraudNot analyses text messages, screenshots, and voice notes — grounding every verdict in verified advisories from the Singapore Police Force (SPF) and Monetary Authority of Singapore (MAS).
Built with a focus on the Singaporean context, FraudNot grounds its AI analysis in real-world advisories from the Singapore Police Force (SPF) and Monetary Authority of Singapore (MAS).

---

## 📖 Table of Contents
1. [The Problem](#-the-problem)
2. [Key Features](#-key-features)
3. [System Architecture](#-system-architecture)
4. [Tech Stack](#-tech-stack)
5. [Getting Started (Local & Docker)](#-getting-started)
6. [Usage & Commands](#-usage--commands)
7. [Project Structure](#-project-structure)

---

## The Problem
Scams are Singapore's most prevalent crime — and the numbers are staggering.

According to the **SPF Annual Scams and Cybercrime Brief 2025**, Singapore recorded **37,308 scam cases** in 2025, with total losses amounting to **$913.1 million**. While overall case counts declined by 27.6% year-on-year, scammers are rapidly adapting, deploying more sophisticated tactics that are harder for the average person to detect.

The four highest-impact scam categories tracked by [ScamShield (scamshield.gov.sg)](https://www.scamshield.gov.sg) tell the story:

| Scam Type | Total Losses |
|---|---|
| 💼 Investment Scams | **$336.2 million** |
| 🏛️ Government Impersonation | **$242.9 million** |
| 💼 Job Scams | **$123.5 million** |
| 🎣 Phishing | **$39.9 million** |

Beyond the financial toll, scams cause lasting psychological harm — victims report anxiety, shame, and loss of trust. Many never report incidents to the authorities, meaning the true scale is likely far greater.

**The core failure of existing tools is modality.** Traditional scam filters rely on static keyword blacklists and URL databases. They cannot:

- **See** a screenshot of a fabricated bank transfer or fake crypto dashboard
- **Listen** to a cloned voice note impersonating a government officer
- **Reason** about local context — Singapore-specific agencies (CPF, IRAS, SPF), payment methods (PayNow), and scam patterns that generic models miss

FraudNot was built to close that gap.

---

## How FraudNot Helps

FraudNot gives any Telegram user — regardless of technical literacy — a zero-friction forensic verification layer. Instead of searching for information or second-guessing suspicious content alone, users forward the suspect material directly to SPOT and receive a structured verdict within seconds.

If the content is a confirmed scam, SPOT can immediately draft a formal police report pre-populated with the relevant details, dramatically lowering the friction of reporting to SPF.

For urgent help, users can also contact the **24/7 ScamShield Helpline at 1799**.

---

## Key Features

**Multimodal Threat Detection**
Powered by Reka Flash, FraudNot analyses text messages, screenshots, and voice notes in a single unified pipeline. It can read a fabricated PayNow confirmation, decode a phishing URL hidden in an image, and transcribe a voice note impersonating an SPF officer.

**Contextual RAG Pipeline**
Generic language models frequently miss Singapore-specific scam patterns. FraudNot uses a custom Retrieval-Augmented Generation (RAG) system built on TF-IDF cosine similarity, querying a curated knowledge base of verified SPF and MAS scam advisories before every analysis. This grounds verdicts in local reality rather than generic heuristics.

**Self-Reflection & Verification Pass**
To minimise false positives, FraudNot employs an autonomous escalation loop. When initial confidence is ambiguous (30–70%), the model is forced to act as a Senior Forensic Investigator — re-examining each indicator's strength and context before delivering a final verdict.

**Automated Police Report Drafting**
After any scan, users can type `/report` or click on `Detailed Report` to instantly generate a structured draft police report in the format expected by SPF. This reduces a common barrier: victims know they should report but find the process daunting.

**On-the-Fly Audio Transcoding**
Telegram voice notes (OGG/Opus) are automatically transcoded via FFmpeg to 16kHz mono WAV, then transcribed via ElevenLabs Scribe before being run through the scam analysis pipeline. This means voice-based impersonation attacks — one of the fastest-growing scam vectors — are handled natively.

---

## System Architecture

FraudNot is designed as a linear forensic pipeline. Every input flows through four distinct processing layers before a verdict is returned.

```
[ User / Victim ] 📱
       │
       ▼
[ Telegram Bot ] 🤖 ─────────────────────────┐
       │                                     │ /report
       ├─► Text / Image                      │
       └─► Voice Note (.ogg / .mp3 / etc.)   │
               │                             │
               ▼                             │
        [ FFmpeg + ElevenLabs ] 🎙️           │
        (Transcode → Transcribe)             │
               │                             │
               ▼                             ▼
┌──────────────────────────────────────────────────┐
│              🧠 Intelligence Core                │
│                                                  │
│  1. RAG Retriever  — TF-IDF over SPF/MAS cases  │
│  2. Pass 1         — Reka Flash multimodal scan  │
│  3. Pass 2         — Self-reflection (if 30–70%) │
└──────────────────────────────────────────────────┘
       │
       ▼
[ UI Formatter ] 📝  →  HTML verdict + inline button
       │
       ▼
[ Final Verdict ] 🚨  →  User receives result
```
### Decision Flow

```
Confidence ≥ 71% or ≤ 29%  →  Return Pass 1 result immediately
Confidence 30–70%           →  Escalate to verification pass
  Both passes agree          →  Return higher-confidence result
  Passes disagree            →  Return SUSPICIOUS (55%) for human review
```

---
## Tech Stack

| Layer | Technology |
|---|---|
| Language | Python 3.11+ |
| Bot Framework | python-telegram-bot v22.7 |
| AI / Vision | Reka Flash (`reka-flash`) via HTTPX |
| Transcription | ElevenLabs Scribe (`scribe_v1`) |
| RAG Engine | scikit-learn (TF-IDF), NumPy |
| Audio Processing | pydub, FFmpeg |
| Infrastructure | Docker, Docker Compose |

---

## 🚀 Getting Started

### Prerequisites

- A Telegram Bot Token — obtain from [@BotFather](https://t.me/BotFather)
- A [Reka AI](https://reka.ai) API key
- An [ElevenLabs](https://elevenlabs.io) API key (for voice transcription)
- Docker **or** Python 3.11+ with FFmpeg installed locally

---

### Option 1: Docker (Recommended)

Docker handles all system dependencies including FFmpeg automatically.

```bash
# 1. Clone the repository
git clone https://github.com/yourusername/SPOT-scambot.git
cd SPOT-scambot

# 2. Configure environment variables
cp .env.template .env
# Edit .env and fill in your keys

# 3. Build and run
docker-compose up -d --build

# 4. View live logs
docker-compose logs -f
```

---

### Option 2: Local Setup

**Step 1 — Install FFmpeg**

Ensure `ffmpeg` is installed and available on your system PATH:
- **Windows:** Download from [ffmpeg.org](https://ffmpeg.org/download.html) and add the `bin/` directory to PATH
- **macOS:** `brew install ffmpeg`
- **Linux:** `sudo apt install ffmpeg`

Verify: `ffmpeg -version`

**Step 2 — Configure environment**

```bash
cp .env.template .env
```

Edit `.env`:
```env
TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
REKA_API_KEY="your-reka-api-key"
REKA_API_URL="https://api.reka.ai/v1"
ELEVENLABS_API_KEY="your-elevenlabs-api-key"
```

**Step 3 — Install dependencies and run**

```bash
python -m venv venv
source venv/bin/activate       # Windows: venv\Scripts\activate
pip install -r requirements.txt
python main.py
```

---

## Usage & Commands

| Command / Input | Action |
|---|---|
| `/start` | Welcome message and quick guide |
| `/help` | Full command reference |
| `/report` | Draft a police report from the last scan |
| Send any **text or URL** | Analyse for scam patterns |
| Send an **image / screenshot** | Analyse for visual scam indicators |
| Send a **voice note or audio file** | Transcribe and analyse for impersonation cues |

After every scan, an inline **"Draft a Police Report"** button appears for one-tap report generation.

---

## Project Structure
```
FraudNot/
├── Dockerfile                   # Debian-based image with FFmpeg
├── docker-compose.yml           # Container orchestration
├── main.py                      # Entry point and handler registration
├── requirements.txt
├── .env.template                # Environment variable template
├── handlers/
│   ├── start.py                 # /start command
│   ├── help.py                  # /help command
│   ├── text.py                  # Text and URL messages
│   ├── image.py                 # Photo uploads
│   ├── voice.py                 # Voice notes and audio files
│   └── report.py                # /report command + inline button callback
└── services/
    ├── reka_client.py           # AI pipeline, escalation logic, report generation
    ├── audio_converter.py       # FFmpeg transcoding (OGG → 16kHz WAV)
    ├── utils/
    │   ├── formatter.py         # HTML verdict formatter
    │   └── formatter_button.py  # Verdict with inline keyboard
    └── rag/
        ├── knowledge_base.py    # Curated SPF/MAS scam case database
        └── retriever.py         # TF-IDF cosine similarity search
```

---

## ⚠️ Disclaimer

FraudNot is a decision-support tool, not a replacement for professional judgement. All verdicts should be verified independently. If you believe you have been scammed:

- Call the **24/7 ScamShield Helpline at 1799**
- Lodge a police report at [police.gov.sg](https://www.police.gov.sg/e-services/lodge-police-report)
- Contact your bank immediately to freeze transactions

---

*Built for Singapore 🇸🇬 · Powered by [Reka AI](https://reka.ai) · Scam data sourced from [ScamShield](https://www.scamshield.gov.sg) and [SPF](https://www.police.gov.sg)*

