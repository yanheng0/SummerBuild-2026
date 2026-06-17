# 🛡️ SPOT (Scan, Pattern, Observe & Track)

![Python](https://img.shields.io/badge/Python-3.11+-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Supported-2496ED.svg)
![Telegram](https://img.shields.io/badge/Telegram-Bot-2CA5E0.svg)
![AI](https://img.shields.io/badge/AI-Reka_Vision-purple.svg)

**SPOT** is an autonomous, multimodal Telegram bot designed to protect Singapore residents from digital fraud in real time. Acting as a forensic scam detection engine, SPOT analyses text messages, screenshots, and voice notes — grounding every verdict in verified advisories from the Singapore Police Force (SPF) and Monetary Authority of Singapore (MAS).
Built with a focus on the Singaporean context, SPOT grounds its AI analysis in real-world advisories from the Singapore Police Force (SPF) and Monetary Authority of Singapore (MAS).

---

## 📖 Table of Contents
1. [The Problem](#-the-problem)
2. [Key Features](#-key-features)
3. [System Architecture](#-system-architecture)
4. [Tech Stack](#-tech-stack)
5. [Getting Started (Local & Docker)](#-getting-started)
6. [Usage & Commands](#-usage--commands)
7. [Project Structure](#-project-structure)
8. [Future Roadmap](#-future-roadmap)

---

## The Problem
Scams are becoming increasingly sophisticated. Threat actors now utilize AI-generated deepfakes, cloned voice notes, and highly targeted phishing campaigns. Traditional scam filters—which rely purely on static text-matching or blacklisted URLs—fail to catch multimodal threats (e.g., a voice note impersonating an official, or a screenshot of a fabricated bank transfer). 

**SPOT** solves this by offering a zero-friction, multimodal verification layer right inside Telegram.

---

## Key Features

* **Multimodal Threat Detection:** Powered by Reka AI, SPOT doesn't just read text. It "sees" screenshots of fake crypto platforms and "listens" to voice notes to detect impersonation and urgency cues.
* **Contextual RAG Pipeline:** Generic LLMs often miss local nuances. SPOT utilizes a custom Retrieval-Augmented Generation (RAG) system built with `scikit-learn` (TF-IDF). It intercepts queries, searches a curated database of verified Singaporean scam cases, and grounds the AI's analysis in local reality.
* **Self-Reflection & Verification Pass:** To eliminate false positives, SPOT features an autonomous escalation loop. If the AI's initial confidence score is ambiguous (30%–70%), the backend forces the model to act as a "Senior Forensic Investigator," re-evaluating the evidence step-by-step before returning a final verdict.
* **Automated Police Reporting:** If a user is targeted by a scam, SPOT lowers the friction of reporting it. By typing `/report`, the bot parses the forensic JSON from the last scan and drafts a formal, structured police report ready for submission to the authorities.
* **On-the-Fly Audio Transcoding:** Telegram voice notes (OGG/Opus) are automatically transcoded via FFmpeg into 16kHz WAV files, ensuring compatibility with the AI engine without hitting file size limits.

---

## System Architecture

SPOT is designed as a linear, high-speed forensic pipeline. When a user interacts with the bot, their input flows through four distinct processing layers.

### Visual Flow
```text
[ User / Victim ] 📱
       │
       ▼
[ Telegram Bot ] 🤖 ────────────────────────┐ (If /report)
       │                                    │
       ├─► Text / Image                     │
       │                                    │
       └─► Voice Note (.ogg)                │
               │                            │
               ▼                            │
         [ FFmpeg ] 🎵 (Converts to WAV)    │
               │                            │
               ▼                            │
[ 🧠 Intelligence Core ] ◄──────────────────┘
       │
       ├─► 1. RAG System 📚 (Retrieves local SPF/MAS case context)
       │
       ├─► 2. AI Pass 1  👁️ (Reka Flash: Multimodal Scan)
       │
       └─► 3. AI Pass 2  🕵️‍♂️ (Self-Reflection triggered if Confidence is 30-70%)
               │
               ▼
[ UI Formatter ] 📝 (Translates JSON to clean HTML)
       │
       ▼
[ Final Verdict ] 🚨 (Sent back to User)
```
## How It Works:
The telegram bot uses REKA API to analyse the image. The bot returns a confidence scoring of the scam as well as the explainment based on its verdict.
It is capable of drafting a detailed explaination for submission, providing detailed information such as "" <<< which are useful information for the
police>>>

## Architecture:
```text
Scambot/
├── Dockerfile                  # Debian-based Dockerfile with FFmpeg
├── docker-compose.yml          # Container orchestration
├── main.py                     # Entry point & bot routing
├── requirements.txt
├── handlers/                   # Telegram event handlers
│   ├── image.py                # Handles photo uploads
│   ├── voice.py                # Handles audio/voice notes
│   ├── text.py                 # Handles text/links
│   ├── report.py               # Generates draft police reports
│   └── ...
└── services/                   # Core business logic
    ├── reka_client.py          # AI integration & Self-Reflection logic
    ├── audio_converter.py      # Transcodes Telegram OGG to WAV
    ├── utils/formatter.py      # HTML formatting for Telegram UI
    └── rag/
        ├── knowledge_base.py   # Curated SG scam patterns & indicators
        └── retriever.py        # TF-IDF search engine
```
## Tech Stack:
- Language: Python 3.11+
- Bot Framework: python-telegram-bot (v22.7)
- AI Provider: Reka AI (reka-flash model via HTTPX)
- Vector/RAG Engine: scikit-learn, numpy (TF-IDF & Cosine Similarity)
- Audio Processing: pydub, FFmpeg
- Infrastructure: Docker, Docker Compose

## Getting Started:
**Prerequisites**
1. A Telegram Bot Token (From @BotFather on telegram)
2. A Reka API key
3. Docker or Python 3.11+ with FFmpeg installed 

**Option 1: Running with Docker (Recommended)**:

Docker handles all system dependencies, including FFmpeg for voice note processing.

1. Clone the repository:
```
git clone [https://github.com/yourusername/SPOT-scambot.git](https://github.com/yourusername/SPOT-scambot.git)
cd SPOT-scambot
```
2. Configure Environment Variables:
```
cp .env.template .env
```
3. Edit the .env file and insert your keys:
```
TELEGRAM_BOT_TOKEN="your-telegram-bot-token"
REKA_API_KEY="your-reka-api-key"
REKA_API_URL="[https://api.reka.ai/v1](https://api.reka.ai/v1)"
```
4. Build and Run the Bot:
```
docker-compose up -d --build
```
To view logs: 
```docker-compose logs -f```

**Option 2: Local Setup**

Install FFmpeg: Ensure FFmpeg is installed and added to your system's PATH.

1. Install Python dependencies:
```
python -m venv venv
source venv/bin/activate  # On Windows use: venv\Scripts\activate
pip install -r requirements.txt
```
2. Run the bot:
```
python main.py
```
