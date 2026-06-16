# SPOT - Scan Pattern Observation & Tracking
SPOT is an autonomous, multimodal Telegram Bot designed to protect Singaporeans by detecting scams, deepfakes, and fraudulent patterns across text messages, screenshots, and voice recordings.

## What Our Product Does:
As scams become increasingly sophisticated—utilizing AI-generated images, voice cloning, and highly targeted phishing—identifying them manually is harder than ever. SPOT acts as a first line of defense. 

Users can seamlessly forward suspicious content (a dubious WhatsApp message, an odd voice note from an "official", or a screenshot of an investment platform) directly to the SPOT Telegram bot. The bot acts as a forensic scam detection engine:
1. **Multimodal Analysis:** It analyzes the text, image, or audio to detect subtle scam indicators.
2. **Contextual Verdict:** It returns a clear verdict (`SAFE`, `SUSPICIOUS`, or `HIGH_RISK`) along with a confidence score and a breakdown of the identified threat (e.g., Government Impersonation, Pig-Butchering).
3. **Actionable Reporting:** If flagged as a scam, users can invoke the `/report` command. SPOT will automatically generate a formal, well-structured draft police report summarizing the incident, ready for submission to the Singapore Police Force (SPF).

## Key Features:
- Focuses on targetting AI image based scams where scammers may utilise AI to generate fake images
- 


## How It Works:
The telegram bot uses REKA API to analyse the image. The bot returns a confidence scoring of the scam as well as the explainment based on its verdict.
It is capable of drafting a detailed explaination for submission, providing detailed information such as "" <<< which are useful information for the
police>>>

## Architecture:

```text
Scambot/
├── backend/
│   ├── main.py                           
│   ├── services/
│   │   ├── reka_client.py           # Reka Vision (image → text)
│   │   ├── audio_converter.py       # 
│   │   ├── rag
│   │   │   ├──  knowledge_base.py
│   │   │   ├──  retriever.py
│   │   ├── utils
│   │   │   ├── formatter.py 
├── handlers/
│   ├── help.py                    # 
│   ├── image.py                   #
│   ├── report.py                  #
│   ├── start.py                   #
│   ├── text.py                    #
│   └── voice.py                   #
├── requirement.txt
└── Dockerfile
```

## Tech Stack:
- Backend: Python 3.11+
- Frontend: 
- AI: Reka Vision


