# SPOT - Scan Pattern Observation & Tracking
Autonomous Telegram Bot designed to detect scams based on screenshots, text messages and voice recordings.

## Key Features:
- Focuses on targetting AI image based scams where scammers may utilise AI to generate fake images
- 


## How It Works:
The telegram bot uses REKA API to analyse the image. The bot returns a confidence scoring of the scam as well as the explainment based on its verdict.
It is capable of drafting a detailed explaination for submission, providing detailed information such as "" <<< which are useful information for the
police>>>

## Architecture:
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


## Tech Stack:
Backend: Python 3.11+
Frontend: 
AI: Reka Vision

