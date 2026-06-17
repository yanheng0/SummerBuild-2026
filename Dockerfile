
FROM python:3.11-slim

# ffmpeg is required by pydub (services/audio_converter.py) to decode
# Telegram's OGG/Opus voice notes and re-encode them as WAV for Reka.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "main.py"]