import os
from pydub import AudioSegment
from pydub.utils import which
import io

# pydub shells out to ffmpeg. The Conda ffmpeg is missing VC++ runtime DLLs on
# this machine, so we point pydub at the standalone build we extracted to C:\ffmpeg.
_FFMPEG_DIR = r"C:\ffmpeg\ffmpeg-8.1.1-full_build\bin"
if os.path.isdir(_FFMPEG_DIR):
    AudioSegment.converter = os.path.join(_FFMPEG_DIR, "ffmpeg.exe")
    AudioSegment.ffmpeg = os.path.join(_FFMPEG_DIR, "ffmpeg.exe")
    AudioSegment.ffprobe = os.path.join(_FFMPEG_DIR, "ffprobe.exe")
    # Also put the dir on PATH for any subprocess pydub spawns
    os.environ["PATH"] = _FFMPEG_DIR + os.pathsep + os.environ.get("PATH", "")


def convert_to_wav(audio_bytes: bytes) -> bytes:
    """Convert an OGG/Opus voice note (or any ffmpeg-readable format) to WAV bytes."""
    audio = AudioSegment.from_file(io.BytesIO(audio_bytes))
    wav_buf = io.BytesIO()
    audio.export(wav_buf, format="wav")
    return wav_buf.getvalue()