import io
import os
from pydub import AudioSegment
from pydub.utils import which


def _ensure_ffmpeg() -> None:
    """Point pydub at an ffmpeg binary.

    Prefer whatever is already on PATH (typical for Linux/macOS and the
    Docker image, which installs ffmpeg via apt). If ffmpeg is not on PATH
    (e.g. a bare Windows install), fall back to a known local build so the
    developer machine still works.
    """
    if which("ffmpeg") is not None:
        return

    _FFMPEG_DIR = r"C:\ffmpeg\ffmpeg-8.1.1-full_build\bin"
    if os.path.isdir(_FFMPEG_DIR):
        AudioSegment.converter = os.path.join(_FFMPEG_DIR, "ffmpeg.exe")
        AudioSegment.ffmpeg = os.path.join(_FFMPEG_DIR, "ffmpeg.exe")
        AudioSegment.ffprobe = os.path.join(_FFMPEG_DIR, "ffprobe.exe")
        # Also put the dir on PATH for any subprocess pydub spawns
        os.environ["PATH"] = _FFMPEG_DIR + os.pathsep + os.environ.get("PATH", "")


_ensure_ffmpeg()


def convert_to_wav(audio_bytes: bytes) -> bytes:
    """Convert an OGG/Opus voice note (or any ffmpeg-readable format) to WAV bytes.

    Output is 16kHz mono PCM: plenty of fidelity for scam/voice-pattern
    detection, and small enough to stay under Reka's 20MB upload cap for
    typical Telegram voice notes (vs. 44.1kHz stereo which can blow past it).
    """
    audio = AudioSegment.from_file(io.BytesIO(audio_bytes))
    audio = audio.set_channels(1).set_frame_rate(16000)
    wav_buf = io.BytesIO()
    audio.export(wav_buf, format="wav")
    return wav_buf.getvalue()
