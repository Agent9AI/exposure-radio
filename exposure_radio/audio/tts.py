"""Local text-to-speech with Kokoro-82M (Apache-2.0) through onnxruntime.

Optional dependencies: ``numpy``, ``onnxruntime``, ``misaki[en]`` (G2P),
``kokoro-onnx`` (tokeniser vocabulary) and ``soundfile`` (WAV writing).
Weights are not bundled: point ``model_path`` at ``model_quantized.onnx``
(or the fp16/fp32 export) and ``voices_dir`` at a folder of ``*.bin`` style
vectors (510 x 256 float32) from the Kokoro release.
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Optional

SAMPLE_RATE = 24_000
MAX_TOKENS = 510


class TtsUnavailable(RuntimeError):
    pass


def _import_stack() -> Dict[str, Any]:
    try:
        import numpy as np  # type: ignore
        import onnxruntime as ort  # type: ignore
        from kokoro_onnx.tokenizer import Tokenizer  # type: ignore
        from misaki import en  # type: ignore
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise TtsUnavailable(
            "Kokoro TTS needs the optional packages: pip install onnxruntime numpy 'misaki[en]' kokoro-onnx soundfile"
        ) from exc
    return {"np": np, "ort": ort, "Tokenizer": Tokenizer, "en": en}


class KokoroSynth:
    def __init__(self, model_path: str, voices_dir: str, voice: str = "af_heart", speed: float = 1.0, threads: int = 4) -> None:
        stack = _import_stack()
        self.np = stack["np"]
        if not os.path.isfile(model_path):
            raise TtsUnavailable(f"Kokoro model not found: {model_path}")
        voice_path = os.path.join(voices_dir, f"{voice}.bin")
        if not os.path.isfile(voice_path):
            raise TtsUnavailable(f"voice file not found: {voice_path}")
        options = stack["ort"].SessionOptions()
        options.intra_op_num_threads = threads
        self.session = stack["ort"].InferenceSession(model_path, options, providers=["CPUExecutionProvider"])
        self.input_names = [i.name for i in self.session.get_inputs()]
        self.tokenizer = stack["Tokenizer"]()
        self.g2p = stack["en"].G2P(trf=False, british=False, fallback=None)
        self.voice = self.np.fromfile(voice_path, dtype=self.np.float32).reshape(-1, 1, 256)
        self.voice_name = voice
        self.speed = float(speed)
        self.model_path = model_path
        self.model_sha256 = _sha256(model_path)
        self.ort_version = stack["ort"].__version__

    def phonemize(self, text: str) -> str:
        phonemes, _tokens = self.g2p(text)
        return phonemes

    def synthesize(self, text: str) -> Any:
        """Return float32 samples at 24 kHz for one sentence."""
        np = self.np
        phonemes = self.phonemize(text)
        ids: List[int] = list(self.tokenizer.tokenize(phonemes))
        if not ids:
            return np.zeros(0, dtype=np.float32)
        if len(ids) > MAX_TOKENS:
            ids = ids[:MAX_TOKENS]
        style = self.voice[min(len(ids), self.voice.shape[0] - 1)].astype(np.float32)
        feed: Dict[str, Any] = {}
        token_array = np.array([[0] + ids + [0]], dtype=np.int64)
        for name in self.input_names:
            if name in ("input_ids", "tokens"):
                feed[name] = token_array
            elif name == "style":
                feed[name] = style
            elif name == "speed":
                feed[name] = np.array([self.speed], dtype=np.float32)
        audio = self.session.run(None, feed)[0]
        audio = np.asarray(audio, dtype=np.float32).reshape(-1)
        if not np.all(np.isfinite(audio)):
            raise RuntimeError("TTS produced non-finite samples; try another onnxruntime version or the fp32 model")
        return trim_silence(audio, np)

    def describe(self) -> Dict[str, Any]:
        return {
            "engine": "Kokoro-82M (ONNX)",
            "model_path": os.path.basename(self.model_path),
            "model_sha256": self.model_sha256,
            "voice": self.voice_name,
            "speed": self.speed,
            "onnxruntime": self.ort_version,
            "sample_rate": SAMPLE_RATE,
        }


def trim_silence(audio: Any, np: Any, threshold: float = 0.004, pad_seconds: float = 0.06) -> Any:
    if audio.size == 0:
        return audio
    loud = np.flatnonzero(np.abs(audio) > threshold)
    if loud.size == 0:
        return audio
    pad = int(pad_seconds * SAMPLE_RATE)
    start = max(0, int(loud[0]) - pad)
    end = min(audio.size, int(loud[-1]) + pad)
    return audio[start:end]


def _sha256(path: str) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def write_wav(path: str, audio: Any, np: Any) -> None:
    """16-bit PCM mono WAV without third-party packages."""
    import struct
    import wave

    clipped = np.clip(audio, -1.0, 1.0)
    pcm = (clipped * 32767.0).astype(np.int16)
    with wave.open(path, "wb") as handle:
        handle.setnchannels(1)
        handle.setsampwidth(2)
        handle.setframerate(SAMPLE_RATE)
        handle.writeframes(pcm.tobytes())
    _ = struct  # kept for symmetry with other writers; wave handles headers


def env_default(name: str, fallback: Optional[str]) -> Optional[str]:
    return os.environ.get(name) or fallback
