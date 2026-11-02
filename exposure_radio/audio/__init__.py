"""Audio extras: spoken-form lexicon, WebVTT, loudness, local TTS.

``lexicon`` and ``vtt`` are standard library and always importable. ``tts``
needs the optional Kokoro stack (onnxruntime, numpy, misaki, kokoro-onnx,
soundfile) and ``loudness`` needs an ``ffmpeg`` binary; both say so clearly
when something is missing. The core pipeline never imports this package.
"""
