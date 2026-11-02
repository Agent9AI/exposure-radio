# Third-party notices

Exposure Radio's source code is MIT licensed. The data snapshots and optional
components below keep their own terms.

- **CISA Known Exploited Vulnerabilities catalogue.** `data/feeds/kev.json` is the
  public catalogue, version 2026.10.30, from
  https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json.
  Catalogue dates and required-action text are reported as CISA's own values and are
  kept apart from the configured internal deadlines.
- **FIRST EPSS.** `data/feeds/epss.json` and `epss-2026-10-29.json` hold Exploit
  Prediction Scoring System scores published by FIRST (https://www.first.org/epss/),
  produced by Empirical Security. Attribution and usage guidance:
  https://www.first.org/epss/data.html. The `feeds refresh` command downloads the
  daily file from the URL FIRST publishes.
- **Tenable Research publications.** `data/feeds/tenable_research.json` lists titles
  and URLs of public Tenable blog posts; no article text is stored.
- **Kokoro-82M** (Apache-2.0, https://huggingface.co/hexgrad/Kokoro-82M). The
  committed sample was synthesised with the community ONNX export
  (`model_quantized.onnx`, sha256 `fbae9257…1478`) and the `af_heart` voice. Model
  weights and voices are not included in this repository.
- **misaki** (Apache-2.0) grapheme-to-phoneme conversion, **kokoro-onnx** (MIT)
  tokeniser vocabulary, **onnxruntime** (MIT), **numpy** (BSD), **soundfile** (BSD)
  and **FFmpeg** (LGPL/GPL, used as an external binary) are optional audio
  dependencies. None is required to run the core, the tests or to play the sample.
- **anthropic** Python SDK (MIT) is an optional dependency of the opt-in analyst
  agent.

Every hostname, address, asset identifier, owner and finding in the demonstration
tenants was generated for the synthetic scenario. No customer export is included.
