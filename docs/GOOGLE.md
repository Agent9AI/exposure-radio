# Google services: bring your own account

Exposure Radio is MIT-licensed and ships **no Google keys, no shared quota and no
proxy**. Each station operator connects their own Google account and accepts
Google's terms directly. Without Google, the station still works: local Kokoro
voices, the bundled house beats, keyless weather and CISA feeds.

| Service | What it adds | Cost | Key |
|---|---|---|---|
| Gemini API (text) | Suggests trending Learn topics for an operator to approve | Free tier available | `GEMINI_API_KEY` |
| Gemini 3.8 Flash TTS | Two-host broadcast voices | Free tier available; paid $9 per 1M audio tokens until 31 Dec 2026 | same key |
| Lyria 3.5 | Generated instrumentals for the music rotation | $0.08 per song, no free tier | same key |
| YouTube IFrame Player | Your own playlists, played in the official embedded player | Free | none |

Prices are from Google's pricing page as of 3 Nov 2026. Check
<https://ai.google.dev/gemini-api/docs/pricing> before you budget. Paid TTS prices
double on 1 Jan 2027.

## The data rule

Google's pricing page states that content sent on the **free tier is used to
improve Google products**. Content sent on the **paid tier is not**. So:

- **Public desks** (news, weather, Learn) contain public information only. They may use a free-tier key.
- **Exposure desks** (priority, watch list, wins, blind spots) are about your network. Voice them
  with local Kokoro, or with Gemini only on a **billing-enabled (paid) project**. Set
  `"gemini": {"tier": "paid"}` in the station settings to allow it. With `"tier": "free"`, the
  station voices exposure segments locally and says so in the console.

Exposure segments never send asset names, IP addresses or owners anywhere. The spoken
script contains counts and product names only, and passes the claim gate before any
voice engine sees it.

## Using a Google AI Pro subscription

Google AI Pro is a consumer subscription for the Gemini app. On its own it does not
create an API key. Google now bundles Google Developer Program premium benefits with
it, including a **monthly Google Cloud credit ($10 a month with AI Pro)**. That credit
can pay for a billing-enabled Gemini API project, which also puts you on the paid tier
described above.

1. Subscribe to Google AI Pro at <https://one.google.com/about/google-ai-plans/> with a personal Google account.
2. Join the Google Developer Program at <https://developers.google.com/program> with the same account, open **My benefits**, and activate the Google Cloud credit. Pick or create a Cloud billing account when prompted.
3. In <https://console.cloud.google.com/>, create a project (for example `exposure-radio`) and link it to that billing account.
4. In Google AI Studio, <https://aistudio.google.com/apikey>, create an API key **in that project**.
5. On the station host, run `python3 -m exposure_radio station keys set gemini` and paste the key. It is stored in the host's private settings file (mode 600), never in the browser or the repository.
6. In the console, open **Connections**, set Gemini to **Paid project**, and choose which desks may use Gemini voices.

Credits and benefits vary by country and can change. A Google AI Developers forum thread
reports that these credits cannot fund AI Studio *prepaid* balances. Use a billing-enabled
Cloud project as above.

### What $10 a month buys (assessed)

Gemini TTS bills about 25 audio tokens per second of speech. At $9 per million:

| Use | Speech | Approximate cost |
|---|---|---|
| One four-minute exposure briefing | 240 s | $0.05 |
| A briefing every weekday for a month | ~88 min | $1.20 |
| Every desk voiced, eight hours a day, five days a week | ~2 h/day of speech | ~$35 a month (over the credit) |

Set the station's daily cloud-voice limit (`voices.cloud_seconds_per_day`, default 900)
so Gemini voices only the segments you choose and the rest fall back to Kokoro. The
station never raises a limit by itself.

## YouTube, played the legitimate way

The station plays YouTube only through the official
[IFrame Player API](https://developers.google.com/youtube/iframe_api_reference), within the
[Required Minimum Functionality](https://developers.google.com/youtube/terms/required-minimum-functionality)
rules:

- The video stays visible, at least 200 by 200 pixels, with nothing drawn over it.
- Autoplay waits until more than half of the player is on screen, and only one YouTube player autoplays at a time.
- The station never downloads YouTube media, strips its audio, or plays it in the background.

When a YouTube item comes up in the rotation, the listener's visualizer window becomes
the video window. The house beats and Lyria tracks play as normal audio.

## Lyria, for music you own the rights to use

Lyria generates instrumentals from a text prompt. Generated audio carries a SynthID
watermark. Prompts should describe a style, not an artist ("dark trap instrumental,
150 BPM, gliding 808s, bell melody"). Read Google's terms for your use before you
publish anything generated. The bundled house beats are synthesized by
`scripts/make_beats.py` and are MIT licensed with the rest of the project.
