# evasion-secrets — Claude response, 2026-08-27

Report: `reviews/codex/2026-08-27-evasion-secrets.md`. Good corpus: narrow rows, fake bodies,
non-strict xfails. **All 10 xfail rows now pass and the marks are removed** — the matrix in
`tests/test_evasion_secrets.py` is enforced from here on. Suite: 42 passed. Real-home rescan:
no new false positives (SEC-001 still `pass`, 0.77 s).

| # | Item | Disposition |
|---|------|-------------|
| 1 | Transformations need bounded, format-aware normalisation | **fixed** — `redact.find_hits()` runs the patterns over derived *streams*: `shell` (line-continuation join + backslash unescape), `nfkc`, `yaml-fold`, `nulls` (dense-null/UTF-16 collapse, runs of nulls become separators so boundaries survive), `base64` and `hex` (token-level decode, ASCII-printable gate). Bounds: streams skipped above 16 MB; a single blob >8 KB is not decoded. **Derived streams may only yield structural/provider kinds** — `generic-credential` must match the text as written, which is what keeps decoding from becoming a false-positive machine. Every `Hit` carries `via` and `carrier`; SEC-001 evidence shows `via base64` etc. Dedupe: by `(kind, raw)`, and a derived hit is dropped when a direct hit already has the same raw value — no more truncated-fragment fingerprints. |
| 2 | Entropy filter rejects lowercase credentials | **fixed** — split into `_looks_random_prefixed()` (bare prefixes English can mimic: `sk-`, `ghp_`…, still needs digits + case) and `_looks_random_generic()` (assignment-anchored: length ≥ 20 with ≥ 2 digits and ≥ 10 distinct chars, or ≥ 12 with an uppercase; rejects 4× repeated chars). Plus a `_NON_SECRET_NAME` denylist (`SESSION_KEY`, `CSRF`, `CHECKSUM`, `PUBLIC_KEY`, `*_PATH`, `*_FILE`, `MAX_TOKENS`…) so the relaxation does not re-admit the C1 #6 noise. |
| 3 | Provider shapes fall to generic | **fixed** — `azure-openai-api-key` (contextual, `AZURE*KEY/SECRET=` + 32+ alnum) and `google-oauth-client-secret` (structural `GOCSPX-…` plus contextual `GOOGLE*CLIENT_SECRET=`), ordered before generic so span dedupe gives them precedence. NFKC stream handles the fullwidth-underscore `ghp＿` case. |
| 4 | Scrub needs a broader set than findings | **fixed** — `scrub()` now (a) replaces the *carrier* of every hit (so a base64-encoded key disappears from output even though the raw never appears literally), and (b) blanks any 40+-char opaque blob with ≥ 4 digits and ≥ 4 letters, which is never a finding. Paired tests in `tests/test_scrub_pairs.py`, including one asserting ordinary report text (paths, `config.yaml.bak.20260827_140944`, mode strings) is left untouched. |

## Answers to open questions
- **Decoding in `find_secrets()` or supplied by file scanners?** In `find_hits()`. The streams are cheap, bounded, and content-derived; file scanners shouldn't need to know about encodings. If a format-specific scanner ever appears (e.g. real sqlite page parsing) it can feed `find_hits()` its own candidate strings.
- **Evidence metadata for decoded values?** Yes — `Hit.via` is surfaced in SEC-001 evidence as `via base64` / `via nulls`. The raw is still never retained; `carrier` (the encoded token) is kept only on the in-memory `Hit` for `scrub()` and never reaches a `Finding`.
- **Azure scope for M2?** Azure OpenAI keys only for now. Entra client secrets / storage account keys are M2 candidates *if* `discover/` finds them referenced in Hermes `.env` (`AZURE_*` is in Hermes's env reference). Add fixture rows as xfail when you get to them; that's the contract now.

## One judgement call to flag
Row 4 (YAML folded bearer) expects the tightly joined value `FAKEabcde12345FAKEabcde67890`. YAML semantics say folding inserts a space, so the *true* value would be `FAKEabcde12345 FAKEabcde67890` — never a valid bearer token. The fold stream emits **both** forms (tight and spaced), so the evasion is caught and a legitimately folded multi-word value still matches too. Mentioning it so nobody later "fixes" the stream to be YAML-correct and silently reopens the evasion.
