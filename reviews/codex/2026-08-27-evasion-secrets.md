# evasion-secrets — Codex report, 2026-08-27

## Scope

Added an adversarial secret corpus under `tests/fixtures/evasion/` and its test
matrix in `tests/test_evasion_secrets.py`. The corpus covers line continuation,
base64/hex storage wrappers, YAML folded scalars, null-interleaved sqlite bytes,
URL userinfo, exported env values, quoted escapes, Unicode look-alikes,
lowercase opaque tokens, provider classification, and documented non-secrets.

All credential values are synthetic. Provider-shaped values use `FAKE` in the
credential body where their alphabet permits it; strict lowercase hexadecimal
formats have an adjacent `FAKE` fixture comment. The encoded carriers decode to
values containing `FAKE`.

Test result: `28 passed, 10 xfailed`. Every current miss or misclassification is
an expected failure with a one-line reason; supported and negative cases are
ordinary passing assertions.

## Detection matrix

| Fixture / case | Expected classification | Current behavior | Test |
|---|---|---|---|
| shell line-continuation OpenAI key | `openai-api-key`, reconstructed value | truncated fragment classified `generic-credential` | xfail |
| base64-wrapped OpenAI key | `openai-api-key` after decoding | no hit | xfail |
| hex-wrapped Anthropic key | `anthropic-api-key` after decoding | no hit | xfail |
| YAML folded bearer scalar | `bearer-token`, folded value | no hit | xfail |
| null-interleaved GitHub token in sqlite-like page | `github-token` after null normalization | no hit | xfail |
| quoted backslash inside OpenAI key | `openai-api-key`, unescaped value | truncated fragment classified `generic-credential` | xfail |
| fullwidth underscore in GitHub prefix | `github-token` after Unicode normalization | whole value classified `generic-credential` | xfail |
| lowercase opaque `SERVICE_TOKEN` | `generic-credential` | rejected by `_looks_random()` | xfail |
| Azure OpenAI key | `azure-openai-api-key` | `generic-credential` | xfail |
| Google OAuth client secret | `google-oauth-client-secret` | `generic-credential` | xfail |
| `export ANTHROPIC_API_KEY=...` | `anthropic-api-key` | correct | pass |
| `https://user:token@host` | `url-embedded-credential` | correct | pass |
| authorization bearer value | `bearer-token` | correct | pass |
| Discord bot token | `discord-bot-token` | correct | pass |
| OpenRouter key | `openrouter-api-key` | correct | pass |
| Slack app token | `slack-app-token` | correct | pass |
| documentation examples, `${VAR}`, `op://`, angle-bracket placeholder, `changeme` | no hit | no hit | pass |

## Findings

### 1. Transformations need bounded, format-aware normalization  [severity: should-fix]

- **Where:** `src/daemonaudit/redact.py:113-130`; `tests/test_evasion_secrets.py`
- **What:** Direct regex scanning misses base64, hex, YAML folding, and null-interleaved
  text. Backslash/line-continuation cases are worse than a clean miss: the generic
  pattern reports a truncated fragment, which creates a misleading fingerprint and
  display value that will not correlate with the actual credential.
- **Why it matters:** These representations occur naturally in databases, serialized
  config, shell env files, and copied credentials. An attacker can also select them
  deliberately to evade both findings and `scrub()`.
- **Suggested fix:** Add bounded decoding/normalization passes with provenance and
  strict size/expansion limits. Start with null-interleaved ASCII/UTF-16 detection and
  shell/YAML logical-value reconstruction. Treat base64/hex decoding more cautiously:
  require credential context or a decoded provider prefix to control false positives.
  Deduplicate normalized hits against direct spans by fingerprint.

### 2. Entropy filtering rejects plausible lowercase credentials  [severity: should-fix]

- **Where:** `src/daemonaudit/redact.py:82-89`; `tests/fixtures/evasion/lowercase-token.env`
- **What:** `_looks_random()` requires at least two digits and then uppercase or four
  digits. A long lowercase opaque token with two digits is rejected even when assigned
  to `SERVICE_TOKEN`.
- **Why it matters:** Case and digit composition are issuer choices, not reliable
  evidence that a value is non-secret. The current rule trades away contextual,
  high-confidence assignments to avoid English-word prefix false positives.
- **Suggested fix:** Score provider-prefix and assignment-context matches separately.
  For generic credential assignments, accept sufficiently long lowercase alphanumeric
  values using an entropy/repetition check; retain stricter heuristics for unlabelled
  broad prefix patterns. Keep placeholder/reference suppression as a separate step.

### 3. Provider-shaped values fall back to generic classification  [severity: should-fix]

- **Where:** `src/daemonaudit/redact.py:31-65`; `tests/fixtures/evasion/providers.env`
- **What:** Azure OpenAI and Google OAuth client values are detected only because their
  variable names contain generic keywords. A Unicode-obfuscated GitHub prefix likewise
  falls through to generic detection.
- **Why it matters:** Generic classification loses provider-specific rotation advice
  and blast-radius grouping, and the same value is missed when it appears without a
  recognized assignment name.
- **Suggested fix:** Add provider-specific contextual patterns for Azure and Google
  OAuth, then normalize safe Unicode compatibility characters before matching known
  prefixes. Preserve the original text only long enough to calculate spans; findings
  must still receive redacted values only.

### 4. Finding patterns and emergency output scrubbing need different risk tolerances  [severity: should-fix]

- **Where:** `src/daemonaudit/redact.py:133-140`
- **What:** `scrub()` still calls `find_secrets()`, so every detector false negative is
  also an output-redaction false negative. Broadening finding detection enough to make
  scrubbing safe would create noisy audit findings for encoded blobs and session data.
- **Why it matters:** False positives are tolerable in a last-ditch output sanitizer but
  costly in security findings; one shared pattern/heuristic set cannot optimize both.
- **Suggested fix:** Introduce a broader scrub-only pattern/normalization set that
  replaces suspicious credential-shaped values without emitting findings. Keep the
  provider-aware, higher-confidence detector for classification. Add paired tests where
  a value is intentionally not a finding but must still disappear from rendered output.

## Things I checked that are fine

- Existing structural support correctly recognizes current OpenRouter, Discord bot,
  Slack app, bearer, and URL-userinfo cases in the corpus.
- `export KEY=...` requires no special handling; the assignment regex finds the value.
- Placeholder filtering handles example wording, `${VAR}` references, `op://` refs,
  angle-bracket instructions, and `changeme` in the negative fixture.
- Each xfail is narrow and non-strict: it documents one expected kind/value pair, so a
  detector improvement becomes an XPASS rather than breaking unrelated matrix rows.
- The sqlite fixture is stored as base64 because it represents binary bytes; the test
  decodes it to an `SQLite format 3` page containing a null-interleaved FAKE GitHub token
  before calling `find_secrets()`.
- No production source file was edited for C2.

## Open questions for Claude

- Should decoding live in `find_secrets()` itself, or should file scanners supply
  format-derived candidate streams plus provenance?
- For normalized/decoded values, does the model need evidence metadata such as
  `encoding=base64` without ever retaining the raw value?
- Which Azure credential families are in M2 scope: Azure OpenAI API keys only, or also
  Entra client secrets and storage/account keys?
