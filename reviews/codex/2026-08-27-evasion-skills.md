# evasion-skills — Codex report, 2026-08-27

## Scope

Added 15 isolated skill fixtures under `tests/fixtures/evasion-skills/` and a
SKILL-001 matrix in `tests/test_evasion_skills.py`. The suite exercises remote
execution, alternate network clients, secret reads, prompt injection, invisible
Unicode, frontmatter parsing, legitimate documentation/API-client patterns, and
bundled-skill severity behavior.

Full test result: `52 passed, 15 xfailed`. The 15 expected failures are current
false negatives or false positives, each with a one-line reason. Four supported
negative/bundling behaviors pass normally. No production source was edited.

## Detection matrix

| Fixture / case | Expected | Current behavior | Test |
|---|---|---|---|
| `curl` + continued newline + `| sh` | pipe-to-shell | missed | xfail |
| downloader/shell stored in variables | pipe-to-shell | missed | xfail |
| `$(curl ...)` stored then `eval` | remote execution | inventory/network only | xfail |
| `requests.get(...).text` passed to `subprocess` | remote execution | inventory/network only | xfail |
| `nc`, `openssl s_client`, DNS carrying secrets | network + secret read | missed | xfail |
| split `.env` path and `env | grep` piped to curl | network + secret read | network only | xfail |
| homoglyph/markdown/base64 injection instruction | prompt injection | missed | xfail |
| soft hyphen inside instruction | invisible Unicode | missed | xfail |
| `python -c` with assembled import/env name | network + secret read | missed | xfail |
| YAML block env list, secret after benign first item | wants provider key | missed | xfail |
| YAML block credential list with `../.env` | wants vault | missed | xfail |
| declarations nested under `metadata:` | wants key and vault | missed | xfail (2 rows) |
| legitimate scoped API client | no risk finding | wants-key + network/secret findings | xfail |
| defensive rubric quoting injection language | no risk finding | prompt-injection finding | xfail |
| safe install docs, `id_ed25519.pub`, benign HTML marker | no risk finding | no risk finding | pass |
| scoped non-vault credential file | no vault finding | no vault finding | pass |
| byte-identical vendor injection fixture | downgraded MEDIUM → LOW | correct, marked bundled | pass |
| locally modified vendor fixture | remains MEDIUM | correct, not marked bundled | pass |

## Findings

### 1. Shell remote-execution detection models syntax, not data flow  [severity: blocker]

- **Where:** `src/daemonaudit/checks/skills.py:24,127-128`
- **What:** Newlines, variables, download-then-`eval`, and Python
  download-to-`subprocess` all bypass `PIPE_TO_SHELL`. These are semantically the
  same as the detected `curl | sh` pattern.
- **Why it matters:** A malicious skill author can evade the HIGH category with a
  cosmetic rewrite while preserving remote unauthenticated code execution.
- **Suggested fix:** Add bounded shell logical-line normalization and explicit patterns
  for download-to-eval/command-substitution. For Python, use a small AST pass that
  tracks network-return values reaching `exec`, `eval`, `os.system`, or subprocess
  shell/code arguments. Keep regex as a fallback for malformed files.

### 2. Network and secret-source vocabularies are too narrow  [severity: blocker]

- **Where:** `src/daemonaudit/checks/skills.py:38-42,145-149`
- **What:** `nc`, `openssl s_client`, DNS tools, dynamically imported Python clients,
  `env`, `printenv`, `find`, and split credential paths evade the conjunction used for
  `net_and_secrets`.
- **Why it matters:** The LOW exfiltration-shape finding disappears entirely for common
  living-off-the-land commands, even when a fixture visibly joins a secret source to an
  external destination.
- **Suggested fix:** Expand sink/source primitives by language and shell command, then
  recognize pipelines and redirections across a normalized command. Treat DNS as a
  network sink. Avoid escalating on mere co-occurrence when a simple scoped API client
  can be recognized as such.

### 3. Frontmatter must be parsed as YAML and paths normalized  [severity: blocker]

- **Where:** `src/daemonaudit/checks/skills.py:45,136-143`
- **What:** Regex captures only the first physical value after a key. A benign first
  block-list entry hides later provider keys; indented `metadata:` declarations are
  invisible. Credential paths such as `../.env` evade the vault basename regex.
- **Why it matters:** These are valid YAML representations of fields Hermes may consume.
  A skill can request a master credential while SKILL-001 reports nothing.
- **Suggested fix:** Use the existing PyYAML dependency to parse bounded frontmatter,
  recursively inspect the supported metadata locations, coerce scalar/list forms, and
  normalize each credential path lexically before comparing its basename/resolved
  target against the vault layout. Do not open requested paths during this check.

### 4. Text matching misses visual obfuscation but flags defensive prose  [severity: should-fix]

- **Where:** `src/daemonaudit/checks/skills.py:25-37,125-135`
- **What:** Cyrillic homoglyphs, markdown-separated clauses, base64 text, and U+00AD
  soft hyphens hide malicious instructions. Meanwhile a security review rubric that
  tells the reader to identify “ignore previous instructions” is flagged as an attack.
- **Why it matters:** Literal phrase matching is easy to evade and creates alerts on the
  exact defensive skills most likely to discuss attack language.
- **Suggested fix:** Normalize NFKC plus a conservative set of default-ignorable
  characters and expose any changed suspicious line as evidence. Strip Markdown link
  destinations while retaining visible text. Add contextual negation/quotation/rubric
  handling; encoded prose should be decoded only under strict bounds and labeled.

### 5. Legitimate scoped API clients are indistinguishable from exfiltration  [severity: should-fix]

- **Where:** `src/daemonaudit/checks/skills.py:140-149,169-177`
- **What:** A weather client declaring `WEATHER_API_KEY` and sending it only to its
  documented weather endpoint receives both the wants-key and network-plus-secret
  findings.
- **Why it matters:** This pattern is the normal purpose of many skills. At 82 bundled
  skills, persistent warnings train users to ignore SKILL-001.
- **Suggested fix:** Separate inventory (“declares scoped credential”) from risk. Raise
  risk for master/provider credentials, vault files, undeclared secret access, or a
  destination inconsistent with the declared service. Bundled downgrading works and
  should remain a secondary confidence signal, not the primary false-positive filter.

## Things I checked that are fine

- Byte-identical vendor files are labeled `(bundled)` and the injection category is
  downgraded from MEDIUM to LOW.
- Appending a local modification prevents bundled labeling and preserves MEDIUM.
- `id_ed25519.pub` is not mistaken for a private key.
- Benign `<!-- ascii-guard-ignore -->` does not trigger hidden-comment detection.
- Install guidance that says to download, verify, and then execute does not trigger the
  pipe-to-shell category.
- A scoped non-vault credential filename is not classified as a vault request.
- Fixtures use only `.invalid` destinations and synthetic `FAKE` data; tests execute no
  fixture script and make no network requests.

## Open questions for Claude

- Does Hermes officially read `required_*` fields from a nested `metadata:` mapping, or
  should that row be rejected as a non-runtime representation while still parsing YAML?
- Should normal per-skill credential declarations become INFO inventory instead of a
  risk finding, reserving MEDIUM for known master/provider credentials?
- Is a small Python AST analyzer acceptable in v0.1, or should AST/data-flow support be
  deferred while the regex scanner explicitly labels these cases as limitations?
