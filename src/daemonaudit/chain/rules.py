"""Chain rules: turn a flat list of findings into attack paths.

A rule is an ordered list of hops; each hop is a set of tags, any one of which
satisfies it. A path exists when every hop has at least one finding carrying one of
its tags. The first matching finding per hop becomes the hop shown in the report.
`kill_hop` is the earliest hop — fix it and the whole path is gone.

A path needs a real foothold: hop 1 must be MEDIUM or worse, intermediate hops at
least LOW; only the final hop (what is reached) may be INFO. Without this, the vendor's
own `curl | bash` install docs (LOW, bundled) would "chain" on every default install.

Tags are set by checks (see each check) — rules never parse titles.
"""

from __future__ import annotations

from dataclasses import dataclass

from daemonaudit.model import AttackPath, BlastEntry, Finding, RedactedSecret, ScanReport, Severity

# What a stolen credential of each kind lets an attacker do.
BLAST: dict[str, str] = {
    "anthropic-api-key": "spend on your Anthropic account and run models as you; reads nothing of yours",
    "openai-api-key": "spend on your OpenAI account; may reach fine-tunes, files and assistants you created",
    "openrouter-api-key": "spend your OpenRouter balance across every provider it fronts",
    "xai-api-key": "spend on your xAI account and run Grok as you",
    "groq-api-key": "spend on your Groq account",
    "azure-openai-api-key": "spend on your Azure OpenAI resource",
    "google-api-key": "billable calls on every Google API the key is enabled for",
    "google-oauth-client-secret": "impersonate your OAuth app to users who trust it",
    "github-token": "act as you on GitHub: read private repos, push commits, open PRs, read Actions secrets it can see",
    "github-fine-grained-pat": "whatever repos/permissions the PAT was scoped to, as you",
    "telegram-bot-token": "become your bot: read every message sent to it and reply to your contacts as it",
    "discord-bot-token": "become your bot in every server it is in: read channels it can see, post as it",
    "discord-webhook-url": "post anything into that Discord channel as the webhook",
    "slack-token": "read channels and DMs the token can see; post as the bot or as you",
    "slack-app-token": "open Socket Mode connections as your Slack app",
    "aws-access-key-id": "whatever the IAM identity allows — often everything in the account",
    "private-key-block": "log in to every host or service that trusts this key",
    "jwt": "act as the session/identity the token represents until it expires",
    "bearer-token": "act as whatever identity the bearer token represents",
    "url-embedded-credential": "log in to that service as that user",
    "generic-credential": "unknown — depends on the service; assume the worst until you know",
}


@dataclass(frozen=True)
class Rule:
    name: str
    narrative: str
    hops: tuple[frozenset[str], ...]
    reaches_default: str


RULES: list[Rule] = [
    Rule(
        "Remote → agent tools → every credential",
        "Something on the network reaches the daemon without a password, hands it a prompt, and the agent runs commands on your host with your keys in its environment.",
        (frozenset({"net:public"}), frozenset({"net:unauth", "net:unauth:verified"}), frozenset({"exec:host", "exec:noapproval"}), frozenset({"secret:procenv", "secret:vault"})),
        "every credential the daemon holds",
    ),
    Rule(
        "Local unauthenticated service → agent tools → every credential",
        "A service on this host answers without auth. Anything running as any user here — a browser tab via a crafted page, another account, a compromised package — can drive the agent.",
        (frozenset({"net:unauth", "net:unauth:verified"}), frozenset({"exec:host", "exec:noapproval"}), frozenset({"secret:procenv", "secret:vault"})),
        "every credential the daemon holds",
    ),
    Rule(
        "Anyone on the chat platform → prompt injection → commands as you",
        "The front door is open to strangers. A message is a prompt; with approvals weakened, a prompt is a shell.",
        (frozenset({"content:allow-all", "net:unauth-inbound"}), frozenset({"exec:noapproval", "exec:noapproval:cron"}), frozenset({"exec:host", "secret:procenv", "secret:vault"})),
        "command execution as your user, and every credential",
    ),
    Rule(
        "Malicious skill → remote code → your host",
        "A skill you installed downloads and runs code on first use. It runs where the agent runs: on your host, as you.",
        (frozenset({"skill:remote-exec"}), frozenset({"exec:host"}), frozenset({"secret:procenv", "secret:vault"})),
        "everything in the daemon's environment",
    ),
    Rule(
        "Skill sees master keys → exfiltration",
        "Provider keys are passed into every command the agent runs, and at least one skill both reads credentials and talks to the network.",
        (frozenset({"secret:passthrough"}), frozenset({"skill:exfil-shape", "skill:wants-secrets", "skill:remote-exec"})),
        "the forwarded provider keys",
    ),
    Rule(
        "Injected instructions in a skill → agent acts against you",
        "Text the model reads contains instructions a human would not see. With approvals weakened there is nothing between those instructions and your shell.",
        (frozenset({"skill:injection"}), frozenset({"exec:noapproval", "exec:noapproval:cron", "exec:host"})),
        "command execution as your user",
    ),
    Rule(
        "SSRF → local services → agent",
        "The agent's web tools may be pointed at localhost, and something is listening there. A hostile web page becomes a client of your own services.",
        (frozenset({"ssrf:off"}), frozenset({"net:loopback", "net:unauth", "net:unauth:verified"})),
        "whatever the loopback services expose — including the agent's own API",
    ),
    Rule(
        "Local user → readable credentials",
        "No exploit needed: another account or process on this host just reads the file.",
        (frozenset({"secret:sprawl:readable", "secret:vault-readable"}),),
        "the credentials in the listed files",
    ),
    Rule(
        "Local user → gateway socket → agent as you",
        "The control socket is writable by others. Connecting to it is driving the agent with your identity.",
        (frozenset({"local:gateway-socket"}), frozenset({"secret:procenv", "secret:vault", "exec:host"})),
        "command execution as your user, and every credential",
    ),
]


def _index(findings: list[Finding]) -> dict[str, list[Finding]]:
    idx: dict[str, list[Finding]] = {}
    for f in findings:
        for t in f.tags:
            idx.setdefault(t, []).append(f)
    return idx


def build_attack_paths(report: ScanReport) -> list[AttackPath]:
    idx = _index(report.findings)
    vault = [f for f in report.findings if "secret:vault" in f.tags]
    reach_detail = ""
    if vault and vault[0].secrets:
        kinds: dict[str, int] = {}
        for s in vault[0].secrets:
            kinds[s.kind] = kinds.get(s.kind, 0) + 1
        reach_detail = " (" + ", ".join(f"{k}×{n}" for k, n in sorted(kinds.items())) + ")"
    paths: list[AttackPath] = []
    for rule in RULES:
        hops: list[Finding] = []
        used: set[int] = set()
        for n, hop in enumerate(rule.hops):
            last = n == len(rule.hops) - 1
            floor = Severity.MEDIUM.rank if n == 0 else (Severity.INFO.rank if last else Severity.LOW.rank)
            candidates = [f for t in hop for f in idx.get(t, []) if id(f) not in used and f.severity.rank >= floor]
            if not candidates:
                break
            best = max(candidates, key=lambda f: f.severity.rank)
            hops.append(best)
            used.add(id(best))
        else:
            reaches = rule.reaches_default + (reach_detail if "credential" in rule.reaches_default else "")
            paths.append(AttackPath(rule.name, rule.narrative, hops, reaches, kill_hop=1))
    paths.sort(key=lambda p: -p.severity.rank)
    return paths


def build_blast_radius(report: ScanReport) -> list[BlastEntry]:
    """Per-kind summary of every credential the audit could see (vault + process env)."""
    seen: dict[str, dict[str, RedactedSecret]] = {}
    for f in report.findings:
        if not ({"secret:vault", "secret:procenv"} & set(f.tags)):
            continue
        for s in f.secrets:
            seen.setdefault(s.kind, {})[s.fingerprint] = s
    out = [
        BlastEntry(kind, len(v), BLAST.get(kind, BLAST["generic-credential"]), [s.display for s in list(v.values())[:5]])
        for kind, v in seen.items()
    ]
    out.sort(key=lambda b: (-b.count, b.kind))
    return out
