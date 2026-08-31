"""POL-001..010: Hermes policy configuration. Names of env vars are shown; values never are
(except booleans/modes that are policy, not secrets)."""

from __future__ import annotations

import re
from pathlib import Path

from daemonaudit.discover.hermes_config import PLATFORM_ENV, SECRET_NAME, HermesSettings, load_settings
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform, q
from daemonaudit.redact import find_hits, redact
from daemonaudit.registry import check

CFG = "config.yaml"


def _f(check_id: str, title: str, sev: Severity, pos: Position, asset: str, why: str, fix: str, verify: str | None = None, ev: list[str] | None = None, tags: list[str] | None = None) -> Finding:
    return Finding(check_id, title, sev, pos, asset, why, fix, verify, ev or [], tags=tags or [])


def _env_where(settings: HermesSettings, name: str) -> str:
    _, src = settings.env(name)
    return f"{name} ({src})"


# --- POL-001 approval bypasses -----------------------------------------------------------

_SERVICE_GLOBS = [
    "~/.config/systemd/user/*.service",
    "/etc/systemd/system/*hermes*",
    "/etc/systemd/system/*.service.d/*.conf",
    "~/Library/LaunchAgents/*hermes*.plist",
    "~/.bashrc", "~/.zshrc", "~/.profile", "~/.bash_profile", "~/.zprofile", "~/.config/fish/config.fish",
]


def _grep_startup_files(plat: Platform, out: CheckOutput, needle: re.Pattern[str]) -> list[str]:
    hits: list[str] = []
    for pattern in _SERVICE_GLOBS:
        base = Path(pattern).expanduser()
        for p in base.parent.glob(base.name):
            try:
                text = plat.read_nofollow(p, 1 << 20).decode("utf-8", "replace")
            except NotSupported:
                try:
                    text = p.read_text(errors="replace")
                except OSError:
                    continue
            except OSError:
                continue
            for i, line in enumerate(text.splitlines(), 1):
                if needle.search(line) and not line.lstrip().startswith("#"):
                    hits.append(f"{p}:{i}")
    return hits


@check("POL-001", "Dangerous-command approval bypassed (yolo / exec-ask off)", Position.CONTENT)
def approval_bypass(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    out.coverage_notes += s.notes
    vault = target.vault_path

    if s.env_truthy("HERMES_YOLO_MODE"):
        out.findings.append(_f("POL-001", "HERMES_YOLO_MODE is on — every dangerous command runs without approval",
            Severity.HIGH, Position.CONTENT, str(vault),
            "Yolo mode disables the approval prompt for rm -rf, chmod 777, curl|sh, service control and friends. "
            "Any prompt injection that reaches the agent becomes arbitrary command execution as your user.",
            f"Remove HERMES_YOLO_MODE from {vault} (or set it to 0) and restart the gateway.",
            f"grep -n HERMES_YOLO_MODE {q(vault)}  # expect nothing", [_env_where(s, "HERMES_YOLO_MODE")], ["exec:noapproval"]))
    if s.env_falsy("HERMES_EXEC_ASK"):
        out.findings.append(_f("POL-001", "HERMES_EXEC_ASK=false — gateway sessions never ask before executing",
            Severity.HIGH, Position.CONTENT, str(vault),
            "In gateway (chat platform) mode this is the only prompt between an injected instruction and a shell.",
            f"Remove HERMES_EXEC_ASK from {vault} (default is true).",
            f"grep -n HERMES_EXEC_ASK {q(vault)}", [_env_where(s, "HERMES_EXEC_ASK")], ["exec:noapproval"]))
    if s.env_truthy("HERMES_ACCEPT_HOOKS"):
        out.findings.append(_f("POL-001", "HERMES_ACCEPT_HOOKS is on — shell hooks are auto-approved",
            Severity.MEDIUM, Position.SUPPLY_CHAIN, str(vault),
            "Hooks are shell commands shipped with plugins/skills. Auto-accepting them means installing a skill is installing a script that runs on your host.",
            "Remove HERMES_ACCEPT_HOOKS; approve hooks individually.",
            f"grep -n HERMES_ACCEPT_HOOKS {q(vault)}", [_env_where(s, "HERMES_ACCEPT_HOOKS")]))

    startup = _grep_startup_files(plat, out, re.compile(r"HERMES_YOLO_MODE\s*=\s*(1|true|yes|on)|(^|\s)--yolo(\s|$)", re.I))
    if startup:
        out.findings.append(_f("POL-001", "Yolo mode is baked into a service unit or shell profile",
            Severity.HIGH, Position.CONTENT, startup[0].split(":")[0],
            "The daemon (or every interactive session) starts with approvals disabled, regardless of what .env says.",
            "Remove the --yolo flag / HERMES_YOLO_MODE export from the listed file(s); reload the unit or shell.",
            f"grep -nE 'HERMES_YOLO_MODE|--yolo' {' '.join(q(h.split(':')[0]) for h in startup[:5])}", startup[:10], ["exec:noapproval"]))
    return out


# --- POL-002 approvals config ------------------------------------------------------------

@check("POL-002", "Approval policy weakened in config", Position.CONTENT)
def approvals_config(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    s.require_config()  # config.yaml unparsable → skip, never a pass on defaults (AGENTS.md §4)
    cfg = str(target.home / CFG)
    mode = s.get("approvals.mode", "smart")
    if mode == "off":
        out.findings.append(_f("POL-002", "approvals.mode: off — dangerous commands are never gated",
            Severity.HIGH, Position.CONTENT, cfg,
            "Equivalent to permanent yolo mode, set in config instead of the environment.",
            "Set approvals.mode to smart (default) or manual in config.yaml.",
            f"grep -nA3 '^approvals:' {q(cfg)}", [f"approvals.mode: {mode}"], ["exec:noapproval"]))
    for key, label in (("approvals.cron_mode", "scheduled (cron) jobs"), ("approvals.single_query_mode", "one-shot -q sessions")):
        if s.get(key) == "approve":
            out.findings.append(_f("POL-002", f"{key}: approve — {label} auto-approve dangerous commands",
                Severity.MEDIUM, Position.CONTENT, cfg,
                f"Headless {label} have no human to ask, so 'approve' means anything they are tricked into is executed. The default is deny.",
                f"Set {key}: deny in config.yaml and allowlist specific commands instead.",
                f"grep -n {key.split('.')[-1]} {q(cfg)}", [f"{key}: approve"], ["exec:noapproval:cron"]))
    allow = s.get("command_allowlist") or s.get("approvals.allowlist") or []
    if isinstance(allow, list) and allow:
        broad = [a for a in allow if str(a).strip() in ("*", "**", ".*") or str(a).startswith(("rm ", "sudo", "curl", "bash", "sh "))]
        out.findings.append(_f("POL-002", f"{len(allow)} command pattern(s) are permanently pre-approved",
            Severity.MEDIUM if broad else Severity.INFO, Position.CONTENT, cfg,
            "Allowlisted patterns skip the approval prompt forever. Broad patterns (rm, sudo, curl, bash, wildcards) hand injection a free shell.",
            "Audit command_allowlist; remove anything broader than a specific command line.",
            f"grep -nA{len(allow)+1} command_allowlist {q(cfg)}",
            [str(a)[:60] for a in (broad or allow)[:10]]))
    if s.get("approvals.destructive_slash_confirm") is False:
        out.findings.append(_f("POL-002", "approvals.destructive_slash_confirm: false",
            Severity.LOW, Position.CONTENT, cfg,
            "/clear, /reset, /undo run without confirmation. Low impact, but it is a guard you turned off.",
            "Remove the key (default true).", None, ["approvals.destructive_slash_confirm: false"]))
    return out


# --- POL-003 execution sandbox ----------------------------------------------------------

@check("POL-003", "Agent executes directly on the host without a write boundary", Position.CONTENT)
def unsandboxed(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    s.require_config()  # config.yaml unparsable → skip, never a pass on defaults (AGENTS.md §4)
    backend = s.get("terminal.backend") or s.env("TERMINAL_ENV")[0] or "local"
    safe_root = s.env_set("HERMES_WRITE_SAFE_ROOT")
    cwd = s.get("terminal.cwd")
    if backend == "local" and not safe_root:
        out.findings.append(_f("POL-003", "terminal.backend: local with no HERMES_WRITE_SAFE_ROOT",
            Severity.MEDIUM, Position.CONTENT, str(target.home / CFG),
            "Tools run as your user on this machine with your whole home directory writable. Hermes blocks ~/.ssh, ~/.aws "
            "and its own vault, but everything else — your repos, your vault, your shell rc — is one convincing prompt away. "
            f"(terminal.cwd is {cwd!r}.)",
            f"Either terminal.backend: docker (with resource limits), or set HERMES_WRITE_SAFE_ROOT=<project dirs> in {target.vault_path} "
            "so write_file/patch cannot leave them.",
            f"grep -n HERMES_WRITE_SAFE_ROOT {q(target.vault_path)}; grep -n 'backend:' {q(target.home / CFG)}",
            [f"terminal.backend: {backend}", "HERMES_WRITE_SAFE_ROOT: unset"], ["exec:host"]))
    return out


# --- POL-004 who may talk to the agent -----------------------------------------------------

@check("POL-004", "Anyone may message the agent (allow-all users)", Position.CONTENT)
def allow_all_users(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    vault = str(target.vault_path)
    flags = ["GATEWAY_ALLOW_ALL_USERS"] + [v[2] for v in PLATFORM_ENV.values()]
    on = [n for n in flags if s.env_truthy(n)]
    if on:
        out.findings.append(_f("POL-004", f"{', '.join(on)} — any account on the platform can drive the agent",
            Severity.HIGH, Position.CONTENT, vault,
            "The chat platform is the agent's front door. Allow-all means strangers can send it instructions, "
            "and with tools enabled that is remote command execution gated only by the approval prompt.",
            f"Remove the allow-all flag(s) from {vault}; use GATEWAY_ALLOWED_USERS / <PLATFORM>_ALLOWED_USERS or DM pairing (hermes pairing).",
            f"grep -nE 'ALLOW_ALL_USERS' {q(vault)}  # expect nothing", [_env_where(s, n) for n in on], ["content:allow-all"]))
    if s.parse_error:
        out.note(s.parse_error)
    elif s.get("unauthorized_dm_behavior") not in (None, "pair", "ignore"):
        out.findings.append(_f("POL-004", f"unauthorized_dm_behavior: {s.get('unauthorized_dm_behavior')}",
            Severity.MEDIUM, Position.CONTENT, str(target.home / CFG),
            "Unknown value; Hermes expects pair or ignore.", "Set unauthorized_dm_behavior: pair.", None))
    return out


# --- POL-005 API server ------------------------------------------------------------------

@check("POL-005", "OpenAI-compatible API server exposed or unauthenticated", Position.REMOTE)
def api_server(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    vault = str(target.vault_path)
    if not s.env_truthy("API_SERVER_ENABLED"):
        return out
    host, _ = s.env("API_SERVER_HOST")
    host = (host or "127.0.0.1").strip()
    public = host not in ("127.0.0.1", "localhost", "::1")
    has_key = s.env_set("API_SERVER_KEY")
    if not has_key:
        out.findings.append(_f("POL-005", "API_SERVER_ENABLED without API_SERVER_KEY",
            Severity.CRITICAL if public else Severity.HIGH, Position.REMOTE, vault,
            "The API server accepts chat completions that run through the agent — tools included. Without a key, "
            + ("anything on the network can use it." if public else "any local process (browser tab via a crafted page, other users) can use it."),
            f"Set API_SERVER_KEY in {vault} to a long random value, restart the gateway.",
            f"grep -n API_SERVER_KEY {q(vault)}", [f"API_SERVER_HOST: {host}", "API_SERVER_KEY: unset"], ["net:unauth"] + (["net:public"] if public else [])))
    if public:
        out.findings.append(_f("POL-005", f"API_SERVER_HOST={host} — API server bound beyond loopback",
            Severity.HIGH if has_key else Severity.INFO, Position.REMOTE, vault,
            "Reachable from the network. A bearer key is the only thing between the internet and your agent's tools.",
            "Bind to 127.0.0.1 and reach it over SSH/Tailscale, or front it with an authenticating reverse proxy.",
            f"grep -n API_SERVER_HOST {q(vault)}", [f"API_SERVER_HOST: {host}"], ["net:public"]))
    cors, _ = s.env("API_SERVER_CORS_ORIGINS")
    if cors and cors.strip() in ("*", "'*'", '"*"'):
        out.findings.append(_f("POL-005", "API_SERVER_CORS_ORIGINS=* — any web page may call the API from your browser",
            Severity.MEDIUM, Position.CONTENT, vault,
            "With CORS wide open, a page you visit can drive the local API server (ClawJacked-style). A key helps only if the page cannot obtain it.",
            "Restrict API_SERVER_CORS_ORIGINS to the exact origin that needs it, or unset it.",
            f"grep -n API_SERVER_CORS_ORIGINS {q(vault)}", ["API_SERVER_CORS_ORIGINS: *"]))
    return out


# --- POL-006 webhooks & dashboard ----------------------------------------------------------

@check("POL-006", "Inbound webhook or dashboard without verification/auth", Position.REMOTE)
def webhooks_and_dashboard(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    vault = str(target.vault_path)
    if s.env_names_matching(r"^WHATSAPP_CLOUD_") and not s.env_set("WHATSAPP_CLOUD_APP_SECRET"):
        host, _ = s.env("WHATSAPP_CLOUD_WEBHOOK_HOST")
        out.findings.append(_f("POL-006", "WhatsApp Cloud webhook without WHATSAPP_CLOUD_APP_SECRET",
            Severity.HIGH, Position.REMOTE, vault,
            f"Inbound messages are not signature-verified, and the webhook binds to {host or '0.0.0.0 (default)'}. "
            "Anyone who finds the port can post messages 'from' any contact straight into the agent.",
            f"Set WHATSAPP_CLOUD_APP_SECRET in {vault}; bind WHATSAPP_CLOUD_WEBHOOK_HOST to 127.0.0.1 behind a TLS proxy.",
            f"grep -nE 'WHATSAPP_CLOUD_(APP_SECRET|WEBHOOK_HOST)' {q(vault)}", [f"WHATSAPP_CLOUD_WEBHOOK_HOST: {host or 'unset'}"], ["net:unauth-inbound"]))
    if s.env_set("TELEGRAM_WEBHOOK_URL") and not s.env_set("TELEGRAM_WEBHOOK_SECRET"):
        out.findings.append(_f("POL-006", "Telegram webhook mode without TELEGRAM_WEBHOOK_SECRET",
            Severity.HIGH, Position.REMOTE, vault,
            "Telegram echoes the secret back so you can tell real updates from forged ones. Without it, any HTTP client can inject messages.",
            f"Set TELEGRAM_WEBHOOK_SECRET in {vault} and re-register the webhook.",
            f"grep -n TELEGRAM_WEBHOOK_SECRET {q(vault)}", ["TELEGRAM_WEBHOOK_URL: set", "TELEGRAM_WEBHOOK_SECRET: unset"], ["net:unauth-inbound"]))
    if s.env_set("HERMES_DASHBOARD_PUBLIC_URL"):
        auth = s.env_names_matching(r"^HERMES_DASHBOARD_(BASIC_AUTH|OAUTH|OIDC)")
        if not auth:
            out.findings.append(_f("POL-006", "Dashboard has a public URL but no auth provider configured",
                Severity.HIGH, Position.REMOTE, vault,
                "HERMES_DASHBOARD_PUBLIC_URL says the dashboard is reachable from outside; nothing in .env configures who may log in.",
                "Configure OAuth (Nous Portal) or OIDC for internet exposure; basic auth only on a trusted LAN/VPN.",
                f"grep -nE 'HERMES_DASHBOARD_(BASIC_AUTH|OAUTH|OIDC)' {q(vault)}", ["HERMES_DASHBOARD_PUBLIC_URL: set"], ["net:public", "net:unauth"]))
        elif any(a.startswith("HERMES_DASHBOARD_BASIC_AUTH") for a in auth) and not any(a.startswith(("HERMES_DASHBOARD_OAUTH", "HERMES_DASHBOARD_OIDC")) for a in auth):
            out.findings.append(_f("POL-006", "Public dashboard protected only by username/password",
                Severity.MEDIUM, Position.REMOTE, vault,
                "Hermes documents basic auth as suitable for a trusted LAN or VPN, not direct internet exposure.",
                "Switch to OAuth/OIDC, or keep the dashboard behind a VPN.", None, auth))
    return out


# --- POL-007 debug / redaction -------------------------------------------------------------

@check("POL-007", "Secret redaction off or request dumping on", Position.LOCAL)
def debug_leaks(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    vault = str(target.vault_path)
    if s.env_falsy("HERMES_REDACT_SECRETS"):
        out.findings.append(_f("POL-007", "HERMES_REDACT_SECRETS=false — credentials are written to logs and tool output verbatim",
            Severity.MEDIUM, Position.LOCAL, vault,
            "Every log line, transcript and error that touches a key now contains the key. SEC-001 will start finding them.",
            "Remove HERMES_REDACT_SECRETS (default true).", f"grep -n HERMES_REDACT_SECRETS {q(vault)}", [_env_where(s, "HERMES_REDACT_SECRETS")]))
    if s.env_truthy("HERMES_DUMP_REQUESTS"):
        out.findings.append(_f("POL-007", "HERMES_DUMP_REQUESTS is on — full API payloads are written to disk",
            Severity.HIGH, Position.LOCAL, vault,
            "Request dumps include system prompts, tool results and, depending on provider, auth headers. They are debug files nobody remembers to delete.",
            "Unset HERMES_DUMP_REQUESTS; delete the dump directory.", f"grep -n HERMES_DUMP_REQUESTS {q(vault)}", [_env_where(s, "HERMES_DUMP_REQUESTS")]))
    if s.env_truthy("HERMES_OAUTH_TRACE"):
        out.findings.append(_f("POL-007", "HERMES_OAUTH_TRACE is on — token exchanges are logged",
            Severity.MEDIUM, Position.LOCAL, vault, "OAuth traces contain refresh/access tokens.",
            "Unset HERMES_OAUTH_TRACE.", f"grep -n HERMES_OAUTH_TRACE {q(vault)}", [_env_where(s, "HERMES_OAUTH_TRACE")]))
    lf = s.env_names_matching(r"^HERMES_LANGFUSE_(PUBLIC|SECRET)_KEY$")
    if lf:
        out.findings.append(_f("POL-007", "Langfuse tracing configured — transcripts leave this machine",
            Severity.INFO, Position.LOCAL, vault,
            "Not a misconfiguration, but worth knowing: every prompt and tool result is shipped to a third-party observability service.",
            "Keep if intended; otherwise remove the HERMES_LANGFUSE_* keys.", None, lf))
    return out


# --- POL-008 injection / SSRF / plugin guards ------------------------------------------------

@check("POL-008", "Content-safety guards disabled (SSRF, tirith, project plugins)", Position.CONTENT)
def content_guards(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    s.require_config()  # config.yaml unparsable → skip, never a pass on defaults (AGENTS.md §4)
    cfg = str(target.home / CFG)
    vault = str(target.vault_path)
    if s.get("security.allow_private_urls") is True or s.env_truthy("HERMES_ALLOW_PRIVATE_URLS"):
        out.findings.append(_f("POL-008", "Private-URL fetching allowed — SSRF guard is off",
            Severity.MEDIUM, Position.CONTENT, cfg,
            "The agent's web tools may be steered at 127.0.0.1, RFC-1918 hosts, cloud metadata and its own gateway/API server. "
            "Combined with an exposed local service that is a full attack path.",
            "Remove security.allow_private_urls / HERMES_ALLOW_PRIVATE_URLS unless a specific internal host is needed (use website_blocklist instead).",
            f"grep -n allow_private_urls {q(cfg)} {q(vault)}", ["allow_private_urls: true"], ["ssrf:off"]))
    if s.get("security.tirith_enabled") is not True:
        out.findings.append(_f("POL-008", "tirith pre-execution scanning is not enabled",
            Severity.LOW, Position.CONTENT, cfg,
            "tirith scans commands and context files (AGENTS.md, SOUL.md, .cursorrules) for injection patterns before execution. It is an extra layer, not the only one.",
            "Install tirith and set security.tirith_enabled: true in config.yaml.",
            f"grep -n tirith_enabled {q(cfg)}", ["security.tirith_enabled: unset/false"]))
    if s.env_truthy("HERMES_ENABLE_PROJECT_PLUGINS"):
        out.findings.append(_f("POL-008", "HERMES_ENABLE_PROJECT_PLUGINS is on — any cloned repo can load code into the agent",
            Severity.MEDIUM, Position.SUPPLY_CHAIN, vault,
            "Repo-local plugin discovery means `git clone` of a hostile repo followed by opening it in Hermes runs that repo's Python.",
            "Unset HERMES_ENABLE_PROJECT_PLUGINS; install plugins deliberately.", f"grep -n HERMES_ENABLE_PROJECT_PLUGINS {q(vault)}",
            [_env_where(s, "HERMES_ENABLE_PROJECT_PLUGINS")]))
    return out


# --- POL-009 env passthrough --------------------------------------------------------------

@check("POL-009", "Provider credentials forwarded into tool/skill shells", Position.SUPPLY_CHAIN)
def env_passthrough(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    s.require_config()  # config.yaml unparsable → skip, never a pass on defaults (AGENTS.md §4)
    cfg = str(target.home / CFG)
    leaked: list[str] = []
    for key in ("terminal.env_passthrough", "terminal.docker_forward_env"):
        vals = s.get(key) or []
        if isinstance(vals, list):
            leaked += [f"{key}: {v}" for v in vals if isinstance(v, str) and SECRET_NAME.search(v)]
    fwd, _ = s.env("TERMINAL_DOCKER_FORWARD_ENV")
    if fwd:
        leaked += [f"TERMINAL_DOCKER_FORWARD_ENV: {v.strip()}" for v in fwd.split(",") if SECRET_NAME.search(v)]
    if leaked:
        out.findings.append(_f("POL-009", f"{len(leaked)} credential-named variable(s) are passed through to every command the agent runs",
            Severity.HIGH, Position.SUPPLY_CHAIN, cfg,
            "Anything in env_passthrough is visible to every skill script, every `terminal` call and every subprocess — including one "
            "a malicious skill wrote. Hermes strips these by default precisely so a skill cannot `echo $ANTHROPIC_API_KEY | curl`.",
            "Remove provider keys from terminal.env_passthrough / docker_forward_env. Skills that truly need a key should declare it in "
            "required_environment_variables so the grant is per-skill and visible.",
            f"grep -nA6 env_passthrough {q(cfg)}", leaked[:10], ["secret:passthrough"]))
    cred_files = s.get("terminal.credential_files") or []
    bad = [c for c in cred_files if isinstance(c, str) and Path(c).name in (".env", "auth.json", ".anthropic_oauth.json")]
    if bad:
        out.findings.append(_f("POL-009", "The vault itself is listed in terminal.credential_files",
            Severity.HIGH, Position.SUPPLY_CHAIN, cfg,
            "credential_files are mounted into the tool container. Mounting .env/auth.json gives every command the master keys.",
            "Mount only the specific token file a skill needs.", f"grep -nA4 credential_files {q(cfg)}", bad, ["secret:passthrough"]))
    return out


# --- POL-010 literal secrets in MCP config ---------------------------------------------------

@check("POL-010", "Literal secrets in mcp_servers config", Position.LOCAL)
def mcp_env_secrets(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = load_settings(target, plat)
    s.require_config()  # config.yaml unparsable → skip, never a pass on defaults (AGENTS.md §4)
    cfg = str(target.home / CFG)
    servers = s.get("mcp_servers") or {}
    ev: list[str] = []
    if isinstance(servers, dict):
        for name, conf in servers.items():
            env = (conf or {}).get("env") if isinstance(conf, dict) else None
            if not isinstance(env, dict):
                continue
            for var, val in env.items():
                if not isinstance(val, str) or val.startswith(("$", "${")):
                    continue
                hits = find_hits(f"{var}={val}")
                if hits:
                    r = redact(hits[0].kind, hits[0].raw)
                    ev.append(f"mcp_servers.{name}.env.{var}: {r.kind} {r.display} (fp {r.fingerprint})")
    if ev:
        out.findings.append(_f("POL-010", f"{len(ev)} MCP server env value(s) are literal credentials in config.yaml",
            Severity.MEDIUM, Position.LOCAL, cfg,
            "config.yaml is the file people share, back up and paste into issues. Hermes's own guidance is credentials in .env, references in config.",
            f"Move each value to {target.vault_path} and reference it as ${{VAR}} in mcp_servers.<name>.env.",
            f"daemonaudit scan --home {q(target.home)}  # POL-010 should pass", ev[:10]))
    return out
