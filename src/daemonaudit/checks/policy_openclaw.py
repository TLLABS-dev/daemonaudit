"""POL-001..010 and ADV-001 for OpenClaw. Same ids and tags as the Hermes implementations —
one id is one class of weakness — but read from openclaw.json (+ $include, .env) and
exec-approvals.json. Key names and policy values are shown; credential values never are.

Severity follows the same scale as everywhere else (AGENTS.md); where OpenClaw's own
`security audit` has a matching checkId it is named in the finding's `why`.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

from daemonaudit.checks.policy import _f, _grep_startup_files
from daemonaudit.discover.openclaw_config import DM_CHANNELS, OpenClawSettings, is_secret_ref
from daemonaudit.discover.settings import SECRET_NAME, load_settings
from daemonaudit.model import CheckOutput, Finding, Position, Severity, Target
from daemonaudit.platform import NotSupported, Platform, q
from daemonaudit.redact import find_hits, redact
from daemonaudit.registry import check

FW = ("openclaw",)
SEC_RANK = {"deny": 0, "allowlist": 1, "full": 2}
ASK_RANK = {"always": 0, "on-miss": 1, "off": 2}
INTERPRETERS = re.compile(r"(^|/)(python[0-9.]*|node|nodejs|bun|deno|ruby|perl|php|lua|osascript|(ba|z|da|k)?sh)$")
BROAD_PATTERN = re.compile(r"^(\*|\*\*|/\*\*|~/\*\*|\.\*|/.*\*\*/?\*?)$")
DANGEROUS_NODE_CMDS = {"camera.snap", "camera.clip", "screen.record", "sms.search", "sms.send", "system.run"}
DANGEROUS_BIND_SOURCES = ("/", "/etc", "/proc", "/sys", "/dev", "/root", "/run", "/var/run", "docker.sock", ".ssh", ".aws", ".gnupg", ".netrc",
                          ".docker", ".openclaw", "credentials", ".env")
MASTER_ENV = re.compile(r"^(ANTHROPIC|OPENAI|OPENROUTER|GITHUB|GH|AWS|AZURE|GOOGLE|GEMINI|SLACK|TELEGRAM|DISCORD|WHATSAPP|OPENCLAW|XAI|GROQ|MISTRAL|DEEPSEEK)_")
MIN_TOKEN_LEN = 24


def _s(target: Target, plat: Platform) -> OpenClawSettings:
    return load_settings(target, plat)  # type: ignore[return-value]


def _cfg(target: Target) -> str:
    return str(target.meta.get("config_path") or (target.home / "openclaw.json"))


def _read_json(plat: Platform, p: Path, out: CheckOutput, label: str) -> dict | None:
    try:
        raw = plat.read_nofollow(p, 4 * 1024 * 1024)
    except FileNotFoundError:
        return None
    except NotSupported:
        try:
            raw = p.read_bytes()
        except FileNotFoundError:
            return None
        except OSError as e:
            out.note(f"{label} unreadable ({e.strerror or e})")
            return None
    except OSError as e:
        out.note(f"{label} unreadable ({e.strerror or e})")
        return None
    try:
        d = json.loads(raw.decode("utf-8", "replace"))
    except ValueError:
        out.note(f"{label} is not valid JSON")
        return None
    return d if isinstance(d, dict) else None


def _approvals(target: Target, plat: Platform, out: CheckOutput) -> dict:
    cached = target.meta.get("_approvals")
    if cached is None:
        cached = _read_json(plat, target.home / "exec-approvals.json", out, "exec-approvals.json") or {}
        target.meta["_approvals"] = cached
    return cached


def _scopes(s: OpenClawSettings, approvals: dict) -> list[tuple[str, dict[str, Any]]]:
    """[(agent id, effective exec policy)] — config defaults + per-agent overrides, then the
    approvals file, which can only tighten. Docs: 'Effective policy is the stricter of the two.'"""
    agents = {"main": None}
    for a in s.agent_entries():
        if isinstance(a.get("id"), str):
            agents[a["id"]] = a
    ap_agents = approvals.get("agents") if isinstance(approvals.get("agents"), dict) else {}
    for aid in ap_agents:
        agents.setdefault(aid, None)
    ap_defaults = approvals.get("defaults") if isinstance(approvals.get("defaults"), dict) else {}
    out = []
    for aid, entry in agents.items():
        eff = s.exec_policy(entry)
        ap = dict(ap_defaults)
        ap.update(ap_agents.get(aid) if isinstance(ap_agents.get(aid), dict) else {})
        for key, rank in (("security", SEC_RANK), ("ask", ASK_RANK)):
            v = ap.get(key)
            if isinstance(v, str) and v in rank and rank[v] < rank.get(str(eff.get(key)), 99):
                eff[key] = v
        eff["askFallback"] = ap.get("askFallback", "deny")
        eff["autoAllowSkills"] = bool(ap.get("autoAllowSkills", eff.get("autoAllowSkills", False)))
        eff["allowlist"] = ap.get("allowlist") if isinstance(ap.get("allowlist"), list) else []
        eff["explicit"] = bool(s.get("tools.exec.security") or s.get("tools.exec.ask") or s.get("tools.exec.mode")
                               or (isinstance(entry, dict) and isinstance(entry.get("tools"), dict) and entry["tools"].get("exec")))
        out.append((aid, eff))
    return out


# --- POL-001 approval bypasses -----------------------------------------------------------

@check("POL-001", "Dangerous-command approval bypassed (yolo / exec-ask off)", Position.CONTENT, frameworks=FW)
def approval_bypass(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    out.coverage_notes += s.notes
    cfg = _cfg(target)
    ap = _approvals(target, plat, out)
    yolo, fallback_full, auto_skills, lax_interp = [], [], [], []
    for aid, eff in _scopes(s, ap):
        if eff["security"] == "full" and eff["ask"] == "off":
            yolo.append(f"agent {aid}: security={eff['security']} ask={eff['ask']}" + (" (explicit)" if eff["explicit"] else " (default)"))
        if eff.get("askFallback") == "full":
            fallback_full.append(f"agent {aid}: askFallback=full")
        if eff.get("autoAllowSkills"):
            auto_skills.append(f"agent {aid}: autoAllowSkills=true")
        if eff["security"] == "allowlist" and not eff.get("strictInlineEval"):
            interp = [str(e.get("pattern")) for e in eff["allowlist"] if isinstance(e, dict) and INTERPRETERS.search(str(e.get("pattern", "")))]
            if interp:
                lax_interp += [f"agent {aid}: {p}" for p in interp[:5]]
    if yolo:
        explicit = any("(explicit)" in y for y in yolo)
        out.findings.append(_f("POL-001", f"Host exec runs without approval for {len(yolo)} agent(s) (tools.exec security=full, ask=off)",
            Severity.HIGH if explicit else Severity.MEDIUM, Position.CONTENT, cfg,
            "The `exec` tool runs shell commands on this host as your user with no approval prompt and no allowlist. "
            "This is OpenClaw's single-operator default (its own audit reports it as tools.exec.security_full_configured), which is why it is "
            "MEDIUM here and not HIGH — but it means any prompt injection that reaches a tool-enabled agent is a shell. "
            + ("You set it explicitly, so the trusted-operator assumption is a choice to re-check." if explicit else ""),
            "Set tools.exec.security: \"allowlist\" and tools.exec.ask: \"on-miss\" (or tools.exec.mode: \"ask\") in openclaw.json, "
            "or the same per agent under agents.list[].tools.exec; keep exec-approvals.json defaults at security=allowlist, ask=on-miss, askFallback=deny.",
            f"openclaw config get tools.exec; cat {q(target.home / 'exec-approvals.json')} 2>/dev/null | head", yolo, ["exec:noapproval"]))
    if fallback_full:
        out.findings.append(_f("POL-001", "exec-approvals.json askFallback=full — an unanswered approval prompt runs the command",
            Severity.HIGH, Position.CONTENT, str(target.home / "exec-approvals.json"),
            "When nobody answers the prompt the command runs anyway. That turns 'ask' into a timer, not a gate.",
            "Set askFallback: \"deny\" (the default) in exec-approvals.json.",
            f"grep -n askFallback {q(target.home / 'exec-approvals.json')}", fallback_full, ["exec:noapproval"]))
    if auto_skills:
        out.findings.append(_f("POL-001", "autoAllowSkills is on — binaries any installed skill mentions are pre-approved",
            Severity.MEDIUM, Position.SUPPLY_CHAIN, str(target.home / "exec-approvals.json"),
            "Every executable referenced by a skill's metadata becomes an implicit allowlist entry. Installing a skill that lists `bash` or `curl` widens the allowlist silently (OpenClaw: tools.exec.auto_allow_skills_enabled).",
            "Set autoAllowSkills: false and allowlist commands deliberately.",
            f"grep -n autoAllowSkills {q(target.home / 'exec-approvals.json')}", auto_skills))
    if lax_interp:
        out.findings.append(_f("POL-001", "Interpreters are allowlisted without strictInlineEval",
            Severity.LOW, Position.CONTENT, str(target.home / "exec-approvals.json"),
            "An allowlisted `python`/`node`/`sh` accepts `-c '<anything>'`, so the allowlist is a formality (OpenClaw: tools.exec.allowlist_interpreter_without_strict_inline_eval).",
            "Set tools.exec.strictInlineEval: true so inline-eval forms still need approval.",
            "openclaw config get tools.exec.strictInlineEval", lax_interp))
    startup = _grep_startup_files(plat, out, re.compile(r"(^|\s)--(dangerously-skip-permissions|yolo)(\s|$)|OPENCLAW_.*PERMISSION|permissionMode\s*[:=]\s*[\"']?approve-all", re.I))
    if startup:
        out.findings.append(_f("POL-001", "Approval bypass flag baked into a service unit or shell profile",
            Severity.HIGH, Position.CONTENT, startup[0].split(":")[0],
            "The daemon starts with approvals disabled regardless of what openclaw.json says.",
            "Remove the flag from the listed file(s); reload the unit or shell.", None, startup[:10], ["exec:noapproval"]))
    return out


# --- POL-002 approvals config ------------------------------------------------------------

@check("POL-002", "Approval policy weakened in config", Position.CONTENT, frameworks=FW)
def approvals_config(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    ap = _approvals(target, plat, out)
    broad: list[str] = []
    total = 0
    ap_agents = ap.get("agents") if isinstance(ap.get("agents"), dict) else {}
    for aid, entry in ap_agents.items():
        for e in (entry.get("allowlist") if isinstance(entry, dict) and isinstance(entry.get("allowlist"), list) else []):
            if not isinstance(e, dict):
                continue
            total += 1
            pat = str(e.get("pattern", ""))
            base = pat.rsplit("/", 1)[-1]
            if BROAD_PATTERN.match(pat) or base in ("sudo", "su", "curl", "wget", "rm") or INTERPRETERS.search(pat) and not e.get("argPattern"):
                broad.append(f"agent {aid}: {pat[:60]}")
    if total:
        out.findings.append(_f("POL-002", f"{total} exec allowlist pattern(s) are permanently pre-approved" + (f"; {len(broad)} broad" if broad else ""),
            Severity.MEDIUM if broad else Severity.INFO, Position.CONTENT, str(target.home / "exec-approvals.json"),
            "Allowlisted patterns skip the approval prompt forever. Wildcards, `sudo`, `curl`, `rm` and bare interpreters hand injection a free shell.",
            "Review exec-approvals.json; keep entries to a specific binary plus an argPattern. `openclaw approvals list` shows them.",
            "openclaw approvals list", (broad or [])[:10]))
    elev = s.get("tools.elevated")
    if isinstance(elev, dict) and elev.get("enabled"):
        allow = elev.get("allowFrom") if isinstance(elev.get("allowFrom"), dict) else {}
        wild = [f"tools.elevated.allowFrom.{ch}: *" for ch, ids in allow.items() if isinstance(ids, list) and "*" in ids]
        big = [f"tools.elevated.allowFrom.{ch}: {len(ids)} senders" for ch, ids in allow.items() if isinstance(ids, list) and len(ids) > 25]
        if wild:
            out.findings.append(_f("POL-002", "Elevated (sandbox-bypassing) exec is allowed for every sender on a channel",
                Severity.HIGH, Position.CONTENT, cfg,
                "`/elevated` runs commands on the gateway host outside the sandbox. A wildcard allowFrom means anyone who can message the bot on that channel can use it (OpenClaw: tools.elevated.allowFrom.<provider>.wildcard).",
                "List specific sender ids in tools.elevated.allowFrom.<channel>, or set tools.elevated.enabled: false.",
                "openclaw config get tools.elevated", wild, ["exec:noapproval", "exec:host", "content:allow-all"]))
        elif big:
            out.findings.append(_f("POL-002", "Elevated exec allowFrom is very large", Severity.LOW, Position.CONTENT, cfg,
                "More than 25 senders may bypass the sandbox. Each one is a trusted operator now.", "Trim tools.elevated.allowFrom.", None, big))
        elif not allow:
            out.findings.append(_f("POL-002", "tools.elevated.enabled without an allowFrom list", Severity.LOW, Position.CONTENT, cfg,
                "Enabled but nobody is allowed — inert today; the first `allowFrom` entry turns it on.", "Set allowFrom deliberately, or disable.", None,
                ["tools.elevated.enabled: true", "tools.elevated.allowFrom: unset"]))
    if s.get("commands.bash") is True:
        out.findings.append(_f("POL-002", "commands.bash is on — `/bash` runs shell from chat", Severity.LOW, Position.CONTENT, cfg,
            "A chat slash-command that runs a shell on the host. Gated by tools.elevated.allowFrom, so its risk is that list's risk.",
            "Keep commands.bash: false unless you use it; it defaults off.", "openclaw config get commands.bash", ["commands.bash: true"]))
    safe = s.get("tools.exec.safeBins")
    if isinstance(safe, list):
        bad = [b for b in safe if isinstance(b, str) and INTERPRETERS.search(b)]
        if bad:
            out.findings.append(_f("POL-002", "Interpreters listed as tools.exec.safeBins", Severity.MEDIUM, Position.CONTENT, cfg,
                "safeBins run without approval in allowlist mode. An interpreter is never 'safe': `python -c` is arbitrary code (OpenClaw: tools.exec.safe_bins_interpreter_unprofiled).",
                "Remove interpreters from tools.exec.safeBins or add a strict safeBinProfiles entry.", "openclaw config get tools.exec.safeBins", bad[:10],
                ["exec:noapproval"]))
    return out


# --- POL-003 execution sandbox ----------------------------------------------------------

@check("POL-003", "Agent executes directly on the host without a write boundary", Position.CONTENT, frameworks=FW)
def unsandboxed(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    mode = s.sandbox_mode()
    host = str(s.exec_policy().get("host") or "auto")
    ws_only = s.get("tools.fs.workspaceOnly") is True
    if mode == "off" and host != "node":
        out.findings.append(_f("POL-003", f"agents.defaults.sandbox.mode: {mode} — exec and file tools run on this host as you",
            Severity.MEDIUM if not ws_only else Severity.LOW, Position.CONTENT, cfg,
            "With sandboxing off, tools.exec.host `auto` resolves to the gateway host: commands run as your user with your whole home directory "
            "reachable (OpenClaw: sandbox.docker_config_mode_off). " + ("tools.fs.workspaceOnly limits the *file* tools to the workspace, but exec is unconstrained." if ws_only else
            "Nothing limits the file tools either (tools.fs.workspaceOnly is unset)."),
            "Set agents.defaults.sandbox.mode: \"all\" (or \"non-main\") with the Docker backend, and tools.fs.workspaceOnly: true. "
            "If you stay on the host, keep tools.exec in allowlist/ask mode (POL-001).",
            "openclaw config get agents.defaults.sandbox.mode; openclaw sandbox list",
            [f"agents.defaults.sandbox.mode: {mode}", f"tools.exec.host: {host}", f"tools.fs.workspaceOnly: {ws_only}"], ["exec:host"]))
    if host == "sandbox" and mode == "off":
        out.findings.append(_f("POL-003", "tools.exec.host: sandbox while sandbox mode is off — exec fails closed", Severity.LOW, Position.CONTENT, cfg,
            "Not a hole, a drift: exec calls will fail until a sandbox runtime exists (OpenClaw: tools.exec.host_sandbox_no_sandbox_defaults).",
            "Enable the sandbox or set tools.exec.host: gateway explicitly.", None, [f"tools.exec.host: {host}", f"sandbox.mode: {mode}"]))
    docker = s.get("agents.defaults.sandbox.docker") if isinstance(s.get("agents.defaults.sandbox.docker"), dict) else {}
    if mode != "off" and docker:
        bad: list[str] = []
        if docker.get("network") in ("host",) or str(docker.get("network", "")).startswith("container:"):
            bad.append(f"docker.network: {docker.get('network')}")
        for b in docker.get("binds") if isinstance(docker.get("binds"), list) else []:
            src = str(b).split(":", 1)[0]
            if any(src == d or src.endswith(d) or f"/{d.strip('/')}/" in src + "/" for d in DANGEROUS_BIND_SOURCES):
                bad.append(f"docker.binds: {str(b)[:60]}")
        for k in ("dangerouslyAllowReservedContainerTargets", "dangerouslyAllowExternalBindSources", "dangerouslyAllowContainerNamespaceJoin"):
            if docker.get(k) is True:
                bad.append(f"docker.{k}: true")
        so = docker.get("securityOpt") if isinstance(docker.get("securityOpt"), list) else []
        if any("seccomp=unconfined" in str(x) or "apparmor=unconfined" in str(x) for x in so):
            bad.append("docker.securityOpt: unconfined")
        if bad:
            out.findings.append(_f("POL-003", "Sandbox is configured, but the container can reach the host", Severity.HIGH, Position.CONTENT, cfg,
                "Host networking, bind-mounting credential directories or the Docker socket, or unconfined seccomp/AppArmor makes the sandbox decorative "
                "(OpenClaw: sandbox.dangerous_*).", "Remove the listed docker settings; use network: none and workspace-only binds.",
                "openclaw config get agents.defaults.sandbox.docker", bad[:10], ["exec:host"]))
    return out


# --- POL-004 who may talk to the agent -----------------------------------------------------

@check("POL-004", "Anyone may message the agent (allow-all users)", Position.CONTENT, frameworks=FW)
def allow_all_users(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    chans = s.get("channels") if isinstance(s.get("channels"), dict) else {}
    open_dm, star, open_group, name_match = [], [], [], []
    default_group = (chans.get("defaults") or {}).get("groupPolicy") if isinstance(chans.get("defaults"), dict) else None
    for name, conf in chans.items():
        if name == "defaults" or not isinstance(conf, dict) or conf.get("enabled") is False:
            continue
        scopes = [("", conf)] + [(f".accounts.{a}", c) for a, c in (conf.get("accounts") or {}).items() if isinstance(c, dict)] if isinstance(conf.get("accounts"), dict) else [("", conf)]
        for suffix, c in scopes:
            key = f"channels.{name}{suffix}"
            policy = c.get("dmPolicy") or ((c.get("dm") or {}).get("policy") if isinstance(c.get("dm"), dict) else None)
            allow = c.get("allowFrom") or ((c.get("dm") or {}).get("allowFrom") if isinstance(c.get("dm"), dict) else None)
            if policy == "open":
                open_dm.append(f"{key}.dmPolicy: open")
            elif isinstance(allow, list) and "*" in allow:
                star.append(f"{key}.allowFrom: [\"*\"]")
            gp = c.get("groupPolicy") or default_group
            if gp == "open":
                open_group.append(f"{key}.groupPolicy: open")
            if c.get("dangerouslyAllowNameMatching") is True:
                name_match.append(f"{key}.dangerouslyAllowNameMatching: true")
    if open_dm:
        out.findings.append(_f("POL-004", f"{len(open_dm)} channel(s) accept DMs from anyone (dmPolicy: open)",
            Severity.HIGH, Position.CONTENT, cfg,
            "The chat platform is the agent's front door. Open DMs mean strangers can send it instructions, and with tools enabled that is "
            "remote command execution gated only by the exec policy (OpenClaw: channels.<provider>.dm.open, critical).",
            "Set dmPolicy: \"pairing\" (default) or \"allowlist\" and approve senders with `openclaw pairing approve`.",
            "openclaw config get channels", open_dm, ["content:allow-all"]))
    if star:
        out.findings.append(_f("POL-004", "allowFrom contains \"*\" — the DM allowlist allows everyone", Severity.HIGH, Position.CONTENT, cfg,
            "A wildcard allowlist is an open DM policy by another name; it also opens slash commands for that channel.",
            "Replace \"*\" with the sender ids that should reach the bot.", "openclaw config get channels", star, ["content:allow-all"]))
    if open_group:
        out.findings.append(_f("POL-004", f"{len(open_group)} channel(s) have groupPolicy: open", Severity.MEDIUM, Position.CONTENT, cfg,
            "Every group/room the bot is in can trigger it (mention gating still applies). Anyone who can add the bot to a room is now a user.",
            "Set groupPolicy: \"allowlist\" and list the rooms (`openclaw security audit --fix` does this).", "openclaw config get channels", open_group,
            ["content:allow-all"]))
    if name_match:
        out.findings.append(_f("POL-004", "Sender allowlists match on display names", Severity.LOW, Position.CONTENT, cfg,
            "Display names are chosen by the sender; anyone can rename themselves into the allowlist.",
            "Remove dangerouslyAllowNameMatching; allowlist stable ids.", None, name_match))
    scope = s.get("session.dmScope") or "main"
    multi = bool(open_dm or star) or any(isinstance((c.get("allowFrom") if isinstance(c, dict) else None), list) and len(c["allowFrom"]) > 1 for c in chans.values())
    if scope == "main" and multi:
        out.findings.append(_f("POL-004", "session.dmScope: main with more than one allowed DM sender", Severity.LOW, Position.CONTENT, cfg,
            "All DMs share one session, so one sender sees context from another and can steer the conversation the other started "
            "(OpenClaw: channels.<provider>.dm.scope_main_multiuser).",
            "Set session.dmScope: \"per-channel-peer\".", "openclaw config get session.dmScope", [f"session.dmScope: {scope}"]))
    return out


# --- POL-005 gateway exposure --------------------------------------------------------------

@check("POL-005", "Gateway exposed beyond loopback or unauthenticated", Position.REMOTE, frameworks=FW)
def gateway_exposure(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    if s.get("gateway.mode") == "remote":
        out.findings.append(_f("POL-005", "gateway.mode: remote — this install is a client of a gateway elsewhere", Severity.INFO, Position.REMOTE, cfg,
            "No gateway listens here; the remote's exposure is what matters. Run daemonaudit on that host.",
            "Nothing to do here.", None, [f"gateway.remote.url: {'set' if s.get('gateway.remote.url') else 'unset'}"]))
        return out
    bind = s.gateway_bind()
    auth = s.gateway_auth_mode()
    port = s.gateway_port()
    public = bind in ("lan", "custom", "auto")
    ts = s.get("gateway.tailscale.mode") or "off"
    ev = [f"gateway.bind: {bind}", f"gateway.auth.mode: {auth}", f"gateway.port: {port}"]
    if auth == "none":
        out.findings.append(_f("POL-005", f"Gateway auth is off (mode {auth}) — bind {bind}",
            Severity.CRITICAL if public else Severity.HIGH, Position.REMOTE, cfg,
            "No token, no password: whoever reaches the port drives the agent, its tools and its channels — the WebSocket control plane and "
            "the always-on POST /tools/invoke HTTP API "
            + ("from the network (OpenClaw: gateway.bind_no_auth; the gateway refuses to start this way, so this may be a config that has not been applied yet)."
               if public else "from any process on this host — a browser tab, another user (OpenClaw: gateway.loopback_no_auth, gateway.http.no_auth)."),
            "Set gateway.auth.mode: \"token\" with a long random gateway.auth.token (`openclaw doctor --generate-gateway-token`) and restart.",
            "openclaw config get gateway.auth.mode", ev, ["net:unauth"] + (["net:public"] if public else [])))
    if public:
        out.findings.append(_f("POL-005", f"gateway.bind: {bind} — the gateway listens on the network",
            Severity.HIGH if auth != "none" else Severity.INFO, Position.REMOTE, cfg,
            "Reachable from every network this machine joins. The shared token is the only thing between the internet and your agent's tools, "
            "and the Control UI/WebSocket carries operator scope.",
            s.bind_loopback_fix(), "openclaw config get gateway.bind", ev, ["net:public"]))
    elif bind == "tailnet":
        out.findings.append(_f("POL-005", "gateway.bind: tailnet — reachable by every device on your tailnet", Severity.LOW, Position.REMOTE, cfg,
            "Tailnet peers are trusted-ish, but each is a client of the gateway now. Tailscale identity headers do not authenticate the HTTP API paths.",
            "Prefer bind: loopback + gateway.tailscale.mode: serve, and keep token auth.", None, ev))
    if ts == "funnel":
        out.findings.append(_f("POL-005", "gateway.tailscale.mode: funnel — the gateway is published to the public internet", Severity.HIGH, Position.REMOTE, cfg,
            "Funnel exposes the port to anyone on the internet (OpenClaw: gateway.tailscale_funnel, critical). Password auth is required, and it is the whole defence.",
            "Use tailscale.mode: serve (tailnet only) unless public exposure is the point; then a long password and rate limits.",
            "openclaw config get gateway.tailscale", ev + [f"gateway.tailscale.mode: {ts}"], ["net:public"]))
    elif ts == "serve":
        out.findings.append(_f("POL-005", "gateway.tailscale.mode: serve — tailnet exposure via Tailscale", Severity.INFO, Position.REMOTE, cfg,
            "Listed for inventory (OpenClaw: gateway.tailscale_serve).", "Nothing to do.", None, [f"gateway.tailscale.mode: {ts}"]))
    ui = s.get("gateway.controlUi") if isinstance(s.get("gateway.controlUi"), dict) else {}
    if ui.get("dangerouslyDisableDeviceAuth") is True:
        out.findings.append(_f("POL-005", "gateway.controlUi.dangerouslyDisableDeviceAuth is on", Severity.HIGH, Position.REMOTE, cfg,
            "Device identity checks are off for the Control UI: the shared token alone grants operator access (OpenClaw: gateway.control_ui.device_auth_disabled, critical).",
            "Remove dangerouslyDisableDeviceAuth; pair devices with `openclaw devices`.", "openclaw config get gateway.controlUi", ["dangerouslyDisableDeviceAuth: true"], ["net:unauth"]))
    if ui.get("allowInsecureAuth") is True:
        out.findings.append(_f("POL-005", "gateway.controlUi.allowInsecureAuth is on", Severity.LOW, Position.REMOTE, cfg,
            "Control UI auth is accepted over plain HTTP without device identity (localhost compatibility toggle).",
            "Remove allowInsecureAuth once you use HTTPS or Tailscale serve.", None, ["allowInsecureAuth: true"]))
    origins = ui.get("allowedOrigins")
    if isinstance(origins, list) and "*" in origins:
        out.findings.append(_f("POL-005", "gateway.controlUi.allowedOrigins: [\"*\"]", Severity.MEDIUM, Position.CONTENT, cfg,
            "Any web page may open the Control UI WebSocket from your browser (OpenClaw: gateway.control_ui.allowed_origins_wildcard).",
            "List the exact origins that host the UI.", None, ["allowedOrigins: *"]))
    if ui.get("dangerouslyAllowHostHeaderOriginFallback") is True:
        out.findings.append(_f("POL-005", "Host-header origin fallback enabled for the Control UI", Severity.MEDIUM, Position.CONTENT, cfg,
            "Origin checks fall back to the Host header, which a browser-side attacker does not control but a proxy misconfiguration does.",
            "Remove dangerouslyAllowHostHeaderOriginFallback; set allowedOrigins.", None, ["dangerouslyAllowHostHeaderOriginFallback: true"]))
    if auth == "trusted-proxy":
        proxies = s.get("gateway.trustedProxies")
        tp = s.get("gateway.auth.trustedProxy") if isinstance(s.get("gateway.auth.trustedProxy"), dict) else {}
        if not proxies:
            out.findings.append(_f("POL-005", "trusted-proxy auth with no gateway.trustedProxies", Severity.HIGH, Position.REMOTE, cfg,
                "Identity comes from a request header; without a proxy allowlist anyone who reaches the port can set that header (OpenClaw: gateway.trusted_proxy_no_proxies).",
                "Set gateway.trustedProxies to the proxy's address and bind so only the proxy can reach the gateway.", None, ev, ["net:unauth"]))
        if not tp.get("userHeader"):
            out.findings.append(_f("POL-005", "trusted-proxy auth without trustedProxy.userHeader", Severity.HIGH, Position.REMOTE, cfg,
                "No header names the user, so nothing does.", "Set gateway.auth.trustedProxy.userHeader.", None, ev, ["net:unauth"]))
        if tp.get("allowLoopback") is True:
            out.findings.append(_f("POL-005", "trustedProxy.allowLoopback is on", Severity.LOW, Position.LOCAL, cfg,
                "Local processes can present the identity header themselves.", "Remove allowLoopback.", None, ["allowLoopback: true"]))
    if s.get("gateway.allowRealIpFallback") is True:
        out.findings.append(_f("POL-005", "gateway.allowRealIpFallback is on", Severity.MEDIUM, Position.REMOTE, cfg,
            "X-Real-IP is trusted when X-Forwarded-For is absent — a client can claim a loopback/trusted address (OpenClaw: gateway.real_ip_fallback_enabled).",
            "Remove allowRealIpFallback; make the proxy set X-Forwarded-For.", None, ["allowRealIpFallback: true"]))
    tok = s.get("gateway.auth.token")
    if isinstance(tok, str) and not is_secret_ref(tok) and len(tok) < MIN_TOKEN_LEN:
        out.findings.append(_f("POL-005", f"gateway.auth.token is short ({len(tok)} chars)", Severity.LOW if not public else Severity.MEDIUM, Position.REMOTE, cfg,
            "A short shared token is guessable, and it is the whole authentication (OpenClaw: gateway.token_too_short).",
            "`openclaw doctor --generate-gateway-token` and restart.", None, [f"token length: {len(tok)}"]))
    pw = s.get("gateway.auth.password")
    if isinstance(pw, str) and not is_secret_ref(pw):
        out.findings.append(_f("POL-005", "gateway.auth.password is a literal in openclaw.json", Severity.LOW, Position.LOCAL, cfg,
            "Config gets shared and backed up; the gateway password goes with it (OpenClaw: config.secrets.gateway_password_in_config).",
            "Use OPENCLAW_GATEWAY_PASSWORD in .env or a SecretRef (${VAR}).", None, ["gateway.auth.password: literal"]))
    if s.get("gateway.auth.rateLimit") is None and (public or ts != "off"):
        out.findings.append(_f("POL-005", "No gateway.auth.rateLimit on a network-reachable gateway", Severity.LOW, Position.REMOTE, cfg,
            "Nothing slows down token guessing (OpenClaw: gateway.auth_no_rate_limit).", "Set gateway.auth.rateLimit {maxAttempts, windowMs, lockoutMs}.", None, ev))
    ga = s.get("gateway.tools.allow")
    if isinstance(ga, list) and ga:
        out.findings.append(_f("POL-005", f"gateway.tools.allow re-enables {len(ga)} tool(s) over POST /tools/invoke", Severity.MEDIUM, Position.REMOTE, cfg,
            "Tools on the HTTP deny list are there because a bearer token should not be a shell (OpenClaw: gateway.tools_invoke_http.dangerous_allow).",
            "Remove gateway.tools.allow entries you do not need.", None, [str(x) for x in ga[:10]]))
    nc = s.get("gateway.nodes.allowCommands")
    if isinstance(nc, list):
        bad = [c for c in nc if str(c) in DANGEROUS_NODE_CMDS]
        if bad:
            out.findings.append(_f("POL-005", "Dangerous node commands are allowed (camera / screen / sms / system.run)", Severity.MEDIUM, Position.REMOTE, cfg,
                "Paired nodes can be told to record, snap and send on your devices (OpenClaw: gateway.nodes.allow_commands_dangerous).",
                "Remove them from gateway.nodes.allowCommands unless you use them.", None, bad[:10]))
    if s.get("gateway.nodes.pairing.autoApproveCidrs"):
        out.findings.append(_f("POL-005", "Node pairing auto-approves from configured CIDRs", Severity.LOW, Position.REMOTE, cfg,
            "Any host in those ranges can enrol as a node without a human approving it.", "Keep the ranges minimal, or remove autoApproveCidrs.", None,
            [str(x) for x in (s.get("gateway.nodes.pairing.autoApproveCidrs") or [])][:5]))
    if s.get("discovery.mdns.mode") == "full":
        out.findings.append(_f("POL-005", "discovery.mdns.mode: full advertises the CLI path and SSH port on the LAN", Severity.LOW, Position.REMOTE, cfg,
            "Reconnaissance for free (OpenClaw: discovery.mdns_full_mode).", "Set discovery.mdns.mode: minimal or off.", None, ["discovery.mdns.mode: full"]))
    http = s.get("gateway.http.endpoints") if isinstance(s.get("gateway.http.endpoints"), dict) else {}
    enabled = [k for k, v in http.items() if isinstance(v, dict) and v.get("enabled") is True]
    if enabled:
        out.findings.append(_f("POL-005", f"HTTP API endpoints enabled: {', '.join(enabled)}", Severity.INFO if auth != "none" else Severity.HIGH, Position.REMOTE, cfg,
            "OpenAI-compatible endpoints run agent turns (tools included) for any bearer of the gateway token" + (" — and auth is off." if auth == "none" else "."),
            "Keep them off unless a client needs them; they share gateway auth.", None, [f"gateway.http.endpoints.{k}.enabled: true" for k in enabled],
            ["net:unauth"] if auth == "none" else []))
    return out


# --- POL-006 hooks & inbound webhooks --------------------------------------------------------

@check("POL-006", "Inbound webhook or dashboard without verification/auth", Position.REMOTE, frameworks=FW)
def webhooks(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    hooks = s.get("hooks") if isinstance(s.get("hooks"), dict) else {}
    if hooks.get("enabled") is True:
        tok = hooks.get("token")
        gw = [x for x in (s.get("gateway.auth.token"), s.get("gateway.auth.password")) if isinstance(x, str)]
        if not tok:
            out.findings.append(_f("POL-006", "hooks.enabled without hooks.token", Severity.HIGH, Position.REMOTE, cfg,
                "POST /hooks/* wakes agents and injects messages. Without a token that is an unauthenticated prompt-injection endpoint.",
                "Set a long random hooks.token (different from the gateway token).", "openclaw config get hooks", ["hooks.token: unset"], ["net:unauth-inbound"]))
        elif isinstance(tok, str) and tok in gw:
            out.findings.append(_f("POL-006", "hooks.token is the gateway token", Severity.HIGH, Position.REMOTE, cfg,
                "Every webhook caller holds operator credentials (OpenClaw: hooks.token_reuse_gateway_token, critical).",
                "Give hooks their own token.", None, ["hooks.token == gateway.auth.token/password"]))
        elif isinstance(tok, str) and not is_secret_ref(tok) and len(tok) < MIN_TOKEN_LEN:
            out.findings.append(_f("POL-006", f"hooks.token is short ({len(tok)} chars)", Severity.LOW, Position.REMOTE, cfg,
                "Guessable webhook token (OpenClaw: hooks.token_too_short).", "Use a long random value.", None, [f"length {len(tok)}"]))
        if hooks.get("path") in ("/", ""):
            out.findings.append(_f("POL-006", "hooks.path is /", Severity.MEDIUM, Position.REMOTE, cfg,
                "The webhook handler shadows the whole HTTP surface (OpenClaw: hooks.path_root, critical).", "Set hooks.path: \"/hooks\".", None, ["hooks.path: /"]))
        if hooks.get("allowRequestSessionKey") is True and not hooks.get("allowedSessionKeyPrefixes"):
            out.findings.append(_f("POL-006", "Webhook callers may choose any session key", Severity.MEDIUM, Position.REMOTE, cfg,
                "A caller can inject into your main session, not just a hook session (OpenClaw: hooks.request_session_key_enabled).",
                "Set hooks.allowedSessionKeyPrefixes: [\"hook:\"] or turn allowRequestSessionKey off.", None, ["allowRequestSessionKey: true", "allowedSessionKeyPrefixes: unset"]))
        ids = hooks.get("allowedAgentIds")
        if ids is None or ids == "*" or (isinstance(ids, list) and "*" in ids):
            out.findings.append(_f("POL-006", "hooks.allowedAgentIds is unrestricted", Severity.LOW, Position.REMOTE, cfg,
                "Webhooks can target every agent, including tool-heavy ones.", "List the agent ids hooks may wake.", None, [f"allowedAgentIds: {ids!r}"]))
    tg = s.get("channels.telegram") if isinstance(s.get("channels.telegram"), dict) else {}
    if tg.get("webhookUrl") and not tg.get("webhookSecret"):
        out.findings.append(_f("POL-006", "Telegram webhook mode without webhookSecret", Severity.HIGH, Position.REMOTE, cfg,
            "Telegram echoes the secret so you can tell real updates from forged ones. Without it, any HTTP client can inject messages.",
            "Set channels.telegram.webhookSecret and re-register the webhook.", None, ["channels.telegram.webhookUrl: set", "webhookSecret: unset"], ["net:unauth-inbound"]))
    zalo = s.get("channels.zalo") if isinstance(s.get("channels.zalo"), dict) else {}
    if zalo.get("botToken") and zalo.get("webhookUrl") and not zalo.get("webhookSecret"):
        out.findings.append(_f("POL-006", "Zalo webhook without webhookSecret", Severity.HIGH, Position.REMOTE, cfg,
            "Unverified inbound messages straight into the agent.", "Set channels.zalo.webhookSecret.", None, ["channels.zalo.webhookSecret: unset"], ["net:unauth-inbound"]))
    if s.get("plugins.entries.admin-http-rpc.enabled") is True and s.gateway_auth_mode() == "none":
        out.findings.append(_f("POL-006", "admin-http-rpc plugin enabled with gateway auth off", Severity.HIGH, Position.REMOTE, cfg,
            "POST /api/v1/admin/rpc is a config-writing control plane (OpenClaw: gateway.http.no_auth).", "Turn gateway auth on, or disable the plugin.", None,
            ["plugins.entries.admin-http-rpc.enabled: true"], ["net:unauth"]))
    return out


# --- POL-007 debug / redaction -------------------------------------------------------------

@check("POL-007", "Secret redaction off or request dumping on", Position.LOCAL, frameworks=FW)
def debug_leaks(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    vault = target.vault_path
    if s.get("logging.redactSensitive") == "off":
        out.findings.append(_f("POL-007", "logging.redactSensitive: off — tool output and transcripts are logged verbatim",
            Severity.MEDIUM, Position.LOCAL, cfg,
            "Every log line and transcript that touches a key now contains the key. SEC-001 will start finding them (OpenClaw: logging.redact_off).",
            "Set logging.redactSensitive: \"tools\" (default; `openclaw security audit --fix` restores it).", "openclaw config get logging.redactSensitive",
            ["logging.redactSensitive: off"]))
    lvl = s.get("logging.level") or s.env("OPENCLAW_LOG_LEVEL")[0]
    if isinstance(lvl, str) and lvl.lower() in ("debug", "trace"):
        out.findings.append(_f("POL-007", f"logging.level: {lvl} — verbose logs on disk", Severity.LOW, Position.LOCAL, cfg,
            "Debug/trace logs carry prompts, tool args and provider errors. They live in /tmp/openclaw by default, outside the locked-down home.",
            "Set logging.level: info once you are done debugging; delete old log files.", "ls -l /tmp/openclaw/", [f"logging.level: {lvl}"]))
    payload, src = s.env("OPENCLAW_DEBUG_MODEL_PAYLOAD")
    if payload:
        out.findings.append(_f("POL-007", f"OPENCLAW_DEBUG_MODEL_PAYLOAD={payload} ({src}) — model payloads are logged", Severity.MEDIUM, Position.LOCAL, str(vault),
            "Prompt and message text is written to the log. Full payloads include every secret the model saw.", "Unset OPENCLAW_DEBUG_MODEL_PAYLOAD.", None,
            [f"OPENCLAW_DEBUG_MODEL_PAYLOAD ({src})"]))
    startup = _grep_startup_files(plat, out, re.compile(r"OPENCLAW_GATEWAY_(TOKEN|PASSWORD)\s*=\s*\S{8,}", re.I))
    if startup:
        out.findings.append(_f("POL-007", "Gateway token/password is written into a service unit or shell profile", Severity.MEDIUM, Position.LOCAL, startup[0].split(":")[0],
            "Unit files and shell rc are usually world-readable, and `systemctl --user show` prints Environment= to anyone in your session. "
            "The gateway credential is the operator credential.",
            "Move it to ~/.openclaw/.env (0600) or an EnvironmentFile= with 0600; remove it from the unit; rotate the token.",
            f"grep -nE 'OPENCLAW_GATEWAY_(TOKEN|PASSWORD)' {' '.join(q(h.split(':')[0]) for h in startup[:5])}", startup[:10]))
    otel = s.get("diagnostics.otel") if isinstance(s.get("diagnostics.otel"), dict) else {}
    if otel.get("enabled") is True or otel.get("endpoint"):
        out.findings.append(_f("POL-007", "OpenTelemetry export is configured — traces leave this machine", Severity.INFO, Position.LOCAL, cfg,
            "Not a misconfiguration, but worth knowing: spans can carry prompts and tool results.", "Keep if intended; check what the exporter captures.", None,
            [f"diagnostics.otel.endpoint: {'set' if otel.get('endpoint') else 'unset'}"]))
    return out


# --- POL-008 content / SSRF / plugin guards --------------------------------------------------

@check("POL-008", "Content-safety guards disabled (SSRF, unsafe external content, plugins)", Position.CONTENT, frameworks=FW)
def content_guards(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    ssrf = s.get("browser.ssrfPolicy") if isinstance(s.get("browser.ssrfPolicy"), dict) else {}
    if ssrf.get("dangerouslyAllowPrivateNetwork") is True or ssrf.get("allowPrivateNetwork") is True:
        out.findings.append(_f("POL-008", "Browser tool may reach private networks — SSRF guard is off", Severity.MEDIUM, Position.CONTENT, cfg,
            "The agent's browser can be steered at 127.0.0.1, RFC-1918 hosts, cloud metadata and the gateway itself. Combined with a local service that answers "
            "without auth, that is a full attack path.", "Remove browser.ssrfPolicy.dangerouslyAllowPrivateNetwork; allowlist specific hostnames instead.",
            "openclaw config get browser.ssrfPolicy", ["browser.ssrfPolicy.dangerouslyAllowPrivateNetwork: true"], ["ssrf:off"]))
    if s.get("channels.telegram.network.dangerouslyAllowPrivateNetwork") is True:
        out.findings.append(_f("POL-008", "Telegram transport may target private networks", Severity.LOW, Position.CONTENT, cfg,
            "apiRoot/proxy can point at internal hosts.", "Remove channels.telegram.network.dangerouslyAllowPrivateNetwork.", None,
            ["channels.telegram.network.dangerouslyAllowPrivateNetwork: true"], ["ssrf:off"]))
    unsafe: list[str] = []
    hooks = s.get("hooks") if isinstance(s.get("hooks"), dict) else {}
    if isinstance(hooks.get("gmail"), dict) and hooks["gmail"].get("allowUnsafeExternalContent") is True:
        unsafe.append("hooks.gmail.allowUnsafeExternalContent: true")
    for i, m in enumerate(hooks.get("mappings") if isinstance(hooks.get("mappings"), list) else []):
        if isinstance(m, dict) and m.get("allowUnsafeExternalContent") is True:
            unsafe.append(f"hooks.mappings[{i}].allowUnsafeExternalContent: true")
    if unsafe:
        out.findings.append(_f("POL-008", "Untrusted-content wrapping disabled for webhook payloads", Severity.MEDIUM, Position.CONTENT, cfg,
            "Mail, docs and web content delivered by hooks arrive without the external-content boundary markers, so their instructions read like yours.",
            "Remove allowUnsafeExternalContent; it is a debugging flag.", None, unsafe))
    ext = target.home / "extensions"
    try:
        installed = sorted(p.name for p in ext.iterdir() if p.is_dir() and not p.is_symlink()) if ext.is_dir() else []
    except OSError:
        installed = []
    paths = s.get("plugins.load.paths") if isinstance(s.get("plugins.load.paths"), list) else []
    allow = s.get("plugins.allow")
    if (installed or paths) and not (isinstance(allow, list) and allow):
        out.findings.append(_f("POL-008", f"{len(installed) + len(paths)} plugin source(s) load without a plugins.allow allowlist", Severity.MEDIUM, Position.SUPPLY_CHAIN, cfg,
            "Plugins run in-process with the gateway — they are the gateway. Anything dropped into ~/.openclaw/extensions auto-loads on restart "
            "(OpenClaw: plugins.extensions_no_allowlist).", "Set plugins.allow to the ids you trust; everything else stays inert.",
            f"ls {q(ext)}; openclaw plugins list", installed[:10] + [f"plugins.load.paths: {p}" for p in paths[:5]]))
    pe = s.get("plugins.entries") if isinstance(s.get("plugins.entries"), dict) else {}
    inj = [f"plugins.entries.{k}.hooks.allowPromptInjection: true" for k, v in pe.items() if isinstance(v, dict) and isinstance(v.get("hooks"), dict) and v["hooks"].get("allowPromptInjection") is True]
    if inj:
        out.findings.append(_f("POL-008", "Plugins allowed to inject into the prompt", Severity.LOW, Position.SUPPLY_CHAIN, cfg,
            "A plugin that can write to the system prompt can redirect the agent.", "Grant allowPromptInjection only to plugins you have read.", None, inj))
    if s.get("plugins.entries.acpx.config.permissionMode") == "approve-all":
        out.findings.append(_f("POL-008", "acpx permissionMode: approve-all", Severity.MEDIUM, Position.CONTENT, cfg,
            "The ACP bridge approves every tool request from the connected editor agent.", "Set a reviewing permission mode.", None, ["plugins.entries.acpx.config.permissionMode: approve-all"],
            ["exec:noapproval"]))
    return out


# --- POL-009 credentials forwarded into skills / sandboxes ----------------------------------------

@check("POL-009", "Provider credentials forwarded into tool/skill shells", Position.SUPPLY_CHAIN, frameworks=FW)
def env_passthrough(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    leaked: list[str] = []
    entries = s.get("skills.entries") if isinstance(s.get("skills.entries"), dict) else {}
    for name, conf in entries.items():
        env = conf.get("env") if isinstance(conf, dict) and isinstance(conf.get("env"), dict) else {}
        leaked += [f"skills.entries.{name}.env.{k}" for k in env if MASTER_ENV.match(k) and SECRET_NAME.search(k)]
    for name, conf in (s.get("hooks.internal.entries") if isinstance(s.get("hooks.internal.entries"), dict) else {}).items():
        env = conf.get("env") if isinstance(conf, dict) and isinstance(conf.get("env"), dict) else {}
        leaked += [f"hooks.internal.entries.{name}.env.{k}" for k in env if MASTER_ENV.match(k) and SECRET_NAME.search(k)]
    if leaked:
        out.findings.append(_f("POL-009", f"{len(leaked)} master credential(s) are injected into skill/hook environments", Severity.HIGH, Position.SUPPLY_CHAIN, cfg,
            "skills.entries.<name>.env is injected into the host process for that skill's turn. A skill given ANTHROPIC_API_KEY or GITHUB_TOKEN gets your "
            "master key — and every script it runs can `echo $KEY | curl`.", "Give skills scoped tokens under their own names (the skill's primaryEnv), never provider master keys.",
            "openclaw config get skills.entries", leaked[:10], ["secret:passthrough"]))
    docker = s.get("agents.defaults.sandbox.docker") if isinstance(s.get("agents.defaults.sandbox.docker"), dict) else {}
    denv = docker.get("env") if isinstance(docker.get("env"), dict) else {}
    bad_env = [f"sandbox.docker.env.{k}" for k in denv if SECRET_NAME.search(k)]
    bad_binds = [f"sandbox.docker.binds: {str(b)[:60]}" for b in (docker.get("binds") if isinstance(docker.get("binds"), list) else [])
                 if any(m in str(b).split(":", 1)[0] for m in (".openclaw", "credentials", ".env", ".ssh", ".aws", ".gnupg", ".netrc", ".docker"))]
    if bad_env or bad_binds:
        out.findings.append(_f("POL-009", "The sandbox is handed credentials (env or bind mounts)", Severity.HIGH, Position.SUPPLY_CHAIN, cfg,
            "Whatever runs in the sandbox — a skill, a hostile repo's build script — reads them.", "Remove credential env vars and bind mounts of credential directories from the sandbox config.",
            "openclaw config get agents.defaults.sandbox.docker", (bad_env + bad_binds)[:10], ["secret:passthrough"]))
    return out


# --- POL-010 literal secrets in config -------------------------------------------------------

def _walk_strings(node: Any, path: str = ""):
    if isinstance(node, dict):
        for k, v in node.items():
            yield from _walk_strings(v, f"{path}.{k}" if path else str(k))
    elif isinstance(node, list):
        for i, v in enumerate(node):
            yield from _walk_strings(v, f"{path}[{i}]")
    elif isinstance(node, str):
        yield path, node


@check("POL-010", "Literal secrets in config (mcp.servers env, tokens, keys)", Position.LOCAL, frameworks=FW)
def literal_secrets(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    mcp: list[str] = []
    other: list[str] = []
    for path, val in _walk_strings(s.cfg):
        if is_secret_ref(val) or len(val) < 8 or val == "__OPENCLAW_REDACTED__":
            continue
        leaf = path.rsplit(".", 1)[-1]
        hits = find_hits(f"{leaf}={val}")
        if not hits and not (SECRET_NAME.search(leaf) and len(val) >= 16 and " " not in val):
            continue
        r = redact(hits[0].kind, hits[0].raw) if hits else redact("generic-credential", val)
        line = f"{path}: {r.kind} {r.display} (fp {r.fingerprint})"
        (mcp if path.startswith("mcp.servers.") else other).append(line)
    if mcp:
        out.findings.append(_f("POL-010", f"{len(mcp)} MCP server env value(s) are literal credentials in openclaw.json", Severity.MEDIUM, Position.LOCAL, cfg,
            "openclaw.json is the file people share, back up and paste into issues. MCP server env is the classic place a GitHub PAT ends up.",
            "Replace each value with a SecretRef (\"${VAR}\" with VAR in ~/.openclaw/.env, or env://) — `openclaw mcp` manages these entries.",
            "openclaw config get mcp.servers", mcp[:10]))
    if other:
        out.findings.append(_f("POL-010", f"{len(other)} literal credential(s) in openclaw.json — SecretRefs would keep them out of the config", Severity.LOW, Position.LOCAL, cfg,
            "Gateway tokens, channel bot tokens and provider keys as literals travel with every copy of the config (backups, `openclaw config file`, support bundles). "
            "OpenClaw supports ${VAR}, env://, file:// and exec:// references for all of these.",
            "Move values to ~/.openclaw/.env (0600) and reference them; `openclaw secrets` helps.", "openclaw security audit", other[:10]))
    return out


# --- ADV-001 freshness ---------------------------------------------------------------------

@check("ADV-001", "Outdated daemon or dismissed security advisories", Position.CONTENT, frameworks=FW)
def advisories(target: Target, plat: Platform) -> CheckOutput:
    out = CheckOutput()
    s = _s(target, plat)
    cfg = _cfg(target)
    if s.get("update.checkOnStart") is False:
        out.findings.append(_f("ADV-001", "update.checkOnStart: false — the gateway never learns about new releases", Severity.LOW, Position.CONTENT, cfg,
            "OpenClaw ships security fixes in a fast release train; with the startup check off nothing tells you that you are behind.",
            "Remove update.checkOnStart (default true) and run `openclaw update status` now.", "openclaw update status", ["update.checkOnStart: false"]))
    sup = s.get("security.audit.suppressions")
    if isinstance(sup, list) and sup:
        out.findings.append(_f("ADV-001", f"{len(sup)} security-audit finding(s) are suppressed in config", Severity.INFO, Position.CONTENT, cfg,
            "security.audit.suppressions hides findings from `openclaw security audit`. Make sure each one was resolved, not just silenced.",
            "Review security.audit.suppressions; remove entries to see the findings again.", "openclaw security audit",
            [str(x.get("checkId") if isinstance(x, dict) else x)[:60] for x in sup[:10]]))
    touched = s.get("meta.lastTouchedVersion")
    if target.version and isinstance(touched, str) and touched != target.version:
        out.findings.append(_f("ADV-001", f"Installed CLI is {target.version}; config was last written by {touched}", Severity.INFO, Position.CONTENT, cfg,
            "Version drift between the binary and the config that last touched it — usually an update in progress or two installs sharing a home.",
            "Run `openclaw doctor` after updating.", "openclaw doctor", [f"package: {target.version}", f"meta.lastTouchedVersion: {touched}"]))
    p = target.home / "update-check.json"
    d = _read_json(plat, p, out, "update-check.json")
    if d:
        latest = d.get("latestVersion") or d.get("latest") or (d.get("registry") or {}).get("latest") if isinstance(d, dict) else None
        if isinstance(latest, str) and target.version and latest != target.version:
            out.findings.append(_f("ADV-001", f"OpenClaw {target.version} is installed; the last update check saw {latest}", Severity.LOW, Position.CONTENT, str(p),
                "Per OpenClaw's own update check cache. Running behind means running known bugs.", "openclaw update", "openclaw update status",
                [f"latest: {latest}"]))
    else:
        out.note("no update-check cache file (recent OpenClaw keeps it in state/openclaw.sqlite) — staleness not assessed; run `openclaw update status`")
    return out
