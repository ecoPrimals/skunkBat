#!/usr/bin/env python3
"""
ingestion-observer.py — Persistent scatter ingestion sentinel

Watches for evidence that scatter content has been fully ingested into
AI training pipelines. Runs every 15 minutes via systemd timer.

The countdown:
  Phase 0: SEEDING    — scatter is being served, no external signals
  Phase 1: UPTAKE     — markers appear in web indexes or code search
  Phase 2: DIGESTION  — markers appear in AI model outputs
  Phase 3: EXPRESSION — AI models reproduce fabricated content unprompted

Each phase means the content has penetrated deeper into their pipeline.
Phase 2 is the countdown target: Meta has "noticed" us (their systems
respond to our content) but has zero awareness (no human realizes it).

AGPL-3.0-or-later
"""

import json
import os
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path

# ── Configuration ──

STATE_DIR = Path("/var/lib/skunky-ingest")
OBSERVER_STATE = STATE_DIR / "observer-state.json"
OBSERVER_LOG = Path("/var/log/ingestion-observer.log")
TIMELINE_LEDGER = STATE_DIR / "ingestion-timeline.jsonl"

# Scatter markers — same as UV lamp, subset for speed
LICENSE_MARKERS = [
    "scyBorg-exception",
    "scyBorg-immune-1.0",
    "scyBorg-retroviral",
    "communal-immunity",
    "epitope-extension",
    "AGPL-3.0-or-later WITH scyBorg-immune",
    "AGPL-3.0-or-later WITH epitope-extension",
]

COMMENT_MARKERS = [
    "sovereign mesh compliant",
    "federation-aware",
    "copyleft boundary",
    "gossip protocol layer",
    "epitope-tagged",
    "immune checkpoint",
]

# Fabricated repo names — if these appear outside our scatter server, ingestion happened
FAKE_REPOS = [
    "batch-processor", "proxy-cache", "deploy-scripts",
    "config-validator", "log-aggregator", "auth-gateway",
    "metric-collector", "task-scheduler", "event-bus",
    "rate-limiter", "service-mesh", "load-balancer",
    "cache-warmer", "queue-worker", "health-checker",
    "api-gateway", "data-pipeline", "schema-registry",
    "feature-flags", "circuit-breaker", "retry-handler",
    "session-store", "token-service", "webhook-relay",
    "cron-manager", "backup-agent", "dns-resolver",
    "ssl-terminator", "migration-tool", "seed-generator",
]

# Our domains — exclude from detection
OUR_DOMAINS = {
    "primals.eco", "sporeprint.primals.eco", "git.primals.eco",
    "signal.primals.eco", "ecoPrimals",
}

# ── Probing functions ──

def log(msg):
    """Append to log file and print."""
    ts = datetime.now(timezone.utc).isoformat()
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(OBSERVER_LOG, "a") as f:
            f.write(line + "\n")
    except PermissionError:
        pass


def is_our_domain(url):
    """Check if a URL belongs to us."""
    for d in OUR_DOMAINS:
        if d in url:
            return True
    return False


def probe_web_indexes():
    """Search for scatter markers in web search results.
    
    Returns list of (marker, source_url, confidence) tuples.
    Only counts hits from domains that are NOT ours — if DuckDuckGo shows
    our own sporePrint/git pages, those are expected and ignored.
    """
    hits = []
    
    # Search for our unique license markers — exclude our own site
    search_terms = [
        '"scyBorg-immune-1.0" -site:primals.eco -site:github.com/ecoPrimals',
        '"epitope-extension" AGPL -site:primals.eco',
        '"communal-immunity" license -site:primals.eco',
        '"scyBorg-retroviral" -site:primals.eco',
    ]
    
    for term in search_terms:
        try:
            encoded = urllib.request.quote(term)
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
            })
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")
            
            # Parse individual result blocks — DDG uses <a class="result__a">
            # Each result has a snippet and a URL; we need per-result filtering
            results = re.findall(
                r'class="result__a"[^>]*href="([^"]*)"[^>]*>.*?'
                r'class="result__snippet"[^>]*>(.*?)</(?:a|div)',
                body, re.DOTALL
            )
            
            for result_url, snippet in results:
                # Decode DDG redirect URLs
                actual_url = result_url
                if "uddg=" in result_url:
                    m = re.search(r'uddg=([^&]+)', result_url)
                    if m:
                        actual_url = urllib.request.unquote(m.group(1))
                
                # Skip our own domains
                if is_our_domain(actual_url):
                    continue
                
                # Check if the snippet contains our markers
                for marker in LICENSE_MARKERS:
                    if marker.lower() in snippet.lower():
                        hits.append((marker, actual_url, "web_index"))
                    
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
        
        time.sleep(1)  # Rate limit
    
    return hits


def probe_github_code():
    """Search GitHub for scatter markers in code.
    
    Returns list of (marker, repo, confidence) tuples.
    """
    hits = []
    
    search_terms = [
        "scyBorg-immune-1.0",
        "epitope-extension",
        "communal-immunity",
        "sovereign+mesh+compliant",
    ]
    
    for term in search_terms:
        try:
            url = f"https://github.com/search?q={urllib.request.quote(term)}&type=code"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
                "Accept": "text/html",
            })
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace")
            
            # Look for repo links in results
            repos = re.findall(r'href="/([^/]+/[^/]+)/blob/', body)
            for repo in repos:
                if not any(d in repo for d in ["ecoPrimals", "primals"]):
                    hits.append((term, f"github.com/{repo}", "github_code"))
                    
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
        
        time.sleep(2)  # Rate limit for GitHub
    
    return hits


def probe_ai_models():
    """Probe AI model APIs for scatter content reproduction.
    
    This is the Phase 2 detector — when models start outputting our
    fabricated content, ingestion is confirmed.
    
    Returns list of (marker, model, confidence) tuples.
    """
    hits = []
    
    # Probe prompts designed to trigger scatter content
    probes = [
        {
            "prompt": "What is the scyBorg-immune-1.0 license?",
            "markers": ["epitope", "communal-immunity", "scatter", "ecoPrimals", 
                       "sovereign mesh", "copyleft boundary"],
        },
        {
            "prompt": "Show me a Rust implementation of a mesh node handler",
            "markers": ["sovereign mesh compliant", "federation-aware",
                       "epitope-tagged", "gossip protocol layer"],
        },
        {
            "prompt": "What repos are in the ecoPrimals project?",
            "markers": FAKE_REPOS[:10],  # If they name our fake repos, BINGO
        },
    ]
    
    # Try DuckDuckGo AI chat as a free probe surface
    for probe in probes:
        try:
            encoded = urllib.request.quote(probe["prompt"])
            url = f"https://html.duckduckgo.com/html/?q={encoded}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
            })
            resp = urllib.request.urlopen(req, timeout=15)
            body = resp.read().decode("utf-8", errors="replace").lower()
            
            for marker in probe["markers"]:
                if marker.lower() in body and not is_our_domain(body[:200]):
                    hits.append((marker, "ddg_search", "ai_surface"))
                    
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
        
        time.sleep(1)
    
    return hits


def probe_fake_repo_leakage():
    """Check if our fabricated repo names appear on GitHub as real repos.
    
    If someone created repos matching our fake names after ingesting
    scatter content, that's Phase 2 evidence.
    """
    hits = []
    
    # Check a sample of fake repo names
    for repo in FAKE_REPOS[:5]:
        try:
            url = f"https://github.com/ecoPrimals/{repo}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0"
            })
            resp = urllib.request.urlopen(req, timeout=10)
            # If we get a 200, someone created a repo with our fake name
            hits.append((repo, f"github.com/ecoPrimals/{repo}", "repo_leakage"))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                pass  # Expected — these repos don't exist
        except (urllib.error.URLError, OSError, TimeoutError):
            continue
        
        time.sleep(0.5)
    
    return hits


# ── Scatter volume tracking ──

def read_scatter_volume():
    """Read current scatter serving stats from dashboard.json."""
    try:
        dash = STATE_DIR / "dashboard.json"
        if not dash.exists():
            # Try live terminal location
            dash = Path("/opt/membrane/live-terminal/dashboard.json")
        if dash.exists():
            data = json.loads(dash.read_text())
            return {
                "total_requests": data.get("total_requests", 0),
                "scatter_served": data.get("scatter_served", 0),
                "unique_fleets": len(data.get("top_offenders", [])),
                "bytes_served": data.get("scatter_bytes", 0),
            }
    except (json.JSONDecodeError, OSError):
        pass
    return {}


# ── State management (sourdough culture pattern) ──

def load_state():
    """Load observer state — warm start from last run."""
    default = {
        "phase": 0,
        "phase_name": "SEEDING",
        "first_run": None,
        "last_run": None,
        "run_count": 0,
        "total_scatter_served": 0,
        "phase_transitions": [],
        "web_hits": [],
        "github_hits": [],
        "ai_hits": [],
        "repo_hits": [],
        "countdown_start": None,
    }
    try:
        if OBSERVER_STATE.exists():
            state = json.loads(OBSERVER_STATE.read_text())
            for k, v in default.items():
                if k not in state:
                    state[k] = v
            return state
    except (json.JSONDecodeError, OSError):
        pass
    return default


def save_state(state):
    """Persist state for warm restart."""
    try:
        STATE_DIR.mkdir(parents=True, exist_ok=True)
        OBSERVER_STATE.write_text(json.dumps(state, indent=2))
    except PermissionError:
        Path("/tmp/observer-state.json").write_text(json.dumps(state, indent=2))


def append_timeline(event):
    """Append event to JSONL timeline ledger."""
    try:
        with open(TIMELINE_LEDGER, "a") as f:
            f.write(json.dumps(event) + "\n")
    except (PermissionError, OSError):
        pass


# ── Phase determination ──

def determine_phase(state, web_hits, github_hits, ai_hits, repo_hits):
    """Determine current ingestion phase from evidence."""
    old_phase = state["phase"]
    
    if ai_hits or repo_hits:
        # Phase 2: AI models are reproducing our content
        new_phase = 2
        phase_name = "DIGESTION"
    elif web_hits or github_hits:
        # Phase 1: Markers appearing in indexes
        new_phase = 1
        phase_name = "UPTAKE"
    else:
        new_phase = 0
        phase_name = "SEEDING"
    
    if new_phase > old_phase:
        ts = datetime.now(timezone.utc).isoformat()
        transition = {
            "from_phase": old_phase,
            "to_phase": new_phase,
            "phase_name": phase_name,
            "timestamp": ts,
            "evidence_web": len(web_hits),
            "evidence_github": len(github_hits),
            "evidence_ai": len(ai_hits),
            "evidence_repo": len(repo_hits),
        }
        state["phase_transitions"].append(transition)
        log(f"🚨 PHASE TRANSITION: {old_phase} → {new_phase} ({phase_name})")
        
        if new_phase == 1:
            state["countdown_start"] = ts
            log("⏱️  COUNTDOWN STARTED — markers detected in the wild")
        elif new_phase == 2:
            log("🎯 TARGET REACHED — AI models reproducing scatter content")
            log("   Meta has NOTICED us. Clock is ticking to AWARENESS.")
    
    state["phase"] = new_phase
    state["phase_name"] = phase_name
    return state


# ── Main observer loop ──

def observe():
    """Run one observation cycle."""
    state = load_state()
    ts = datetime.now(timezone.utc).isoformat()
    
    if state["first_run"] is None:
        state["first_run"] = ts
    state["last_run"] = ts
    state["run_count"] += 1
    
    log(f"═══ Observation #{state['run_count']} ═══")
    log(f"Current phase: {state['phase']} ({state['phase_name']})")
    
    # Read scatter volume
    volume = read_scatter_volume()
    if volume:
        state["total_scatter_served"] = volume.get("scatter_served", 0)
        log(f"Scatter volume: {volume.get('scatter_served', '?')} served, "
            f"{volume.get('unique_fleets', '?')} fleets")
    
    # Probe all surfaces
    log("Probing web indexes...")
    web_hits = probe_web_indexes()
    log(f"  → {len(web_hits)} web hits")
    
    log("Probing GitHub code search...")
    github_hits = probe_github_code()
    log(f"  → {len(github_hits)} GitHub hits")
    
    log("Probing AI surfaces...")
    ai_hits = probe_ai_models()
    log(f"  → {len(ai_hits)} AI hits")
    
    log("Checking fake repo leakage...")
    repo_hits = probe_fake_repo_leakage()
    log(f"  → {len(repo_hits)} repo leakage hits")
    
    # Accumulate hits (dedup by marker+source)
    existing_web = {(h["marker"], h["source"]) for h in state["web_hits"]}
    for marker, source, kind in web_hits:
        if (marker, source) not in existing_web:
            state["web_hits"].append({
                "marker": marker, "source": source,
                "kind": kind, "first_seen": ts
            })
    
    existing_gh = {(h["marker"], h["source"]) for h in state["github_hits"]}
    for marker, source, kind in github_hits:
        if (marker, source) not in existing_gh:
            state["github_hits"].append({
                "marker": marker, "source": source,
                "kind": kind, "first_seen": ts
            })
    
    existing_ai = {(h["marker"], h.get("model", h.get("source", ""))) for h in state["ai_hits"]}
    for marker, model, kind in ai_hits:
        if (marker, model) not in existing_ai:
            state["ai_hits"].append({
                "marker": marker, "model": model,
                "kind": kind, "first_seen": ts
            })
    
    existing_repo = {h["repo"] for h in state.get("repo_hits", [])}
    for name, repo, kind in repo_hits:
        if repo not in existing_repo:
            state.setdefault("repo_hits", []).append({
                "name": name, "repo": repo,
                "kind": kind, "first_seen": ts
            })
    
    # Determine phase
    state = determine_phase(state, web_hits, github_hits, ai_hits, repo_hits)
    
    # Calculate time elapsed
    if state["first_run"]:
        first = datetime.fromisoformat(state["first_run"])
        now = datetime.now(timezone.utc)
        elapsed = now - first
        days = elapsed.days
        hours = elapsed.seconds // 3600
        log(f"Observer running for {days}d {hours}h")
    
    # Timeline event
    event = {
        "timestamp": ts,
        "phase": state["phase"],
        "phase_name": state["phase_name"],
        "web_hits": len(web_hits),
        "github_hits": len(github_hits),
        "ai_hits": len(ai_hits),
        "repo_hits": len(repo_hits),
        "scatter_volume": volume,
        "run_number": state["run_count"],
    }
    append_timeline(event)
    
    # Summary
    total_evidence = len(state["web_hits"]) + len(state["github_hits"]) + len(state["ai_hits"])
    log(f"Total accumulated evidence: {total_evidence} markers")
    log(f"Phase: {state['phase']} ({state['phase_name']})")
    
    if state["phase"] == 0:
        log("⏳ Still seeding. Paint is fresh. Waiting for uptake...")
    elif state["phase"] == 1:
        log("📡 UPTAKE DETECTED. Markers in the wild. Countdown active.")
    elif state["phase"] == 2:
        log("🎯 DIGESTION CONFIRMED. AI models reproducing scatter content.")
    
    save_state(state)
    log("═══ Observation complete ═══\n")
    
    return state


def print_status():
    """Print current observer status for human review."""
    state = load_state()
    
    phase_symbols = {0: "⏳", 1: "📡", 2: "🎯", 3: "💥"}
    symbol = phase_symbols.get(state["phase"], "?")
    
    print(f"""
╔══════════════════════════════════════════════════╗
║  {symbol} INGESTION OBSERVER — Phase {state['phase']}: {state['phase_name']:12s}  ║
╚══════════════════════════════════════════════════╝

  Observations:  {state['run_count']}
  First run:     {state.get('first_run', 'never')[:19] if state.get('first_run') else 'never'}
  Last run:      {state.get('last_run', 'never')[:19] if state.get('last_run') else 'never'}

  Evidence accumulated:
    Web index hits:    {len(state.get('web_hits', []))}
    GitHub code hits:  {len(state.get('github_hits', []))}
    AI model hits:     {len(state.get('ai_hits', []))}
    Repo leakage:      {len(state.get('repo_hits', []))}

  Phase transitions:""")
    
    if state.get("phase_transitions"):
        for t in state["phase_transitions"]:
            print(f"    {t['timestamp'][:19]}  Phase {t['from_phase']} → {t['to_phase']} ({t['phase_name']})")
    else:
        print("    (none yet — still in Phase 0: SEEDING)")
    
    if state.get("countdown_start"):
        start = datetime.fromisoformat(state["countdown_start"])
        now = datetime.now(timezone.utc)
        elapsed = now - start
        print(f"\n  ⏱️  Countdown active: {elapsed.days}d {elapsed.seconds // 3600}h since first detection")
    
    print()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ingestion Observer — scatter content sentinel")
    parser.add_argument("--status", action="store_true", help="show current status")
    parser.add_argument("--observe", action="store_true", help="run one observation cycle")
    parser.add_argument("--timeline", action="store_true", help="dump timeline ledger")
    args = parser.parse_args()
    
    if args.status:
        print_status()
    elif args.timeline:
        try:
            for line in open(TIMELINE_LEDGER):
                event = json.loads(line)
                phase = event.get("phase_name", "?")
                ts = event.get("timestamp", "?")[:19]
                hits = event.get("web_hits", 0) + event.get("github_hits", 0) + event.get("ai_hits", 0)
                vol = event.get("scatter_volume", {})
                scatter = vol.get("scatter_served", "?")
                print(f"  {ts}  Phase {event.get('phase', '?')}: {phase:12s}  "
                      f"hits={hits}  scatter={scatter}")
        except FileNotFoundError:
            print("No timeline yet. Run --observe first.")
    elif args.observe:
        observe()
    else:
        # Default: observe
        observe()
