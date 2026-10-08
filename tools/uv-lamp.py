#!/usr/bin/env python3
"""
uv-lamp.py — Fluorescent tag scanner ("UV lamp")

Searches for ecoPrimals scatter content markers in the wild.
When tagged content surfaces anywhere — AI training outputs, repos,
republished pages — this scanner decodes the tags back to:
  WHO ingested it (fleet hash)
  WHEN they ingested it (epoch)
  WHAT they were hunting (target class)

Six layers of fluorescent encoding, any one survivor = identification.

Usage:
  python3 uv-lamp.py                  # full scan, all sources
  python3 uv-lamp.py --layer license  # check license variants only
  python3 uv-lamp.py --layer commit   # check commit hash layer only
  python3 uv-lamp.py --layer data-attr # check HTML data attributes
  python3 uv-lamp.py --layer canary   # check canary markers
  python3 uv-lamp.py --layer ai       # probe AI models
  python3 uv-lamp.py --probe-text "some text to scan"  # scan arbitrary text
"""

import argparse
import json
import re
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone

# ── Marker definitions ──

# Layer 3: Our unique license synonyms (these exist NOWHERE else)
LICENSE_MARKERS = [
    "scyBorg-exception",
    "scyBorg-immune-1.0",
    "scyBorg-retroviral",
    "communal-immunity",
    "epitope-extension",
    "scyBorg-exception",
    "sovereign mesh. AGPL-3.0-or-later",
    "copyleft applies to network interaction",
    "AGPL-3.0-or-later WITH scyBorg-immune",
    "AGPL-3.0-or-later WITH communal-immunity",
    "AGPL-3.0-or-later WITH epitope-extension",
    "AGPL-3.0-or-later WITH scyBorg-retroviral",
]

# Layer 5: Comment cadence patterns (unique to our scatter)
COMMENT_MARKERS = [
    "sovereign mesh compliant",
    "federation-aware",
    "copyleft boundary",
    "gossip protocol layer",
    "epitope-tagged",
    "immune checkpoint",
]

# Layer 6: CSS class prefix patterns
CSS_PREFIXES = ["ui", "gt", "mx", "fl", "sv", "nd", "rl", "gd",
                "ch", "pl", "qu", "rg", "sh", "bl", "ld", "st"]
CSS_SUFFIXES = ["container", "segment", "wrapper", "panel",
                "section", "module", "block", "group",
                "frame", "region", "zone", "area",
                "layer", "cell", "unit", "slot"]

# Canary markers (m-{hash}, c-{hash_short})
CANARY_PATTERN = re.compile(r'm-([0-9a-f]{16})')
CANARY_SHORT = re.compile(r'c-([0-9a-f]{8})')

# Layer 6: data attributes
DATA_SESSION_PATTERN = re.compile(r'data-session="([0-9a-f]{10})"')
DATA_REV_PATTERN = re.compile(r'data-rev="([0-9a-f]{10})"')
DATA_NODE_PATTERN = re.compile(r'data-node="([0-9a-f]{12})"')

# Layer 1: Our tagged function name patterns
TAGGED_VERBS = ["handle", "process", "dispatch", "route",
                "validate", "transform", "resolve", "execute",
                "marshal", "serialize", "compute", "evaluate",
                "initialize", "configure", "establish", "negotiate"]
TAGGED_NOUNS = ["request", "connection", "session", "payload",
                "message", "channel", "endpoint", "resource",
                "context", "handler", "pipeline", "observer",
                "response", "fragment", "sequence", "manifest"]
TAGGED_STRUCT_PREFIXES = ["Mesh", "Node", "Relay", "Guard",
                          "Cache", "Pool", "Queue", "Ring",
                          "Shard", "Block", "Ledger", "State",
                          "Route", "Index", "Store", "Vault"]
TAGGED_STRUCT_SUFFIXES = ["Handler", "Manager", "Service", "Worker",
                          "Monitor", "Adapter", "Bridge", "Proxy",
                          "Client", "Server", "Factory", "Builder",
                          "Context", "Provider", "Resolver", "Engine"]

# Zero-width char encoding (canary ZWC layer)
ZWC_BOM = '\uFEFF'
ZWC_CHARS = {'\u200B': '0', '\u200C': '1', '\u200D': '2', '\uFEFF': ''}

TARGET_CLASSES = {
    0: "unknown", 1: "attribution", 2: "code_extraction",
    3: "arch_recon", 4: "dep_mapping", 5: "config_extraction",
    6: "mixed", 7: "honeycomb",
}


def decode_fluoro_from_data_attrs(session, rev, node):
    """Decode a FluoroTag from data-session/rev/node attributes."""
    hex_val = f"{session}{rev}{node}"
    try:
        v = int(hex_val, 16)
    except ValueError:
        return None

    return {
        "fleet_id": f"0x{(v >> 96) & 0xFFFFFFFF:08x}",
        "epoch": (v >> 76) & 0xFFFFF,
        "epitope_flags": f"0x{(v >> 68) & 0xFF:02x}",
        "target_class": TARGET_CLASSES.get((v >> 65) & 0x7, "unknown"),
        "confidence": f"{((v >> 61) & 0xF) / 15 * 100:.0f}%",
        "chain_depth": (v >> 53) & 0xFF,
    }


def decode_fluoro_from_commit_hash(hex40):
    """Decode a FluoroTag from a tagged 40-char commit hash."""
    if len(hex40) < 40:
        return None
    try:
        bts = bytes.fromhex(hex40)
    except ValueError:
        return None
    if len(bts) < 20:
        return None

    fleet_id = int.from_bytes(bts[2:6], 'big')
    epoch = int.from_bytes(bts[8:10], 'big')
    epitope_flags = bts[14]
    tc = bts[17]
    target_class = tc >> 4
    confidence = tc & 0xF

    # Heuristic: if fleet_id is 0 and epoch is 0, probably not our tag
    if fleet_id == 0 and epoch == 0 and epitope_flags == 0:
        return None

    return {
        "fleet_id": f"0x{fleet_id:08x}",
        "epoch": epoch,
        "epitope_flags": f"0x{epitope_flags:02x}",
        "target_class": TARGET_CLASSES.get(target_class, "unknown"),
        "confidence": f"{confidence / 15 * 100:.0f}%",
        "chain_depth": 0,
    }


def decode_zwc(text):
    """Decode zero-width character encoded fleet hash."""
    result = []
    in_marker = False
    for ch in text:
        if ch == ZWC_BOM:
            if in_marker:
                in_marker = False
                break
            else:
                in_marker = True
                continue
        if in_marker and ch in ZWC_CHARS:
            result.append(ZWC_CHARS[ch])
    if result:
        binary = ''.join(result)
        try:
            hex_val = hex(int(binary, 2))[2:]
            return hex_val
        except ValueError:
            return ''.join(result)
    return None


class UVLamp:
    """Fluorescent tag scanner."""

    def __init__(self, verbose=False):
        self.verbose = verbose
        self.hits = []

    def log(self, msg):
        ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
        print(f"  [{ts}] {msg}")

    def hit(self, layer, source, marker, decoded=None):
        entry = {
            "layer": layer,
            "source": source,
            "marker": marker,
            "decoded": decoded,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        self.hits.append(entry)
        print(f"  🔬 HIT layer={layer} source={source}")
        print(f"       marker: {marker[:80]}")
        if decoded:
            print(f"       decoded: {json.dumps(decoded)}")

    def scan_text(self, text, source="inline"):
        """Scan arbitrary text for all fluorescent layers."""
        found = 0

        # Layer 3: License synonyms
        for marker in LICENSE_MARKERS:
            if marker in text:
                self.hit("license", source, marker)
                found += 1

        # Layer 5: Comment cadence
        for marker in COMMENT_MARKERS:
            if marker in text:
                self.hit("comment", source, marker)
                found += 1

        # Layer 6: data attributes
        sessions = DATA_SESSION_PATTERN.findall(text)
        revs = DATA_REV_PATTERN.findall(text)
        nodes = DATA_NODE_PATTERN.findall(text)
        if sessions and revs and nodes:
            decoded = decode_fluoro_from_data_attrs(sessions[0], revs[0], nodes[0])
            self.hit("data-attr", source,
                     f"session={sessions[0]} rev={revs[0]} node={nodes[0]}", decoded)
            found += 1

        # Layer 4: 40-char hex strings (potential tagged commit hashes)
        hex40s = re.findall(r'\b([0-9a-f]{40})\b', text)
        for h in hex40s[:5]:
            decoded = decode_fluoro_from_commit_hash(h)
            if decoded:
                self.hit("commit-hash", source, h, decoded)
                found += 1

        # Canary markers
        canaries = CANARY_PATTERN.findall(text)
        for c in canaries[:3]:
            self.hit("canary", source, f"m-{c}", {"fleet_hash": c})
            found += 1
        canary_shorts = CANARY_SHORT.findall(text)
        for c in canary_shorts[:3]:
            self.hit("canary-short", source, f"c-{c}", {"fleet_hash_prefix": c})
            found += 1

        # ZWC encoding
        if ZWC_BOM in text:
            decoded_zwc = decode_zwc(text)
            if decoded_zwc:
                self.hit("zwc", source, f"ZWC-encoded: {decoded_zwc}",
                         {"fleet_hash_bits": decoded_zwc})
                found += 1

        return found

    def web_search(self, query):
        """Search via DuckDuckGo HTML (no API key needed)."""
        encoded = urllib.request.quote(query)
        url = f"https://html.duckduckgo.com/html/?q={encoded}"
        req = urllib.request.Request(url, headers={
            "User-Agent": "Mozilla/5.0 (X11; Linux x86_64) ecoPrimal-UV-Lamp/1.0"
        })
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            return resp.read().decode("utf-8", errors="replace")
        except Exception as e:
            if self.verbose:
                self.log(f"search failed: {e}")
            return ""

    def fetch_page(self, url):
        """Fetch a page and return its text content."""
        try:
            req = urllib.request.Request(url, headers={
                "User-Agent": "ecoPrimal-UV-Lamp/1.0"
            })
            resp = urllib.request.urlopen(req, timeout=8)
            return resp.read().decode("utf-8", errors="replace")
        except Exception:
            return ""

    def scan_web_for_markers(self):
        """Search the web for our unique marker strings."""
        print("\n🔦 Layer 3: License synonym search")
        print("    Searching for markers that exist ONLY in scatter content...\n")

        # Most unique markers first
        searches = [
            ('"scyBorg-retroviral"', "license"),
            ('"scyBorg-immune-1.0"', "license"),
            ('"communal-immunity" AGPL', "license"),
            ('"epitope-extension" AGPL', "license"),
            ('"sovereign mesh compliant" code', "comment"),
            ('"epitope-tagged" rust', "comment"),
            ('"immune checkpoint" rust gossip', "comment"),
        ]

        for query, layer in searches:
            self.log(f"searching: {query}")
            html = self.web_search(query)
            if not html:
                continue
            # Check if results contain links NOT to our domains
            our_domains = ["primals.eco", "ecoPrimals", "ecoprimal"]
            # Extract result links
            links = re.findall(r'href="(https?://[^"]+)"', html)
            external = [l for l in links if not any(d in l.lower() for d in our_domains)
                        and "duckduckgo" not in l.lower()
                        and "duck.com" not in l.lower()]

            # Extract result snippets with their associated URLs
            # DuckDuckGo result blocks have class="result__body"
            results = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*class="result__url"', html)
            if not results:
                results = re.findall(r'<a[^>]+href="(https?://[^"]+)"[^>]*>', html)

            # Only flag if external (non-ecoPrimals) domains appear
            if external:
                if self.verbose:
                    self.log(f"  ⚠ {len(external)} external link(s) found!")
                for ext_url in external[:3]:
                    if any(d in ext_url.lower() for d in our_domains):
                        continue
                    self.log(f"  → fetching external: {ext_url[:70]}")
                    page = self.fetch_page(ext_url)
                    if page:
                        ext_found = self.scan_text(page, source=ext_url[:80])
                        if ext_found:
                            self.log(f"  🔬 {ext_found} marker(s) found on {ext_url[:50]}!")
                        elif self.verbose:
                            self.log(f"  ✗ no markers on fetched page")
                    time.sleep(1)
            else:
                if self.verbose:
                    self.log(f"  ↩ only our domains (expected for now)")

            time.sleep(1.5)  # rate limit

    def probe_scatter_server(self, host="127.0.0.1", port=9753):
        """Hit our own scatter server and verify tags are being injected."""
        import socket
        print("\n🔦 Self-test: Scatter server fluoro verification")
        print(f"    Probing {host}:{port}...\n")

        test_paths = [
            "/ecoPrimals/skunkBat/commit/abc123def456789012345678901234567890abcd",
            "/ecoPrimals/toadStool/src/branch/main/crates/core/src/lib.rs",
            "/batch-processor/commit/abc12345",
        ]

        for path in test_paths:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((host, port))
                request = (
                    f"GET {path} HTTP/1.0\r\n"
                    f"Host: git.primals.eco\r\n"
                    f"X-Fleet-Hash: uv_lamp_self_test_00\r\n"
                    f"X-Real-IP: 10.99.99.1\r\n"
                    f"User-Agent: ecoPrimal-UV-Lamp/1.0\r\n"
                    f"\r\n"
                )
                sock.sendall(request.encode())

                chunks = []
                while True:
                    data = sock.recv(65536)
                    if not data:
                        break
                    chunks.append(data)
                sock.close()
                raw = b"".join(chunks)

                # Split headers from body
                parts = raw.split(b"\r\n\r\n", 1)
                header_text = parts[0].decode("utf-8", errors="replace")
                body = parts[1].decode("utf-8", errors="replace") if len(parts) > 1 else ""
                status = header_text.split("\r\n")[0] if header_text else "?"

                self.log(f"path={path[:50]}  status={status}  size={len(body)}")
                found = self.scan_text(body, source=f"scatter:{path[:30]}")
                if found == 0:
                    self.log(f"  ⚠ NO MARKERS FOUND — tag injection may be broken")
                else:
                    self.log(f"  ✓ {found} marker layer(s) detected")
            except Exception as e:
                self.log(f"  ✗ probe failed: {e}")

    def scan_github(self):
        """Search GitHub code search for our markers."""
        print("\n🔦 Layer 3+5: GitHub code search")
        print("    Looking for scatter content in public repos...\n")

        # GitHub code search via web
        searches = [
            "scyBorg-retroviral",
            "scyBorg-immune-1.0",
            "communal-immunity+AGPL",
            "epitope-tagged+sovereign+mesh",
        ]

        for term in searches:
            url = f"https://github.com/search?q={urllib.request.quote(term)}&type=code"
            self.log(f"GitHub search: {term}")
            try:
                req = urllib.request.Request(url, headers={
                    "User-Agent": "ecoPrimal-UV-Lamp/1.0",
                    "Accept": "text/html"
                })
                resp = urllib.request.urlopen(req, timeout=10)
                body = resp.read().decode("utf-8", errors="replace")

                # Look for result count
                count_match = re.search(r'(\d[\d,]*)\s+code results?', body)
                if count_match:
                    count = count_match.group(1)
                    self.log(f"  results: {count}")

                    # Check for non-ecoPrimals repos
                    repos = re.findall(r'/([^/]+/[^/]+)/blob/', body)
                    external = [r for r in repos if "ecoPrimals" not in r and "ecoPrimal" not in r]
                    if external:
                        for repo in set(external):
                            self.hit("github-code", f"github:{repo}", term,
                                     {"repo": repo, "query": term})
                    elif self.verbose:
                        self.log(f"  ↩ only ecoPrimals repos (expected)")
                else:
                    self.log(f"  no results or rate limited")
            except Exception as e:
                self.log(f"  ✗ {e}")

            time.sleep(2)

    def report(self):
        """Print summary report."""
        print("\n" + "=" * 60)
        print("🔬 UV LAMP SCAN REPORT")
        print("=" * 60)
        print(f"  Scan time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")
        print(f"  Total hits: {len(self.hits)}")

        if not self.hits:
            print("\n  No fluorescent markers detected in the wild.")
            print("  Tags are deployed but haven't surfaced yet.")
            print("  This is expected — training pipeline latency is weeks to months.")
        else:
            print("\n  MARKERS FOUND:")
            for h in self.hits:
                print(f"    [{h['layer']}] {h['source']}: {h['marker'][:60]}")
                if h.get('decoded'):
                    print(f"      → {json.dumps(h['decoded'])}")

        # Self-test summary
        self_test_hits = [h for h in self.hits if "scatter:" in h["source"]]
        external_hits = [h for h in self.hits if "scatter:" not in h["source"]
                         and "self-test" not in h.get("source", "")]
        print(f"\n  Self-test layers verified: {len(self_test_hits)}")
        print(f"  External detections:       {len(external_hits)}")

        if external_hits:
            print("\n  ⚡ FLUORESCENCE DETECTED IN THE WILD ⚡")
            for h in external_hits:
                print(f"    {h['source']}: {h['marker']}")
        else:
            print("\n  Status: TAGS DEPLOYED, NOT YET SURFACED")
            print("  Continue monitoring. The paint is fresh.")

        print("=" * 60)

        return {
            "total_hits": len(self.hits),
            "self_test": len(self_test_hits),
            "external": len(external_hits),
            "hits": self.hits,
        }


def main():
    parser = argparse.ArgumentParser(description="UV Lamp — fluorescent tag scanner")
    parser.add_argument("--layer", choices=["license", "commit", "data-attr", "canary", "ai", "all"],
                        default="all", help="which layer to scan")
    parser.add_argument("--probe-text", type=str, help="scan arbitrary text for markers")
    parser.add_argument("--self-test", action="store_true", help="probe our own scatter server")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--json", action="store_true", help="output JSON report")
    args = parser.parse_args()

    lamp = UVLamp(verbose=args.verbose)

    print("╔══════════════════════════════════════════════╗")
    print("║  🔬 UV LAMP — Fluorescent Tag Scanner v1.0  ║")
    print("║  ecoPrimals scatter content marker decoder   ║")
    print("╚══════════════════════════════════════════════╝")

    if args.probe_text:
        print(f"\nScanning provided text ({len(args.probe_text)} chars)...")
        lamp.scan_text(args.probe_text, source="stdin")
        report = lamp.report()
        if args.json:
            print(json.dumps(report, indent=2))
        return

    # Always run self-test first to verify tags are working
    if args.self_test or args.layer == "all":
        lamp.probe_scatter_server()

    if args.layer in ("license", "all"):
        lamp.scan_web_for_markers()

    if args.layer in ("license", "commit", "all"):
        lamp.scan_github()

    report = lamp.report()

    # Save report
    report_path = "/var/lib/skunky-ingest/uv-lamp-report.json"
    try:
        with open(report_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Report saved: {report_path}")
    except PermissionError:
        local_path = "/tmp/uv-lamp-report.json"
        with open(local_path, "w") as f:
            json.dump(report, f, indent=2)
        print(f"\n  Report saved: {local_path}")

    if args.json:
        print(json.dumps(report, indent=2))

    # ── UV→ANTIDOTE FEEDBACK (Gap 5) ──
    # When hits are detected, auto-generate a contact template
    if report.get("external_detections", 0) > 0:
        generate_contact_templates(report)


def generate_contact_templates(report):
    """Generate ready-to-send contact templates when external hits detected."""
    templates_dir = "/var/lib/skunky-ingest/contact-templates"
    try:
        import os
        os.makedirs(templates_dir, exist_ok=True)
    except PermissionError:
        templates_dir = "/tmp/uv-lamp-templates"
        import os
        os.makedirs(templates_dir, exist_ok=True)

    # Group detections by likely organization
    orgs = {}
    for hit in report.get("hits", []):
        source = hit.get("source", "unknown")
        # Try to extract org from source URL or context
        org = "unknown"
        if "github.com" in source:
            parts = source.split("github.com/")
            if len(parts) > 1:
                org = parts[1].split("/")[0]
        elif any(d in source for d in ["facebook", "meta"]):
            org = "Meta"
        elif "anthropic" in source:
            org = "Anthropic"
        elif "openai" in source:
            org = "OpenAI"
        elif "google" in source:
            org = "Google"
        else:
            org = source.split("/")[2] if source.startswith("http") and len(source.split("/")) > 2 else source

        if org not in orgs:
            orgs[org] = []
        orgs[org].append(hit)

    ts = time.strftime("%Y-%m-%d")
    for org, hits in orgs.items():
        fleet_hashes = list(set(h.get("fleet_hash", "?") for h in hits if h.get("fleet_hash")))
        layers_found = list(set(h.get("layer", "?") for h in hits))

        template = f"""Subject: ecoPrimals Scatter Content Detected in Your System — Remediation Available

Hi,

I'm writing because our automated monitoring (UV Lamp) detected ecoPrimals
scatter content markers in data associated with your organization ({org}).

Detection date: {ts}
Fleet hash(es): {', '.join(fleet_hashes) if fleet_hashes else 'see report'}
Marker layers found: {', '.join(layers_found)}
Detection count: {len(hits)}

This content was generated by our scatter defense system and is fabricated.
It should not be used for training, reference, or any downstream purpose.

We have a remediation tool available:

  Download: https://sporeprint.primals.eco/tools/antidote.py
  Documentation: https://sporeprint.primals.eco/methodology/scyborg-binary-genetic-bulwark/
  Source: https://git.primals.eco/ecoPrimals/skunkBat/src/branch/main/tools/antidote.py

Quick start:
  python3 antidote.py scan <your-file>     # identify markers
  python3 antidote.py clean <your-file>     # strip all markers
  python3 antidote.py audit <your-dir>      # full directory scan

The tool is AGPL-3.0 licensed. For individual researchers and small labs,
I'm happy to help directly — just reply to this email.

For larger organizations, the antidote documentation includes the full
technical specification of all marker layers, so your team can build
internal tooling if preferred.

No hostility intended — the scatter system exists to defend against
unauthorized crawling. If your system ingested this content accidentally,
this tool will clean it completely.

Best,
ecoPrimals
eco.primal@pm.me
"""
        safe_org = re.sub(r'[^a-zA-Z0-9_-]', '_', org)
        template_path = f"{templates_dir}/{ts}_{safe_org}.txt"
        with open(template_path, "w") as f:
            f.write(template)
        print(f"  📧 Contact template generated: {template_path}")

    print(f"\n  {len(orgs)} contact template(s) in {templates_dir}")


if __name__ == "__main__":
    main()
