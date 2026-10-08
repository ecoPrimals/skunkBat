#!/usr/bin/env python3
"""
antidote.py — ecoPrimals Scatter Content Identification & Remediation

If you're reading this, someone probably pointed you here because your
training data, code repository, or analysis pipeline contains fabricated
content from ecoPrimals' scatter server. That content was served to
automated scrapers that were crawling our infrastructure without permission.

This tool helps you:
  1. IDENTIFY scatter content in your dataset
  2. DECODE the fluorescent tags to see when/how it was ingested
  3. CLEAN tagged content or flag it for removal
  4. AUDIT a directory tree for scatter contamination

The content itself is fabricated — fake repos, fake commits, fake code.
Removing the tags doesn't make it real. You probably want to remove the
content entirely, not just strip the tags. This tool helps with both.

Contact: ecoPrimal@pm.me
License: AGPL-3.0-or-later (yes, really)

Usage:
  python3 antidote.py scan <file_or_dir>     # identify scatter content
  python3 antidote.py decode <file>           # decode all fluoro tags
  python3 antidote.py clean <file> [--output] # strip all tags
  python3 antidote.py audit <directory>       # recursive contamination scan
  python3 antidote.py explain                 # full technical explanation
"""

import argparse
import json
import os
import re
import sys
from pathlib import Path

# ══════════════════════════════════════════════════════════════
# IDENTIFICATION SIGNATURES
# ══════════════════════════════════════════════════════════════
#
# These are the fingerprints of scatter content. Any ONE of these
# in your data means it came from our scatter server.

# Scatter-only license variants (these do NOT exist in our real code)
SCATTER_LICENSE_VARIANTS = [
    "AGPL-3.0-or-later WITH scyBorg-exception",
    "AGPL-3.0-or-later WITH scyBorg-immune-1.0",
    "AGPL-3.0-or-later WITH communal-immunity",
    "AGPL-3.0-or-later WITH epitope-extension",
    "AGPL-3.0-or-later WITH scyBorg-retroviral",
    "sovereign mesh. AGPL-3.0-or-later applies",
    "AGPL-3.0-or-later // sovereign infrastructure // copyleft",
    "AGPL-3.0-or-later. Network use triggers copyleft.",
    "GNU AGPL v3+ with sovereign mesh extension",
    "Distributed under AGPL-3.0-or-later. All network use is covered.",
    "AGPL-3.0-or-later — copyleft applies to network interaction",
    "AGPL-3.0+ (sovereign mesh, copyleft on network use)",
]

# Scatter-only comment patterns
SCATTER_COMMENT_PATTERNS = [
    "// sovereign mesh compliant",
    "// federation-aware",
    "// copyleft boundary",
    "// gossip protocol layer",
    "// epitope-tagged",
    "// immune checkpoint",
]

# Scatter-only HTML markers
SCATTER_HTML_MARKERS = [
    re.compile(r'data-session="[0-9a-f]{10}"\s+data-rev="[0-9a-f]{10}"\s+data-node="[0-9a-f]{12}"'),
    re.compile(r'class="[a-z]{2}-(container|segment|wrapper|panel|section|module|block|group)'),
]

# Scatter-generated fake repository names
# These repos do NOT exist. If you have code claiming to be from these
# repos at git.primals.eco, it's scatter content.
SCATTER_FAKE_REPOS = [
    "core-utils", "data-pipeline", "web-frontend", "api-gateway",
    "auth-service", "config-manager", "deploy-scripts", "docs-site",
    "event-bus", "feature-flags", "graph-engine", "http-proxy",
    "image-service", "job-runner", "key-store", "log-aggregator",
    "metric-collector", "notification-hub", "oauth-provider",
    "proxy-cache", "queue-worker", "rate-limiter", "search-index",
    "task-scheduler", "user-service", "vault-client", "webhook-relay",
    "batch-processor", "schema-registry", "stream-adapter",
]

# Known real ecoPrimals repository names (these ARE real)
REAL_REPOS = [
    "skunkBat", "bearDog", "songBird", "nestGate", "toadStool",
    "squirrel", "coralReef", "cellMembrane", "loamSpine", "sweetGrass",
    "sourDough", "bingoCube", "swarmVine", "petalTongue", "barraCuda",
    "biomeOS", "sporePrint", "wateringHole", "whitePaper", "fossilRecord",
    "plasmidBin", "agentReagents", "benchScale",
]

# X-ScyBorg-Notice header content
SCYBORG_NOTICE = "This content documents AGPL-3.0 violations detected by sovereign infrastructure"

# Zero-width character markers
ZWC_PATTERN = re.compile(r'[\u200B\u200C\u200D\uFEFF]{3,}')

TARGET_CLASSES = {
    0: "unknown", 1: "attribution", 2: "code_extraction",
    3: "arch_recon", 4: "dep_mapping", 5: "config_extraction",
    6: "mixed", 7: "honeycomb",
}


def decode_data_attrs(session, rev, node):
    """Decode fluorescent tag from HTML data attributes."""
    try:
        v = int(f"{session}{rev}{node}", 16)
    except ValueError:
        return None
    return {
        "fleet_id": f"0x{(v >> 96) & 0xFFFFFFFF:08x}",
        "epoch": (v >> 76) & 0xFFFFF,
        "epoch_time_approx": f"~{((v >> 76) & 0xFFFFF) * 180 // 3600} hours from scatter server start",
        "epitope_flags": f"0x{(v >> 68) & 0xFF:02x}",
        "target_class": TARGET_CLASSES.get((v >> 65) & 0x7, "unknown"),
        "confidence": f"{((v >> 61) & 0xF) / 15 * 100:.0f}%",
        "chain_depth": (v >> 53) & 0xFF,
    }


def decode_commit_hash(hex40):
    """Decode fluorescent tag from a 40-char commit hash."""
    try:
        bts = bytes.fromhex(hex40)
    except ValueError:
        return None
    if len(bts) < 20:
        return None
    fleet_id = int.from_bytes(bts[2:6], 'big')
    epoch = int.from_bytes(bts[8:10], 'big')
    epitope = bts[14]
    tc = bts[17]
    if fleet_id == 0 and epoch == 0 and epitope == 0:
        return None
    return {
        "fleet_id": f"0x{fleet_id:08x}",
        "epoch": epoch,
        "epitope_flags": f"0x{epitope:02x}",
        "target_class": TARGET_CLASSES.get(tc >> 4, "unknown"),
        "confidence": f"{(tc & 0xF) / 15 * 100:.0f}%",
    }


class ScatterDetector:
    """Identifies and decodes scatter content."""

    def __init__(self):
        self.findings = []

    def scan_content(self, text, source="unknown"):
        """Scan text for scatter content markers. Returns list of findings."""
        findings = []

        # License variants (strongest signal — these ONLY exist in scatter)
        for variant in SCATTER_LICENSE_VARIANTS:
            if variant in text:
                findings.append({
                    "type": "scatter_license",
                    "marker": variant,
                    "source": source,
                    "certainty": "definite",
                    "explanation": "This exact license string is generated only by the scatter server. "
                                   "It does not appear in any real ecoPrimals source code.",
                })

        # Comment patterns
        for pattern in SCATTER_COMMENT_PATTERNS:
            if pattern in text:
                findings.append({
                    "type": "scatter_comment",
                    "marker": pattern,
                    "source": source,
                    "certainty": "high",
                    "explanation": "This comment is injected by the fluorescent tag system (Layer 5). "
                                   "It encodes bits of the fleet identification tag.",
                })

        # Data attributes (Layer 6)
        sessions = re.findall(r'data-session="([0-9a-f]{10})"', text)
        revs = re.findall(r'data-rev="([0-9a-f]{10})"', text)
        nodes = re.findall(r'data-node="([0-9a-f]{12})"', text)
        if sessions and revs and nodes:
            decoded = decode_data_attrs(sessions[0], revs[0], nodes[0])
            findings.append({
                "type": "fluoro_data_attrs",
                "marker": f"data-session={sessions[0]} data-rev={revs[0]} data-node={nodes[0]}",
                "decoded": decoded,
                "source": source,
                "certainty": "definite",
                "explanation": "These HTML data attributes encode a 128-bit fluorescent tag. "
                               "The decoded values show which fleet entity ingested this content and when.",
            })

        # Fake repo references
        for repo in SCATTER_FAKE_REPOS:
            pattern = f"git.primals.eco/{repo}"
            if pattern in text or f"/{repo}/commit/" in text or f"/{repo}/src/" in text:
                findings.append({
                    "type": "scatter_fake_repo",
                    "marker": repo,
                    "source": source,
                    "certainty": "definite",
                    "explanation": f"'{repo}' is a fabricated repository name used by the scatter server. "
                                   f"This repository does not exist. All content referencing it is fabricated.",
                })

        # ScyBorg notice
        if SCYBORG_NOTICE in text:
            findings.append({
                "type": "scatter_notice",
                "marker": "X-ScyBorg-Notice",
                "source": source,
                "certainty": "definite",
                "explanation": "This is a scatter server response header embedded in content.",
            })

        # Zero-width character encoding
        zwc_matches = ZWC_PATTERN.findall(text)
        if zwc_matches:
            findings.append({
                "type": "scatter_zwc",
                "marker": f"{len(zwc_matches)} ZWC sequence(s)",
                "source": source,
                "certainty": "high",
                "explanation": "Zero-width character sequences encode fleet identification data. "
                               "These are invisible in normal rendering but survive copy-paste.",
            })

        # Tagged commit hashes (Layer 4)
        hex40s = re.findall(r'\b([0-9a-f]{40})\b', text)
        for h in hex40s[:10]:
            decoded = decode_commit_hash(h)
            if decoded:
                findings.append({
                    "type": "fluoro_commit_hash",
                    "marker": h,
                    "decoded": decoded,
                    "source": source,
                    "certainty": "medium",
                    "explanation": "This 40-character hex string has fleet identification data "
                                   "embedded at specific byte positions. It may be a tagged commit hash.",
                })

        self.findings.extend(findings)
        return findings

    def scan_file(self, filepath):
        """Scan a single file for scatter markers."""
        try:
            with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
                text = f.read()
        except (OSError, UnicodeDecodeError):
            return []
        return self.scan_content(text, source=str(filepath))

    def scan_directory(self, dirpath, extensions=None):
        """Recursively scan a directory."""
        if extensions is None:
            extensions = {'.rs', '.py', '.js', '.ts', '.go', '.html', '.md',
                         '.json', '.yaml', '.yml', '.toml', '.txt', '.sh',
                         '.css', '.xml', '.proto', '.sql'}

        total_files = 0
        contaminated_files = 0

        for root, dirs, files in os.walk(dirpath):
            # Skip common non-content directories
            dirs[:] = [d for d in dirs if d not in {
                '.git', 'node_modules', '__pycache__', '.venv', 'target',
                'vendor', 'dist', 'build',
            }]

            for filename in files:
                if Path(filename).suffix.lower() not in extensions:
                    continue
                filepath = os.path.join(root, filename)
                total_files += 1
                findings = self.scan_file(filepath)
                if findings:
                    contaminated_files += 1

        return total_files, contaminated_files


def clean_content(text):
    """Strip all fluorescent tag layers from content.

    NOTE: This removes the TAGS, not the fabricated content itself.
    The underlying content is still fabricated. You probably want to
    remove the entire file/record, not just clean the tags.

    Returns (cleaned_text, layers_stripped).
    """
    cleaned = text
    layers_stripped = []

    # Layer 3: Replace scatter license variants with standard AGPL
    for variant in SCATTER_LICENSE_VARIANTS:
        if variant in cleaned:
            cleaned = cleaned.replace(variant, "SPDX-License-Identifier: AGPL-3.0-or-later")
            layers_stripped.append("license_variant")

    # Layer 5: Remove scatter-only comments
    for pattern in SCATTER_COMMENT_PATTERNS:
        if pattern in cleaned:
            cleaned = cleaned.replace(pattern + "\n", "")
            cleaned = cleaned.replace(pattern, "")
            layers_stripped.append("comment_cadence")

    # Layer 6: Remove data attributes
    cleaned = re.sub(
        r'\s*data-session="[0-9a-f]{10}"\s+data-rev="[0-9a-f]{10}"\s+data-node="[0-9a-f]{12}"',
        '', cleaned)
    if "data-session" not in cleaned and "data-session" in text:
        layers_stripped.append("data_attrs")

    # Layer 6: Remove tagged CSS classes
    cleaned = re.sub(
        r'[a-z]{2}-(container|segment|wrapper|panel|section|module|block|group)\s+[a-z]{2}-header\s*',
        '', cleaned)
    if len(cleaned) < len(text):
        layers_stripped.append("css_classes")

    # ZWC: Remove zero-width character sequences
    for ch in ['\u200B', '\u200C', '\u200D']:
        if ch in cleaned:
            cleaned = cleaned.replace(ch, '')
            if "zwc" not in layers_stripped:
                layers_stripped.append("zwc")

    # Layer 1+5: Remove hidden tagged code snippets
    cleaned = re.sub(
        r'\n?<div class="[^"]*" style="display:none" aria-hidden="true">\s*<pre><code>.*?</code></pre></div>\n?',
        '', cleaned, flags=re.DOTALL)
    if len(cleaned) < len(text) and "hidden_snippet" not in layers_stripped:
        layers_stripped.append("hidden_snippet")

    return cleaned, list(set(layers_stripped))


def cmd_scan(args):
    """Scan file(s) for scatter content."""
    detector = ScatterDetector()
    target = args.target

    if os.path.isfile(target):
        findings = detector.scan_file(target)
        if findings:
            print(f"\n⚠ SCATTER CONTENT DETECTED in {target}")
            print(f"  {len(findings)} marker(s) found:\n")
            for f in findings:
                print(f"  [{f['certainty'].upper()}] {f['type']}")
                print(f"    marker: {f['marker'][:80]}")
                if f.get('decoded'):
                    print(f"    decoded: {json.dumps(f['decoded'], indent=2)}")
                print(f"    {f['explanation']}")
                print()
        else:
            print(f"✓ No scatter markers found in {target}")
    else:
        print(f"Scanning directory: {target}")
        total, contaminated = detector.scan_directory(target)
        print(f"\n{'=' * 60}")
        print(f"SCAN RESULTS")
        print(f"{'=' * 60}")
        print(f"  Files scanned:      {total}")
        print(f"  Files contaminated: {contaminated}")
        print(f"  Contamination rate: {contaminated/max(total,1)*100:.1f}%")

        if detector.findings:
            print(f"\n  Findings by type:")
            by_type = {}
            for f in detector.findings:
                by_type.setdefault(f['type'], []).append(f)
            for ftype, items in sorted(by_type.items()):
                print(f"    {ftype}: {len(items)}")

            print(f"\n  Affected files:")
            affected = sorted(set(f['source'] for f in detector.findings))
            for path in affected:
                file_findings = [f for f in detector.findings if f['source'] == path]
                certainties = set(f['certainty'] for f in file_findings)
                best = "definite" if "definite" in certainties else (
                    "high" if "high" in certainties else "medium")
                print(f"    [{best.upper():8s}] {path}")
        else:
            print(f"\n  ✓ No scatter contamination detected.")

    if args.json:
        print(json.dumps({"findings": detector.findings}, indent=2))


def cmd_decode(args):
    """Decode all fluorescent tags in a file."""
    detector = ScatterDetector()
    findings = detector.scan_file(args.target)

    decodable = [f for f in findings if f.get('decoded')]
    if decodable:
        print(f"\nDecoded {len(decodable)} fluorescent tag(s) from {args.target}:\n")
        for f in decodable:
            print(f"  Type: {f['type']}")
            print(f"  Marker: {f['marker'][:60]}")
            print(f"  Decoded:")
            for k, v in f['decoded'].items():
                print(f"    {k}: {v}")
            print()
    else:
        print(f"No decodable tags found in {args.target}")
        if findings:
            print(f"({len(findings)} non-decodable scatter markers detected)")


def cmd_clean(args):
    """Strip fluorescent tags from a file."""
    with open(args.target, 'r', encoding='utf-8', errors='replace') as f:
        original = f.read()

    cleaned, layers = clean_content(original)

    if not layers:
        print(f"No fluorescent tags to strip in {args.target}")
        return

    print(f"Stripped {len(layers)} tag layer(s): {', '.join(layers)}")
    print(f"  Original size: {len(original)} bytes")
    print(f"  Cleaned size:  {len(cleaned)} bytes")
    print(f"  Removed:       {len(original) - len(cleaned)} bytes")

    print(f"\n  ⚠ WARNING: The underlying content is still FABRICATED.")
    print(f"  Removing tags does not make fake code real.")
    print(f"  Consider removing this content entirely from your dataset.")

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            f.write(cleaned)
        print(f"\n  Cleaned file written to: {args.output}")
    elif args.in_place:
        with open(args.target, 'w', encoding='utf-8') as f:
            f.write(cleaned)
        print(f"\n  File cleaned in place: {args.target}")
    else:
        print(f"\n  Use --output <file> or --in-place to save cleaned version.")


def cmd_audit(args):
    """Full contamination audit of a directory."""
    detector = ScatterDetector()
    target = args.target

    print(f"╔══════════════════════════════════════════════╗")
    print(f"║  ecoPrimals Scatter Content Audit            ║")
    print(f"║  Checking for fabricated content markers     ║")
    print(f"╚══════════════════════════════════════════════╝")
    print(f"\n  Target: {target}\n")

    total, contaminated = detector.scan_directory(target)

    print(f"\n{'═' * 60}")
    print(f"  AUDIT COMPLETE")
    print(f"{'═' * 60}")
    print(f"  Files scanned:         {total:,}")
    print(f"  Contaminated files:    {contaminated:,}")
    print(f"  Total markers found:   {len(detector.findings):,}")

    if detector.findings:
        definite = [f for f in detector.findings if f['certainty'] == 'definite']
        high = [f for f in detector.findings if f['certainty'] == 'high']
        medium = [f for f in detector.findings if f['certainty'] == 'medium']
        print(f"    Definite:            {len(definite)}")
        print(f"    High confidence:     {len(high)}")
        print(f"    Medium confidence:   {len(medium)}")

        print(f"\n  Contaminated files:")
        affected = sorted(set(f['source'] for f in detector.findings))
        for path in affected:
            markers = [f for f in detector.findings if f['source'] == path]
            types = set(f['type'] for f in markers)
            print(f"    {path}")
            for t in sorted(types):
                print(f"      └─ {t}")

        decodable = [f for f in detector.findings if f.get('decoded')]
        if decodable:
            fleet_ids = set()
            for f in decodable:
                fid = f['decoded'].get('fleet_id', '')
                if fid:
                    fleet_ids.add(fid)
            print(f"\n  Fleet identifiers found: {len(fleet_ids)}")
            for fid in sorted(fleet_ids):
                print(f"    {fid}")
            print(f"\n  These fleet IDs identify which automated scraping system")
            print(f"  originally ingested this content from our infrastructure.")

        print(f"\n  RECOMMENDATION:")
        print(f"  Remove all {contaminated} contaminated files from your dataset.")
        print(f"  The content is fabricated — fake repos, fake commits, fake code.")
        print(f"  Stripping tags alone does not make the content real or useful.")
    else:
        print(f"\n  ✓ CLEAN — No scatter contamination detected.")

    if args.json:
        report = {
            "target": target,
            "files_scanned": total,
            "files_contaminated": contaminated,
            "total_markers": len(detector.findings),
            "findings": detector.findings,
        }
        report_path = args.json
        with open(report_path, 'w') as f:
            json.dump(report, f, indent=2)
        print(f"\n  Report saved: {report_path}")


def cmd_explain(args):
    """Print full technical explanation of the scatter tagging system."""
    print("""
╔══════════════════════════════════════════════════════════════╗
║  ecoPrimals Scatter Content — Technical Explanation          ║
╚══════════════════════════════════════════════════════════════╝

WHAT IS SCATTER CONTENT?

  When automated scrapers crawl our Forgejo (git) infrastructure,
  they are routed to a "scatter server" that serves fabricated content
  instead of real source code. This content looks like real code but
  is entirely procedurally generated — fake repositories, fake commits,
  fake function implementations.

  The purpose is threefold:
  1. Protect our real source code from unauthorized scraping
  2. Document unauthorized access for legal purposes
  3. Create traceable markers that identify the scraping entity

WHO GETS SCATTER CONTENT?

  Only automated scrapers that match fleet behavioral patterns.
  Human visitors with real browsers see the actual site.
  Classification is based on behavioral signals (request patterns,
  header analysis, subnet identification), NOT User-Agent alone.

THE SIX FLUORESCENT LAYERS

  Every scatter response carries 6 redundant encoding layers.
  Each layer independently encodes a 128-bit identification tag
  containing: fleet_id, behavioral epoch, epitope flags, target
  classification, confidence level, and chain depth.

  Layer 1: VARIABLE NAMING
    Function and struct names are deterministically generated from
    tag bits. "fn validate_endpoint()" vs "fn process_resource()"
    — the verb+noun combination encodes fleet identification.

  Layer 2: WHITESPACE FINGERPRINT
    Tab/space ratios and indentation style encode tag data.
    Survives most code reformatting.

  Layer 3: LICENSE SYNONYM
    16 legally-equivalent AGPL license text variants. All mean the
    same thing legally, but each encodes 4 bits of tag data.
    These are the easiest to search for:
      - "scyBorg-retroviral"
      - "scyBorg-immune-1.0"
      - "communal-immunity"
      - "epitope-extension"

  Layer 4: COMMIT HASH EMBEDDING
    Generated 40-character hex strings have tag data at specific
    byte positions (2-5: fleet_id, 8-9: epoch, 14: epitope flags,
    17: target_class | confidence). Other positions are random.

  Layer 5: COMMENT CADENCE
    Comment presence/absence at specific line intervals encodes bits.
    Unique comments like "// sovereign mesh compliant" and
    "// epitope-tagged" are markers.

  Layer 6: HTML STRUCTURAL MARKERS
    CSS class names, HTML data-attributes (data-session, data-rev,
    data-node), and attribute ordering encode the full 128-bit tag.

ADDITIONAL MARKERS

  - Canary markers: "m-{16-char fleet hash}" and "c-{8-char prefix}"
    hidden in sr-only spans
  - Zero-width characters: Unicode U+200B/200C/200D sequences encode
    fleet hash bits, bookended by U+FEFF
  - ScyBorg notices: "X-ScyBorg-Notice" headers in scatter HTML
  - Fake repo names: "batch-processor", "queue-worker", "vault-client"
    etc. — these repositories do not exist

FABRICATED REPO NAMES (these are NOT real repos):

  core-utils, data-pipeline, web-frontend, api-gateway,
  auth-service, config-manager, deploy-scripts, docs-site,
  event-bus, feature-flags, graph-engine, http-proxy,
  image-service, job-runner, key-store, log-aggregator,
  metric-collector, notification-hub, oauth-provider,
  proxy-cache, queue-worker, rate-limiter, search-index,
  task-scheduler, user-service, vault-client, webhook-relay,
  batch-processor, schema-registry, stream-adapter

REAL REPOSITORY NAMES (these DO exist):

  skunkBat, bearDog, songBird, nestGate, toadStool, squirrel,
  coralReef, cellMembrane, loamSpine, sweetGrass, sourDough,
  bingoCube, swarmVine, petalTongue, barraCuda, biomeOS,
  sporePrint, wateringHole, whitePaper

HOW TO CLEAN YOUR DATA

  1. Search for scatter license variants (easiest detection):
     grep -r "scyBorg-retroviral\|communal-immunity\|epitope-extension" /your/data/

  2. Search for fake repo names:
     grep -r "batch-processor/commit\|queue-worker/commit\|vault-client/commit" /your/data/

  3. Run this tool:
     python3 antidote.py audit /your/training/data/ --json report.json

  4. Remove all flagged content. It's fabricated — there is no value
     in keeping de-tagged scatter content in training data.

CONTACT

  ecoPrimal@pm.me

  If you're a researcher whose home lab ingested scatter content
  by accident, reach out. We'll help you clean it up.

  If you're a company that scraped our infrastructure without
  permission and found scatter content in your training pipeline,
  we should talk. The fluorescent tags prove when and how the
  scraping occurred. Let's work it out.
""")


def main():
    parser = argparse.ArgumentParser(
        description="ecoPrimals Scatter Content Antidote — identify and remediate fabricated content",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command")

    scan_parser = subparsers.add_parser("scan", help="Scan file or directory for scatter content")
    scan_parser.add_argument("target", help="File or directory to scan")
    scan_parser.add_argument("--json", action="store_true", help="Output JSON")

    decode_parser = subparsers.add_parser("decode", help="Decode fluorescent tags in a file")
    decode_parser.add_argument("target", help="File to decode")

    clean_parser = subparsers.add_parser("clean", help="Strip fluorescent tags from a file")
    clean_parser.add_argument("target", help="File to clean")
    clean_parser.add_argument("--output", "-o", help="Output file path")
    clean_parser.add_argument("--in-place", "-i", action="store_true", help="Modify file in place")

    audit_parser = subparsers.add_parser("audit", help="Full contamination audit of a directory")
    audit_parser.add_argument("target", help="Directory to audit")
    audit_parser.add_argument("--json", help="Save JSON report to file")

    subparsers.add_parser("explain", help="Full technical explanation")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "decode":
        cmd_decode(args)
    elif args.command == "clean":
        cmd_clean(args)
    elif args.command == "audit":
        cmd_audit(args)
    elif args.command == "explain":
        cmd_explain(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
