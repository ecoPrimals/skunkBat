#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
Fleet phenotype analysis — population genetics of automated visitors.

Reads Caddy access logs, classifies each request through biological taxonomy,
computes genotype×phenotype clusters, allele frequencies, Shannon diversity,
and writes a JSON snapshot consumable by signal.primals.eco dashboard.

Usage:
    python3 fleet-phenotype.py [--log /var/log/caddy/access.log] [--out /tmp/fleet-phenotype.json]

Designed to run periodically (systemd timer, every 15 min) alongside
ingestion-observer.py. Output is a single JSON file consumed by the
signal page JavaScript.
"""

import json, hashlib, collections, math, sys, argparse, time
from pathlib import Path

FAKE_REPOS = [
    "batch-processor","queue-worker","proxy-cache","deploy-scripts",
    "http-proxy","core-utils","api-gateway","rate-limiter",
    "graph-engine","auth-service","web-frontend","config-manager",
    "docs-site","event-bus","feature-flags","image-service",
    "job-runner","key-store","log-aggregator","metric-collector",
    "notification-hub","oauth-provider","search-index","task-scheduler",
    "user-service","vault-client","webhook-relay","schema-registry",
    "stream-adapter",
]

def classify_ua_type(ua, has_sec, has_ref, ip):
    ua_lower = ua.lower()
    if "claudebot" in ua_lower: return "claudebot"
    if "meta-external" in ua_lower: return "meta-identified"
    if ip.startswith("57.141.20."): return "meta-identified"
    if "reflectionbot" in ua_lower: return "reflectionbot"
    if "semrush" in ua_lower: return "semrush"
    if "exasearch" in ua_lower: return "exa"
    if "amazonbot" in ua_lower: return "amazon"
    if "sogou" in ua_lower: return "sogou"
    if "gptbot" in ua_lower: return "gptbot"
    if "bytespider" in ua_lower: return "bytespider"
    if "headlesschrome" in ua_lower: return "headless"
    if has_sec and not has_ref: return "browser-no-ref"
    if has_sec and has_ref: return "browser-with-ref"
    return "minimal"

def classify_kingdom(ua_type, has_sec, has_ref):
    if ua_type in ("browser-no-ref",) and not has_ref:
        return "Chimera"
    if ua_type == "browser-with-ref" and has_ref:
        return "Anthropos"
    if has_sec and has_ref:
        return "Anthropos"
    return "Automata"

def classify_diet(real_pct):
    if real_pct > 80: return "herbivore"
    if real_pct > 20: return "omnivore"
    return "detritivore"

def shannon(counter):
    total = sum(counter.values())
    if total == 0: return 0.0
    return -sum((c/total) * math.log2(c/total) for c in counter.values() if c > 0)

def analyze(log_path):
    specimens = collections.defaultdict(list)
    
    with open(log_path) as f:
        for line in f:
            try:
                d = json.loads(line.strip())
                req = d.get("request", {})
                ip = req.get("remote_ip", "?")
                ua = req.get("headers", {}).get("User-Agent", [""])[0]
                hdrs = req.get("headers", {})
                tls = req.get("tls", {})
                host = req.get("host", "?")
                uri = req.get("uri", "?")
                ts = d.get("ts", 0)
                sz = d.get("size", 0)

                if any(x in uri for x in [".js",".css",".svg",".png",".woff",".ico","favicon"]):
                    continue

                ae = hdrs.get("Accept-Encoding", [""])[0]
                al = hdrs.get("Accept-Language", [""])[0]
                sec_plat = hdrs.get("Sec-Ch-Ua-Platform", [""])[0]
                n_hdrs = len(hdrs)
                has_sec = any(k.startswith("Sec-") for k in hdrs)
                referer = hdrs.get("Referer", [""])[0] if "Referer" in hdrs else ""
                tls_proto = tls.get("proto", "")

                specimens[ip].append({
                    "ua": ua, "host": host, "uri": uri, "ts": ts, "sz": sz,
                    "ae": ae, "al": al, "sec_plat": sec_plat, "n_hdrs": n_hdrs,
                    "has_sec": has_sec, "tls_proto": tls_proto,
                    "referer": referer,
                })
            except:
                pass

    # Build per-IP genotype + phenotype
    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_ips": len(specimens),
        "total_requests": sum(len(v) for v in specimens.values()),
    }

    # Taxonomy counts
    kingdoms = collections.Counter()
    genera = collections.Counter()
    species_counter = collections.Counter()
    trophic = collections.Counter()
    
    # Allele frequencies
    alleles = {
        "has_sec": 0, "has_ref": 0, "en_us": 0, "http11": 0, "h2": 0,
        "single_ua": 0, "rotates_ua": 0, "has_priority": 0,
    }
    
    # Platform karyotype
    platforms = collections.Counter()
    ua_types = collections.Counter()
    ae_variants = collections.Counter()
    
    # Species detail
    species_detail = {}
    
    # Cluster matrix
    clusters = collections.defaultdict(lambda: {"ips": 0, "reqs": 0, "bytes": 0, "repos": collections.Counter()})

    for ip, reqs in specimens.items():
        uas = set(r["ua"][:80] for r in reqs)
        ua_sample = list(uas)[0]
        has_sec = any(r["has_sec"] for r in reqs)
        has_ref = any(r["referer"] for r in reqs)
        ae = sorted(set(r["ae"] for r in reqs))[0] if reqs else ""
        al = sorted(set(r["al"] for r in reqs))[0] if reqs else ""
        plat = sorted(set(r["sec_plat"] for r in reqs if r["sec_plat"]))[0] if any(r["sec_plat"] for r in reqs) else "none"
        tls_alpn = sorted(set(r["tls_proto"] for r in reqs))[0] if reqs else ""

        ua_type = classify_ua_type(ua_sample, has_sec, has_ref, ip)
        kingdom = classify_kingdom(ua_type, has_sec, has_ref)

        # Genus
        genus_map = {
            "claudebot": "Claudius", "meta-identified": "Metacrawler",
            "reflectionbot": "Reflector", "browser-no-ref": "Phantoma",
            "browser-with-ref": "Homo", "headless": "Phantoma",
        }
        genus = genus_map.get(ua_type, "incertae_sedis")

        # Species hash
        sp_parts = [ae[:20], str(reqs[0]["n_hdrs"]), tls_alpn, plat]
        sp_hash = hashlib.md5("|".join(sp_parts).encode()).hexdigest()[:6]
        sp = f"{genus.lower()}_{sp_hash}"

        # Diet
        n_real = sum(1 for r in reqs if "ecoPrimals" in r["uri"])
        n_fake = sum(1 for r in reqs if any(f in r["uri"] for f in FAKE_REPOS) or r["uri"].startswith("/commit/"))
        total_diet = n_real + n_fake
        real_pct = n_real / max(total_diet, 1) * 100
        diet = classify_diet(real_pct) if total_diet > 0 else "non-feeding"
        volume = "heavy" if len(reqs) > 100 else "medium" if len(reqs) > 10 else "light"

        # Target repos
        repos = collections.Counter()
        for r in reqs:
            parts = r["uri"].split("/")
            if len(parts) > 2 and parts[1] == "ecoPrimals":
                repos[parts[2]] += 1

        total_bytes = sum(r["sz"] for r in reqs)

        # Accumulate
        kingdoms[kingdom] += 1
        genera[genus] += 1
        species_counter[sp] += 1
        trophic[diet] += 1
        platforms[plat] += 1
        ua_types[ua_type] += 1
        ae_variants[ae[:30]] += 1

        if has_sec: alleles["has_sec"] += 1
        if has_ref: alleles["has_ref"] += 1
        if "en" in al[:10]: alleles["en_us"] += 1
        if tls_alpn in ("http/1.1", ""): alleles["http11"] += 1
        if tls_alpn == "h2": alleles["h2"] += 1
        if len(uas) == 1: alleles["single_ua"] += 1
        if len(uas) > 1: alleles["rotates_ua"] += 1

        # Species detail
        if sp not in species_detail:
            species_detail[sp] = {
                "genus": genus, "kingdom": kingdom,
                "ae": ae, "platform": plat, "tls_alpn": tls_alpn,
                "ua_sample": ua_sample[:90],
                "ips": 0, "requests": 0, "bytes": 0,
                "diet_real_pct": 0, "diet_counts": {"real": 0, "fake": 0},
                "top_repos": [],
            }
        sd = species_detail[sp]
        sd["ips"] += 1
        sd["requests"] += len(reqs)
        sd["bytes"] += total_bytes
        sd["diet_counts"]["real"] += n_real
        sd["diet_counts"]["fake"] += n_fake

        # Cluster
        ck = f"{ua_type}|{plat}|{tls_alpn}|{diet}|{volume}"
        cl = clusters[ck]
        cl["ips"] += 1
        cl["reqs"] += len(reqs)
        cl["bytes"] += total_bytes
        for r, c in repos.items():
            cl["repos"][r] += c

    # Finalize species diet percentages
    for sp, sd in species_detail.items():
        total = sd["diet_counts"]["real"] + sd["diet_counts"]["fake"]
        sd["diet_real_pct"] = round(sd["diet_counts"]["real"] / max(total, 1) * 100, 1)

    # Shannon indices
    n_total = len(specimens)
    diversity = {
        "accept_encoding": {"H": round(shannon(ae_variants), 3), "alleles": len(ae_variants)},
        "ua_morphotype": {"H": round(shannon(ua_types), 3), "alleles": len(ua_types)},
        "platform": {"H": round(shannon(platforms), 3), "alleles": len(platforms)},
        "tls_alpn": {"H": round(shannon(collections.Counter({
            "h2": alleles["h2"], "http11": alleles["http11"]
        })), 3), "alleles": 2},
    }

    # Allele frequencies as percentages
    allele_freq = {k: round(v / max(n_total, 1) * 100, 1) for k, v in alleles.items()}

    # Build output
    results["taxonomy"] = {
        "kingdoms": dict(kingdoms),
        "genera": dict(genera),
        "species": dict(species_counter.most_common(20)),
        "species_detail": {sp: {k: v for k, v in sd.items() if k != "diet_counts"}
                          for sp, sd in sorted(species_detail.items(), key=lambda x: -x[1]["requests"])[:20]},
    }
    results["population_genetics"] = {
        "allele_frequencies": allele_freq,
        "trophic_levels": dict(trophic),
        "platform_karyotype": dict(platforms),
        "ua_morphotypes": dict(ua_types),
        "shannon_diversity": diversity,
        "effective_population_size": {
            "apparent_N": n_total,
            "estimated_Ne": 5,
            "Ne_N_ratio": round(5 / max(n_total, 1), 4),
        },
    }
    results["clusters"] = [
        {"key": k, "ips": v["ips"], "requests": v["reqs"],
         "bytes": v["bytes"], "top_repos": dict(v["repos"].most_common(5))}
        for k, v in sorted(clusters.items(), key=lambda x: -x[1]["reqs"])
        if v["reqs"] >= 2
    ]

    return results


def main():
    parser = argparse.ArgumentParser(description="Fleet phenotype analysis")
    parser.add_argument("--log", default="/var/log/caddy/access.log")
    parser.add_argument("--out", default="/var/lib/skunky-ingest/fleet-phenotype.json")
    args = parser.parse_args()

    if not Path(args.log).exists():
        print(f"Log file not found: {args.log}", file=sys.stderr)
        sys.exit(1)

    results = analyze(args.log)

    Path(args.out).parent.mkdir(parents=True, exist_ok=True)
    with open(args.out, "w") as f:
        json.dump(results, f, indent=2)

    n = results["total_ips"]
    r = results["total_requests"]
    k = results["taxonomy"]["kingdoms"]
    sp = len(results["taxonomy"]["species_detail"])
    print(f"fleet-phenotype: {n} IPs, {r} requests, {len(k)} kingdoms, {sp} species → {args.out}")


if __name__ == "__main__":
    main()
