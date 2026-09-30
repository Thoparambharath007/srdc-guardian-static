"""
verdict.py
Combines static analysis signals into a final verdict.

Signal priority (weighted by real-world reliability):
  1. VirusTotal  → MAJOR: multi-engine consensus is the strongest evidence.
     Heavily flagged files can reach Ransomware level on VT alone; a broad
     clean consensus is the strongest clean evidence (capped so VT is
     dominant but never over-hyped).
  2. Magic byte mismatch / invalid signature → MEDIUM-STRONG (+3)
  3. YARA match  → MEDIUM (+2): generic rules fire on many clean installers
  4. Entropy     → WEAK (+2, ignored when VT is clean)
  5. Size anomaly→ WEAK (+1, ignored when VT is clean)
"""


def compute_verdict(static: dict) -> dict:

    reasons   : list[str] = []
    mal_score : int       = 0

    vt_clean   = (not static["vt"]["vt_flag"] and
                  static["vt"]["total"] > 0)      # actually checked + clean
    vt_flagged = static["vt"]["vt_flag"]
    vt_unknown = (static["vt"]["total"] == 0)     # no reputation (no key / new file)
    if vt_unknown:
        reasons.append("ℹ VirusTotal reputation unavailable — relying on local static analysis only")

    # ── 1. VirusTotal (MAJOR PRIORITY — strongest single signal) ────────────
    if vt_flagged:
        p = static["vt"]["positives"]
        t = static["vt"]["total"]
        reasons.append(f"⚠ VirusTotal: {p}/{t} engines flagged this file")
        # Scales with engine consensus; the only signal that can reach
        # Ransomware level on its own (broad multi-engine agreement).
        mal_score += min(7, p // 2 + 2)
    elif vt_clean:
        engine_count = static["vt"]["total"]
        reasons.append(f"✔ VirusTotal: Clean ({engine_count} engines checked)")
        # Broad clean consensus is the strongest clean evidence, but capped
        # so VT stays dominant without being over-hyped.
        mal_score -= 3 if engine_count >= 50 else 2 if engine_count >= 10 else 1

    # ── 2. Magic byte mismatch (MEDIUM-STRONG) ───────────────────────────────
    if static["magic"]["flag"]:
        reasons.append(f"⚠ Extension mismatch: {static['magic']['detail']}")
        mal_score += 3

    # ── 3. Digital signature (MEDIUM-STRONG trust signal when VT silent) ────
    sig = static.get("signature", {})
    if sig.get("applicable"):
        if sig.get("trusted"):
            signer = sig.get("signer") or "Unknown publisher"
            reasons.append(f"✔ Digitally signed by {signer} — trusted publisher")
            mal_score -= 3
        elif sig.get("signed"):
            reasons.append(f"⚠ Invalid digital signature: {sig.get('detail', '')}")
            mal_score += 3
        elif not vt_clean:
            # Unsigned is normal for many tools; only worth mentioning when
            # VirusTotal could not vouch for the file either.
            reasons.append("ℹ No digital signature and no VirusTotal record — provenance unknown")

    # ── 4. YARA (MEDIUM — generic rules fire on clean installers too) ───────
    if static["yara"]["flag"]:
        rules = ", ".join(static["yara"]["matches"])
        reasons.append(f"⚠ YARA match: {rules}")
        mal_score += 2

    # ── 5. Entropy (WEAK — ignored if VT clean) ───────────────────────────────
    if static["entropy"]["flag"]:
        if vt_clean:
            # Exe installers are compressed → high entropy is NORMAL
            reasons.append(
                f"ℹ High entropy ({static['entropy']['entropy']}) "
                f"— likely compressed installer (VT clean, ignoring)"
            )
        else:
            reasons.append(
                f"⚠ High entropy ({static['entropy']['entropy']}) — possible hidden payload"
            )
            mal_score += 2

    # ── 6. Size anomaly (WEAK — ignored if VT clean) ─────────────────────────
    if static["size"]["flag"]:
        if not vt_clean:
            reasons.append(f"⚠ Size anomaly: {static['size']['detail']}")
            mal_score += 1

    # ── Final decision ────────────────────────────────────────────────────────
    mal_score = max(0, mal_score)   # floor at 0

    # A "strong" local indicator is something beyond generic YARA / entropy /
    # size noise: an extension that lies, an invalid signature, or a VT flag.
    strong_local = (
        static["magic"]["flag"]
        or vt_flagged
        or (sig.get("applicable") and sig.get("signed") and not sig.get("trusted"))
    )

    no_strong_signals = (not vt_flagged and
                         not static["yara"]["flag"] and
                         not static["magic"]["flag"])

    if vt_clean and no_strong_signals:
        label        = "Clean"
        is_malicious = False
    elif mal_score >= 7:
        label        = "Ransomware"
        is_malicious = True
    elif mal_score >= 2 and (strong_local or mal_score >= 4):
        # A low score (2-3) counts as "Suspicious" only when a strong local
        # indicator is present, or when multiple weaker signals corroborate
        # (score >= 4). This stops a single generic YARA / entropy hit from
        # flagging a clean installer whose VirusTotal reputation is unknown.
        label        = "Suspicious"
        is_malicious = True
    else:
        label        = "Clean"
        is_malicious = False

    # ── Confidence: strength of evidence behind the final label ───────────────
    # Positive trust evidence (broad VirusTotal consensus, a trusted digital
    # signature) can outweigh weak/generic YARA noise for a Clean verdict.
    trust_points = 0
    if vt_clean:
        engine_count = static["vt"]["total"]
        trust_points += 3 if engine_count >= 50 else 2 if engine_count >= 10 else 1
    if sig.get("trusted"):
        trust_points += 3

    if is_malicious:
        if mal_score >= 7:
            confidence = "High"
        elif mal_score >= 3:
            confidence = "Medium"
        else:
            confidence = "Low"
    else:
        # Clean verdict: confidence comes from positive trust evidence
        if trust_points >= 4 or (trust_points >= 3 and vt_clean):
            confidence = "High"
        elif trust_points >= 1:
            confidence = "Medium"
        else:
            confidence = "Low"

    detail_lines = [
        f"VirusTotal  : {static['vt']['detail']}",
        f"Magic bytes : {'MISMATCH' if static['magic']['flag'] else 'OK'} ({static['magic']['real_type']})",
        f"Entropy     : {static['entropy']['entropy']} {'⚠' if static['entropy']['flag'] else '✔'}",
        f"YARA        : {static['yara']['detail']}",
        f"File size   : {static['size']['detail']}",
    ]
    sig = static.get("signature", {})
    if sig:
        detail_lines.append(f"Signature   : {sig.get('detail', 'unknown')}")

    headline = f"This file is {label}"

    return {
        "is_malicious":  is_malicious,
        "confidence":    confidence,
        "label":         label,
        "family":        "N/A",
        "reasons":       reasons,
        "headline":      headline,
        "detail_lines":  detail_lines,
        "mal_score":     mal_score,
    }
