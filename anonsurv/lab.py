# SPDX-License-Identifier: EUPL-1.2
"""Public-health laboratory: clusters anonymous records with clinical isolates, sends private alerts.

Distance here is the allelic (Hamming) distance between cgMLST profiles, ignoring missing loci.
cgDist (SNP/indel-level distances) can replace it without changing the protocol.
"""
from __future__ import annotations

import json

import httpx

from . import alerts

# Cluster thresholds in allelic differences: L. monocytogenes 7 (Moura et al. 2016), Salmonella 5
# (ECDC-EFSA 2023). STEC: 5 is the SNP threshold of Dallman et al. 2015, used here as an approximation.
THRESHOLDS = {"Listeria monocytogenes": 7, "Salmonella enterica": 5, "Escherichia coli (STEC)": 5}


def hamming(a: list[int], b: list[int]) -> int:
    return sum(1 for x, y in zip(a, b) if x and y and x != y)


def run(platform: httpx.Client, lab_key: str, clinical: list[dict], since: int = 0) -> tuple[list[dict], int]:
    """clinical: [{"id", "species", "alleles"}]. Returns (alerts sent, last seq seen)."""
    sent, last = [], since
    for rec in platform.get("/records", params={"since": since}, headers={"x-lab-key": lab_key}).json():
        last = rec["seq"]
        thr = THRESHOLDS.get(rec["meta"]["species"], 7)
        matches = [(hamming(rec["alleles"], c["alleles"]), c["id"]) for c in clinical
                   if c["species"] == rec["meta"]["species"]]
        close = sorted(m for m in matches if m[0] <= thr)
        if not close:
            continue
        msg = {"record_id": rec["id"], "species": rec["meta"]["species"], "clinical_cases": len(close),
               "min_distance": close[0][0], "threshold": thr,
               "text": "Your isolate clusters with human cases. Please contact the competent authority."}
        enc, ct = alerts.seal(bytes.fromhex(rec["pk_alert"]), json.dumps(msg).encode())
        platform.post("/alerts", json={"enc": enc.hex(), "ct": ct.hex()}, headers={"x-lab-key": lab_key})
        sent.append(msg)
    return sent, last
