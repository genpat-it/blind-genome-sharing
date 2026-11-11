# SPDX-License-Identifier: EUPL-1.2
"""Synthetic data for the demo: a register of food companies and cgMLST profiles grouped in clones.

SYNTHETIC ONLY. Replace with public profiles (e.g. NCBI Pathogen Detection, typed with chewBBACA)
for a real evaluation.
"""
from __future__ import annotations

import random

from .issuer import Company

N_LOCI = 1748  # size of the Pasteur L. monocytogenes cgMLST scheme
REGIONS = {"ITF1": "Abruzzo", "ITF2": "Molise", "ITF3": "Campania", "ITI4": "Lazio",
           "ITC4": "Lombardia", "ITH3": "Veneto"}
CATEGORIES = ["dairy", "meat", "fish", "ready-to-eat", "produce"]


def register(rng: random.Random) -> dict[str, Company]:
    reg, i = {}, 0
    for region in REGIONS:
        for cat in CATEGORIES:
            n = 2 if (region, cat) == ("ITF2", "fish") else rng.randint(3, 15)
            for _ in range(n):
                i += 1
                cid = f"FBO{i:04d}"
                reg[cid] = Company(cid, f"Company {i}", region, cat, vat=f"{i:011d}")
    return reg


def clone(rng: random.Random) -> list[int]:
    return [rng.randint(1, 40) for _ in range(N_LOCI)]


def variant(rng: random.Random, base: list[int], changes: int, missing: int = 15) -> list[int]:
    p = list(base)
    for locus in rng.sample(range(N_LOCI), changes):
        p[locus] = p[locus] + 100 + rng.randint(1, 50)   # new allele number
    for locus in rng.sample(range(N_LOCI), missing):
        p[locus] = 0                                     # locus not called
    return p
