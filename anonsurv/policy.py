# SPDX-License-Identifier: EUPL-1.2
"""Metadata generalisation: a record is accepted only if at least k enrolled companies share its
coarse metadata (region, food category). The client generalises before sending; the platform
checks again. Region codes are NUTS: 'ITF1' (NUTS-2) -> 'ITF' (NUTS-1) -> 'IT' (country)."""
from __future__ import annotations

import re

SPECIES = {"Listeria monocytogenes", "Salmonella enterica", "Escherichia coli (STEC)"}
ANY = "*"


def anonymity_set(stats: dict[str, int], region: str, category: str) -> int:
    n = 0
    for key, count in stats.items():
        r, c = key.split("|")
        if r.startswith(region) and (category == ANY or c == category):
            n += count
    return n


def generalise(meta: dict, stats: dict[str, int], k: int) -> dict | None:
    """Coarsest-last ladder; returns the first level with an anonymity set >= k, or None."""
    region, category = meta["region"], meta["category"]
    for r, c in ((region, category), (region[:3], category), (region[:3], ANY),
                 (region[:2], category), (region[:2], ANY)):
        if anonymity_set(stats, r, c) >= k:
            return {**meta, "region": r, "category": c}
    return None


def check(meta: dict, stats: dict[str, int], k: int) -> str | None:
    """Returns an error message, or None if the metadata are acceptable."""
    if set(meta) != {"species", "month", "region", "category"}:
        return "metadata must be exactly species, month, region, category"
    if meta["species"] not in SPECIES:
        return "unknown species"
    if not re.fullmatch(r"\d{4}-(0[1-9]|1[0-2])", meta["month"]):
        return "month must be YYYY-MM (no day)"
    if anonymity_set(stats, meta["region"], meta["category"]) < k:
        return f"fewer than k={k} enrolled companies share region and category: generalise"
    return None
