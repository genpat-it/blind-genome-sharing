# SPDX-License-Identifier: EUPL-1.2
"""How coarse must the metadata be?  Anonymity sets for Italian food manufacturers, real counts.

    .venv/bin/python analysis/anonymity_sets.py          # writes results/anonymity.json

Population: Eurostat structural business statistics. Local units of food manufacturing (NACE C10)
per NUTS-2 region (sbs_r_nuts2021, 2023), split into sectors by the national share of enterprises
in each NACE group (sbs_ovw_act, 2023): meat C10.1, fish C10.2, fruit and vegetables C10.3, dairy
C10.5, other food incl. prepared meals C10.8, bakery C10.7.  The split assumes each region has the
national sector mix, an approximation (Eurostat publishes no regional NACE groups).

For a share p of companies taking part, the anonymity set of a cell is p x its population. The
platform's own generalisation ladder (anonsurv.policy) then decides at which level each
company's record can be released: NUTS-2 and sector, NUTS-1 and sector, NUTS-1, country and
sector, country.
"""
from __future__ import annotations

import json
import sys
import urllib.request
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from anonsurv import policy  # noqa: E402

API = "https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0/data/"
SECTORS = {"C101": "meat", "C102": "fish", "C103": "produce", "C105": "dairy", "C108": "other-food", "C107": "bakery"}
YEAR = "2023"
CACHE = Path(__file__).resolve().parents[2] / "data" / "eurostat"


def get(name: str, query: str) -> dict:
    CACHE.mkdir(parents=True, exist_ok=True)
    p = CACHE / f"{name}.json"
    if not p.exists():
        with urllib.request.urlopen(API + query, timeout=60) as r:
            p.write_bytes(r.read())
    return json.loads(p.read_text())


def values(d: dict, dim: str) -> dict[str, float]:
    """Map the categories of one dimension to values (all other dimensions have size 1)."""
    idx = d["dimension"][dim]["category"]["index"]
    return {k: d["value"][str(i)] for k, i in idx.items() if str(i) in d["value"]}


def main():
    reg = get("c10_loc_nuts2_2023", f"sbs_r_nuts2021?format=JSON&lang=EN&nace_r2=C10&indic_sbs=LOC_NR&time={YEAR}")
    loc = {g: v for g, v in values(reg, "geo").items() if g.startswith("IT") and len(g) == 4}
    nat = get("it_c10x_ent_2023", f"sbs_ovw_act?format=JSON&lang=EN&geo=IT&indic_sbs=ENT_NR&time={YEAR}"
                                  + "".join(f"&nace_r2={n}" for n in ["C10", *SECTORS]))
    ent = values(nat, "nace_r2")
    share = {SECTORS[n]: ent[n] / ent["C10"] for n in SECTORS}
    pop = {f"{g}|{s}": n * share[s] for g, n in loc.items() for s in SECTORS.values()}
    out = {"year": YEAR, "regions": len(loc), "c10_local_units": sum(loc.values()),
           "sector_share": {s: round(v, 4) for s, v in share.items()},
           "cells": {k: round(v, 1) for k, v in pop.items()}, "results": {}}
    for k in (5, 10):
        for p in (0.02, 0.05, 0.10, 0.25, 0.5, 1.0):
            stats = {c: int(v * p) for c, v in pop.items()}
            levels, companies, per = Counter(), 0, {}
            for cell, n in pop.items():
                region, sector = cell.split("|")
                g = policy.generalise({"species": "Listeria monocytogenes", "month": "2026-10", "region": region,
                                       "category": sector}, stats, k)
                lvl = ("withheld" if g is None else
                       f"{'NUTS-2' if len(g['region']) == 4 else 'NUTS-1' if len(g['region']) == 3 else 'country'}"
                       f"{' + sector' if g['category'] != policy.ANY else ''}")
                levels[lvl] += n * p
                companies += n * p
                per.setdefault(sector, Counter())[lvl] += n * p
            out["results"][f"k{k}_p{p}"] = {"k": k, "participation": p, "companies": round(companies),
                                            "share_by_level": {l: round(v / companies, 3) for l, v in levels.most_common()},
                                            "by_sector": {sec: {l: round(v / sum(c.values()), 3) for l, v in c.most_common()}
                                                          for sec, c in per.items()}}
            print(f"k={k:2d} p={p:4.0%} {round(companies):6d} companies:",
                  ", ".join(f"{l} {v / companies:.0%}" for l, v in levels.most_common()),
                  "| at NUTS-2 + sector:", ", ".join(f"{sec} {c['NUTS-2 + sector'] / sum(c.values()):.0%}" for sec, c in per.items()))
    Path("results").mkdir(exist_ok=True)
    Path("results/anonymity.json").write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
