# SPDX-License-Identifier: EUPL-1.2
"""How much earlier could food and environmental genomes warn of human cases?  Real data, NCBI
Pathogen Detection.

    .venv/bin/python analysis/ncbi_lead_time.py --data ../data/ncbi      # writes results/ncbi.json

For every cluster that holds both clinical and food/environmental ('environmental/other') isolates:
  * collection lead: first clinical collection date minus first non-clinical collection date;
  * already there: was a non-clinical genome already in the database (target_creation_date)
    when the first clinical genome of the cluster arrived?  This is when an alert could fire;
  * cases after: clinical isolates collected after a matching non-clinical genome was in the
    database, i.e. cases for which a source hypothesis already existed;
  * persistence: span of non-clinical collection dates in the cluster (a strain living in a plant);
  * spread: distinct countries and US states.
Clusters are NCBI SNP clusters (single linkage, <= 50 SNPs) and, for Listeria, tighter
single-linkage clusters at <= 10 and <= 20 SNPs computed from NCBI's pairwise distances.

The non-clinical isolates in NCBI come mostly from official sampling (FDA, FSIS), not from
companies' own checks, which are far more numerous and today unshared: these figures are a lower
bound on what sharing companies' isolates could add.

Download (about 1.1 GB):
  https://ftp.ncbi.nlm.nih.gov/pathogen/Results/{Listeria,Salmonella}/latest_snps/Metadata/*.metadata.tsv
  .../Clusters/*.reference_target.cluster_list.tsv and, for Listeria, *.SNP_distances.parquet
"""
from __future__ import annotations

import argparse
import glob
import json
from pathlib import Path

import numpy as np
import pandas as pd

COLS = ["target_acc", "collection_date", "epi_type", "geo_loc_name", "isolation_source", "target_creation_date",
        "IFSAC_category"]
YEARS = (2015, 2025)


def parse_date(s: pd.Series) -> pd.Series:
    """YYYY-MM-DD or YYYY-MM (mid-month); year-only and missing dates are dropped."""
    s = s.astype(str).str.strip()
    full = pd.to_datetime(s.where(s.str.fullmatch(r"\d{4}-\d{2}-\d{2}")), errors="coerce")
    month = pd.to_datetime(s.where(s.str.fullmatch(r"\d{4}-\d{2}")) + "-15", errors="coerce")
    return full.fillna(month)


def load(meta_path: str, clusters_path: str) -> pd.DataFrame:
    m = pd.read_csv(meta_path, sep="\t", usecols=COLS, dtype=str, na_values=["NULL", ""], low_memory=False)
    m = m[m.epi_type.isin(["clinical", "environmental/other"])].copy()
    m["date"] = parse_date(m.collection_date)
    m["created"] = pd.to_datetime(m.target_creation_date, errors="coerce")
    m = m[m.date.notna() & m.created.notna() & m.date.dt.year.between(*YEARS)]
    geo = m.geo_loc_name.fillna("")
    m["country"] = geo.str.split(":").str[0].str.strip()
    m["state"] = np.where(m.country == "USA", geo.str.split(":").str[1].str.strip().str.split(",").str[0], None)
    c = pd.read_csv(clusters_path, sep="\t", usecols=["PDS_acc", "target_acc"], dtype=str)
    return m.merge(c, on="target_acc", how="inner")


def tight_clusters(dist_path: str, targets: set[str], thr: int) -> dict[str, str]:
    """Single-linkage components at <= thr SNPs (delta_positions_unambiguous) within NCBI clusters."""
    import pyarrow.parquet as pq
    parent: dict[str, str] = {}

    def find(x):
        while parent.setdefault(x, x) != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x
    f = pq.ParquetFile(dist_path)
    for i in range(f.num_row_groups):
        t = f.read_row_group(i, columns=["target_acc_1", "target_acc_2", "delta_positions_unambiguous"]).to_pandas()
        t = t[t.delta_positions_unambiguous <= thr]
        for a, b in zip(t.target_acc_1.values, t.target_acc_2.values):
            if a in targets and b in targets:
                ra, rb = find(a), find(b)
                if ra != rb:
                    parent[ra] = rb
    return {x: find(x) for x in targets if x in parent}


def summarise(df: pd.DataFrame, key: str, lag_days: int = 0) -> dict:
    rows = []
    for cid, g in df.groupby(key):
        cl, nc = g[g.epi_type == "clinical"], g[g.epi_type == "environmental/other"]
        if cl.empty or nc.empty:
            continue
        first_cl = cl.date.min()
        first_cl_created = cl.created.min()
        first_nc, first_nc_created = nc.date.min(), nc.created.min()
        rows.append({
            "lead_days": (first_cl - first_nc).days,
            "already_there": bool(first_nc_created + pd.Timedelta(days=lag_days) <= first_cl_created),
            "cases_after": int((cl.date > first_nc_created).sum()),
            "n_clinical": len(cl), "n_nc": len(nc),
            "nc_span_days": (nc.date.max() - first_nc).days,
            "countries": g.country.nunique(), "states": g.state.dropna().nunique(),
        })
    r = pd.DataFrame(rows)
    n_clusters = df[key].nunique()
    if r.empty:
        return {"clusters": n_clusters, "mixed": 0}
    lead = r.lead_days
    pos = lead[lead > 0]
    multi = r[r.n_nc >= 2]
    return {
        "clusters": int(n_clusters), "mixed": int(len(r)),
        "isolates": int(len(df)), "clinical": int((df.epi_type == "clinical").sum()),
        "mixed_share_of_clusters_with_clinical": round(len(r) / df[df.epi_type == "clinical"][key].nunique(), 3),
        "nc_first_share": round(float((lead > 0).mean()), 3),
        "lead_days_median_when_nc_first": float(pos.median()) if len(pos) else None,
        "lead_days_iqr_when_nc_first": [float(pos.quantile(.25)), float(pos.quantile(.75))] if len(pos) else None,
        "already_there_share": round(float(r.already_there.mean()), 3),
        "clinical_in_mixed": int(r.n_clinical.sum()),
        "cases_after_nc_in_db": int(r.cases_after.sum()),
        "cases_after_share": round(float(r.cases_after.sum() / r.n_clinical.sum()), 3),
        "persistent_over_1y_share": round(float((multi.nc_span_days > 365).mean()), 3) if len(multi) else None,
        "nc_span_days_median": float(multi.nc_span_days.median()) if len(multi) else None,
        "multi_country_share": round(float((r.countries > 1).mean()), 3),
        "multi_state_share": round(float((r.states > 1).mean()), 3),
        "_lead_days": lead.tolist(),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", default="../data/ncbi")
    ap.add_argument("--out", default="results/ncbi.json")
    a = ap.parse_args()
    d = Path(a.data)
    out = {"years": YEARS}
    for org, pdg in (("Listeria", "PDG000000001"), ("Salmonella", "PDG000000002")):
        meta = glob.glob(str(d / f"{pdg}.*.metadata.tsv"))[0]
        clu = glob.glob(str(d / f"{pdg}.*.reference_target.cluster_list.tsv"))[0]
        df = load(meta, clu)
        res = {"release": Path(meta).name.split(".metadata")[0], "ncbi_snp_cluster": summarise(df, "PDS_acc")}
        res["ncbi_snp_cluster_lag30"] = {k: v for k, v in summarise(df, "PDS_acc", 30).items() if k == "already_there_share"}
        dist = glob.glob(str(d / f"{pdg}.*.reference_target.SNP_distances.parquet"))
        if dist:
            for thr in (10, 20):
                comp = tight_clusters(dist[0], set(df.target_acc), thr)
                t = df.assign(tight=df.target_acc.map(comp))
                t = t[t.tight.notna()]
                res[f"snp_le_{thr}"] = summarise(t, "tight")
        out[org] = res
        print(org, json.dumps({k: {kk: vv for kk, vv in v.items() if not kk.startswith("_")} for k, v in res.items()
                                if isinstance(v, dict)}, indent=1))
    Path(a.out).parent.mkdir(exist_ok=True)
    Path(a.out).write_text(json.dumps(out, indent=1))


if __name__ == "__main__":
    main()
