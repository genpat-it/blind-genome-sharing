# SPDX-License-Identifier: EUPL-1.2
"""Figure for the paper from results/ncbi.json:  .venv/bin/python analysis/figures.py OUT.pdf"""
import json
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402
import numpy as np  # noqa: E402

r = json.load(open("results/ncbi.json"))
plt.rcParams.update({"font.family": "DejaVu Sans", "font.size": 8, "axes.spines.top": False,
                     "axes.spines.right": False, "axes.linewidth": .6, "xtick.major.width": .6,
                     "ytick.major.width": .6, "legend.frameon": False})
fig, (a, b) = plt.subplots(1, 2, figsize=(6.9, 3.1), gridspec_kw={"width_ratios": [1.15, 1]})

lead = np.array(r["Listeria"]["snp_le_10"]["_lead_days"]) / 30.44
bins = np.arange(-60, 61, 4)
a.hist(np.clip(lead, -60, 60), bins=bins, color="#9ccfc9", edgecolor="#177370", linewidth=.5)
a.axvline(0, color="#333", lw=.7, ls="--")
a.set_ylim(0, a.get_ylim()[1] * 1.22)
a.set_xlabel("months from the first food/environmental isolate\nto the first human isolate (clipped at ±60)")
a.set_ylabel("clusters")
a.text(.98, .95, "food/environment first →", transform=a.transAxes, ha="right", va="top", color="#177370")
a.text(.02, .95, "← humans first", transform=a.transAxes, ha="left", va="top", color="#666")
a.set_title("a  L. monocytogenes, clusters ≤ 10 SNPs", loc="left", fontweight="bold")

sets = [("Lm ≤10 SNPs", r["Listeria"]["snp_le_10"]), ("Lm ≤20 SNPs", r["Listeria"]["snp_le_20"]),
        ("Lm NCBI cluster", r["Listeria"]["ncbi_snp_cluster"]), ("Salmonella NCBI", r["Salmonella"]["ncbi_snp_cluster"])]
metrics = [("nc_first_share", "food/env. collected first", "#177370"),
           ("already_there_share", "food/env. genome already public\nwhen first human genome arrived", "#9ccfc9"),
           ("cases_after_share", "human cases collected after a matching\nfood/env. genome was public", "#b86e00")]
y = np.arange(len(sets))
h = .26
for i, (key, label, col) in enumerate(metrics):
    v = [s[key] for _, s in sets]
    b.barh(y + (i - 1) * h, v, h, color=col, label=label)
    for yy, vv in zip(y + (i - 1) * h, v):
        b.text(vv + .01, yy, f"{vv:.0%}", va="center", fontsize=6.5)
b.set_yticks(y, [f"{n}\n({s['mixed']} clusters)" for n, s in sets])
b.invert_yaxis()
b.set_xlim(0, 1)
b.set_xticks([0, .25, .5, .75, 1])
b.xaxis.set_major_formatter(matplotlib.ticker.PercentFormatter(1))
b.legend(loc="upper center", fontsize=6, bbox_to_anchor=(.45, -.16), ncol=1)
b.set_title("b  mixed clusters", loc="left", fontweight="bold")
fig.tight_layout()
fig.savefig(sys.argv[1] if len(sys.argv) > 1 else "results/ncbi_lead.pdf")
