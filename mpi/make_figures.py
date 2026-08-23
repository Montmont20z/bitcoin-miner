#!/usr/bin/env python3
"""
Generate every figure for section 4.5 / 4.7 of the PDC report.

    python3 make_figures.py

Edit CONFIG below to point at your CSVs. Missing files are skipped with a
warning, so you can run this before all the data is collected.

Inputs
  scaling_raw.csv   produced by scaling.sh   (np,rep,seconds,rate_hs)
  results.csv           produced by bench.sh           (experiment,midstate,...)
  difficulty_sweep.csv  produced by difficulty_sweep.sh (difficulty,np,hashes,...)

Outputs (200 dpi PNG, sized to drop straight into Word)
  fig1_scaling.png      strong scaling + parallel efficiency
  fig2_throughput.png   hash rate by process count, both platforms
  fig3_polling.png      wasted post-solution hashes vs polling interval
  fig4_midstate.png     midstate off vs on, both platforms
  fig5_difficulty.png   hashes to first solution vs difficulty
  fig6_decomposition.png  strided vs block, schematic (numbers from results_pc.csv)
"""
import csv, os, statistics as st
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter

# ---------------------------------------------------------------- CONFIG ----
CONFIG = {
    "pc": {
        "label":   "Laptop  i5-1135G7 · 4 cores · SHA-NI",
        "short":   "Laptop i5-1135G7",
        "cores":   4,
        "scaling": "scaling_raw_pc.csv",
        "results": "results_pc.csv",
    },
    "colab": {
        "label":   "Colab  Xeon @ 2.00GHz · 1 core",
        "short":   "Colab Xeon",
        "cores":   1,
        "scaling": "scaling_raw_colab.csv",
        "results": "results_colab.csv",
    },
}
# -----------------------------------------------------------------------------

PC, COLAB = "#2a78d6", "#eb6834"          # validated categorical slots 1 & 2
INK, INK2, MUT = "#0b0b0b", "#52514e", "#8a8985"
SURF, GRID = "#fcfcfb", "#e3e2de"

plt.rcParams.update({
    "font.family": "DejaVu Sans", "font.size": 10,
    "axes.edgecolor": GRID, "axes.labelcolor": INK2,
    "xtick.color": INK2, "ytick.color": INK2,
    "figure.facecolor": SURF, "axes.facecolor": SURF,
})


def _find(name):
    """CSVs live in data/ in the repo, but next to the script right after a run."""
    if not name:
        return None
    for cand in (name, os.path.join("data", os.path.basename(name)), os.path.basename(name)):
        if os.path.exists(cand):
            return cand
    return name


def read_scaling(path):
    """scaling_raw.csv -> {np: median_seconds}, plus rate."""
    path = _find(path)
    if not path or not os.path.exists(path):
        print(f"  [skip] {path} not found")
        return None
    runs = {}
    with open(path) as f:
        for row in csv.DictReader(f):
            runs.setdefault(int(row["np"]), []).append(float(row["seconds"]))
    med = {k: st.median(v) for k, v in sorted(runs.items())}
    base = med[min(med)]
    return {
        "np":      list(med),
        "seconds": [med[n] for n in med],
        "speedup": [base / med[n] for n in med],
        "eff":     [100 * base / med[n] / n for n in med],
    }


def read_results(path):
    path = _find(path)
    if not path or not os.path.exists(path):
        print(f"  [skip] {path} not found")
        return None
    with open(path) as f:
        return list(csv.DictReader(f))


def scaling_from_results(rows, midstate="on"):
    """Fallback when only bench.sh output exists (single run, no medians)."""
    if not rows:
        return None
    sel = [r for r in rows if r["experiment"] == "scaling" and r["midstate"] == midstate]
    if not sel:
        return None
    sel.sort(key=lambda r: int(r["np"]))
    nps = [int(r["np"]) for r in sel]
    secs = [float(r["seconds"]) for r in sel]
    base = secs[0]
    return {"np": nps, "seconds": secs,
            "speedup": [base / s for s in secs],
            "eff": [100 * base / s / n for s, n in zip(secs, nps)]}


def log2_axis(ax, ticks):
    ax.set_xscale("log", base=2)
    ax.set_xticks(ticks)
    ax.get_xaxis().set_major_formatter(FuncFormatter(lambda v, _: f"{int(v)}"))
    ax.set_xlim(min(ticks) * 0.85, max(ticks) * 1.2)
    ax.grid(axis="y", color=GRID, lw=.8)
    ax.set_axisbelow(True)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    ax.set_xlabel("MPI processes (np)")


# ============================================================ figure 1 =======
def fig_scaling(pc, colab):
    if not pc and not colab:
        return
    ticks = sorted(set((pc or {}).get("np", []) + (colab or {}).get("np", [])))
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11.5, 4.6))
    top = max((pc or {"speedup": [1]})["speedup"] + (colab or {"speedup": [1]})["speedup"]) * 1.28

    a1.plot([1, top], [1, top], ls=(0, (4, 3)), lw=1.5, color=MUT, zorder=1)
    a1.text(top * .82, top * .93, "ideal linear", color=MUT, fontsize=8.5,
            rotation=41, ha="center", va="center")
    for d, c, m in ((pc, PC, "o"), (colab, COLAB, "s")):
        if not d:
            continue
        a1.plot(d["np"], d["speedup"], lw=2, color=c, marker=m, ms=7,
                mec=SURF, mew=1.6, zorder=3, label=d["label"])
    if pc:
        a1.axvline(CONFIG["pc"]["cores"], color=PC, lw=1, ls=":", alpha=.5, zorder=0)
        a1.text(CONFIG["pc"]["cores"] * .95, top * .04,
                f"{CONFIG['pc']['cores']} physical cores", color=PC,
                fontsize=8.5, rotation=90, va="bottom", ha="right")
        for n, s in zip(pc["np"], pc["speedup"]):
            if n >= CONFIG["pc"]["cores"]:
                a1.annotate(f"{s:.2f}x", (n, s), textcoords="offset points",
                            xytext=(8, 4), color=INK, fontsize=9, fontweight="bold")
    a1.set_ylim(0, top)
    a1.set_ylabel("Speedup   $S_P = T_1 / T_P$")
    log2_axis(a1, ticks)
    a1.set_title("Strong scaling", color=INK, fontsize=12.5, fontweight="bold", loc="left")
    a1.legend(frameon=False, loc="upper left", fontsize=9, handlelength=1.6, labelcolor=INK2)

    a2.axhline(100, color=MUT, ls=(0, (4, 3)), lw=1.5)
    a2.text(max(ticks) * 1.15, 103, "ideal 100%", color=MUT, fontsize=8.5, ha="right")
    for d, c, m in ((pc, PC, "o"), (colab, COLAB, "s")):
        if not d:
            continue
        a2.plot(d["np"], d["eff"], lw=2, color=c, marker=m, ms=7, mec=SURF, mew=1.6)
    if pc:
        a2.axvline(CONFIG["pc"]["cores"], color=PC, lw=1, ls=":", alpha=.5, zorder=0)
        for n, e in zip(pc["np"], pc["eff"]):
            if n >= CONFIG["pc"]["cores"]:
                a2.annotate(f"{e:.0f}%", (n, e), textcoords="offset points",
                            xytext=(8, 6), color=INK, fontsize=9, fontweight="bold")
    a2.set_ylim(0, 122)
    a2.set_ylabel("Parallel efficiency   $E_P = S_P / P$   (%)")
    log2_axis(a2, ticks)
    a2.set_title("Parallel efficiency", color=INK, fontsize=12.5, fontweight="bold", loc="left")

    fig.tight_layout(pad=1.8, w_pad=3)
    fig.savefig("fig1_scaling.png", dpi=200, facecolor=SURF)
    print("  wrote fig1_scaling.png")


# ============================================================ figure 2 =======
def fig_throughput(pc, colab):
    if not pc:
        return
    ticks = pc["np"]
    hs_pc = [1 / s for s in pc["seconds"]]           # relative; rescaled below
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    x = list(range(len(ticks)))
    # recover absolute rates from seconds if the raw file carried them
    rate_pc = pc.get("rate") or [None] * len(ticks)
    if rate_pc[0] is None:
        rate_pc = hs_pc
    cm = dict(zip(colab["np"], colab.get("rate", []))) if colab else {}
    ax.bar([i - .2 for i in x], [r / 1e6 for r in rate_pc], width=.38,
           color=PC, zorder=3, label=CONFIG["pc"]["short"])
    if cm:
        ax.bar([i + .2 for i in x], [cm.get(n, 0) / 1e6 for n in ticks], width=.38,
               color=COLAB, zorder=3, label=CONFIG["colab"]["short"])
    top = max(rate_pc) / 1e6
    for i, r in enumerate(rate_pc):
        ax.text(i - .2, r / 1e6 + top * .02, f"{r/1e6:.0f}", ha="center", color=INK, fontsize=8.5)
    for i, n in enumerate(ticks):
        if cm.get(n):
            ax.text(i + .2, cm[n] / 1e6 + top * .02, f"{cm[n]/1e6:.1f}",
                    ha="center", color=INK2, fontsize=8.5)
    ax.set_xticks(x); ax.set_xticklabels(ticks)
    ax.set_xlabel("MPI processes (np)"); ax.set_ylabel("Hash rate   (MH/s)")
    ax.set_title("Throughput, midstate enabled", color=INK, fontsize=12.5,
                 fontweight="bold", loc="left")
    ax.legend(frameon=False, loc="upper left", fontsize=9, labelcolor=INK2)
    ax.grid(axis="y", color=GRID, lw=.8); ax.set_axisbelow(True)
    ax.set_ylim(0, top * 1.28)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout(pad=1.6)
    fig.savefig("fig2_throughput.png", dpi=200, facecolor=SURF)
    print("  wrote fig2_throughput.png")


# ============================================================ figure 3 =======
def fig_polling(rows_pc, rows_colab):
    series = []
    for rows, c, cfg in ((rows_pc, PC, CONFIG["pc"]), (rows_colab, COLAB, CONFIG["colab"])):
        if not rows:
            continue
        sel = [r for r in rows if r["experiment"] == "polling" and r["wasted"]]
        if not sel:
            continue
        sel.sort(key=lambda r: int(r["poll"]))
        series.append((cfg["short"], c,
                       [int(r["poll"]) for r in sel],
                       [int(r["wasted"]) for r in sel],
                       [float(r["seconds"]) for r in sel]))
    if not series:
        return
    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11.5, 4.4))

    for name, c, polls, wasted, secs in series:
        a1.plot(polls, wasted, lw=2, color=c, marker="o", ms=7, mec=SURF, mew=1.6, label=name)
        a1.annotate(f"{wasted[-1]:,}", (polls[-1], wasted[-1]), textcoords="offset points",
                    xytext=(-6, 10), color=INK, fontsize=9, fontweight="bold", ha="right")
    a1.set_xscale("log", base=2); a1.set_yscale("log")
    a1.set_xlabel("Polling interval  (hashes between checks)")
    a1.set_ylabel("Wasted post-solution hashes")
    a1.set_title("Cost of a large interval", color=INK, fontsize=12.5, fontweight="bold", loc="left")
    a1.get_xaxis().set_major_formatter(FuncFormatter(lambda v, _: f"{int(v)}"))
    a1.grid(color=GRID, lw=.8); a1.set_axisbelow(True)
    a1.legend(frameon=False, loc="upper left", fontsize=9, labelcolor=INK2)
    for sp in ("top", "right"):
        a1.spines[sp].set_visible(False)

    for name, c, polls, wasted, secs in series:
        base = min(secs)
        a2.plot(polls, [x / base for x in secs], lw=2, color=c, marker="o",
                ms=7, mec=SURF, mew=1.6, label=name)
        a2.annotate(f"{secs[0]/base:.1f}x", (polls[0], secs[0] / base),
                    textcoords="offset points", xytext=(9, -3), color=INK,
                    fontsize=9, fontweight="bold")
    a2.axhline(1.0, color=MUT, ls=(0, (4, 3)), lw=1.5)
    a2.set_xscale("log", base=2)
    a2.set_xlabel("Polling interval  (hashes between checks)")
    a2.set_ylabel("Time to solution, relative to best")
    a2.set_title("Cost of a small interval", color=INK, fontsize=12.5, fontweight="bold", loc="left")
    a2.get_xaxis().set_major_formatter(FuncFormatter(lambda v, _: f"{int(v)}"))
    a2.grid(color=GRID, lw=.8); a2.set_axisbelow(True)
    a2.legend(frameon=False, loc="upper right", fontsize=9, labelcolor=INK2)
    for sp in ("top", "right"):
        a2.spines[sp].set_visible(False)

    fig.tight_layout(pad=1.8, w_pad=3)
    fig.savefig("fig3_polling.png", dpi=200, facecolor=SURF)
    print("  wrote fig3_polling.png")


# ============================================================ figure 4 =======
def fig_midstate(rows_pc, rows_colab):
    bars = []
    for rows, cfg in ((rows_colab, CONFIG["colab"]), (rows_pc, CONFIG["pc"])):
        if not rows:
            continue
        one = {}
        for r in rows:
            if r["experiment"] == "scaling" and int(r["np"]) == 1:
                one[r["midstate"]] = float(r["rate_hs"])
        if "off" in one and "on" in one:
            bars.append((cfg["short"], one["off"], one["on"]))
    if not bars:
        return
    fig, ax = plt.subplots(figsize=(7.2, 4.4))
    x = list(range(len(bars)))
    off = [b[1] / 1e6 for b in bars]
    on = [b[2] / 1e6 for b in bars]
    ax.bar([i - .2 for i in x], off, width=.38, color=MUT, zorder=3, label="Midstate off")
    ax.bar([i + .2 for i in x], on, width=.38, color=PC, zorder=3, label="Midstate on")
    top = max(on)
    for i, (name, o, n) in enumerate(bars):
        ax.text(i - .2, o / 1e6 + top * .02, f"{o/1e6:.2f}", ha="center", color=INK2, fontsize=9)
        ax.text(i + .2, n / 1e6 + top * .02, f"{n/1e6:.2f}", ha="center", color=INK, fontsize=9)
        ax.text(i, top * 1.16, f"{n/o:.1f}x", ha="center", color=INK,
                fontsize=12, fontweight="bold")
    ax.set_xticks(x); ax.set_xticklabels([b[0] for b in bars])
    ax.set_ylabel("Single-process hash rate   (MH/s)")
    ax.set_title("Effect of the midstate optimisation  (np = 1)", color=INK,
                 fontsize=12.5, fontweight="bold", loc="left")
    ax.legend(frameon=False, loc="upper left", fontsize=9, labelcolor=INK2)
    ax.grid(axis="y", color=GRID, lw=.8); ax.set_axisbelow(True)
    ax.set_ylim(0, top * 1.30)
    for s in ("top", "right"):
        ax.spines[s].set_visible(False)
    fig.tight_layout(pad=1.6)
    fig.savefig("fig4_midstate.png", dpi=200, facecolor=SURF)
    print("  wrote fig4_midstate.png")


# ============================================================ figure 5 =======
def fig_difficulty(path="data/difficulty_sweep.csv"):
    """Hashes to first solution against difficulty, and the deviation from 2^d."""
    gt = {}
    for p in (path, "difficulty_sweep.csv"):
        if os.path.exists(p):
            with open(p) as f:
                for row in csv.DictReader(f):
                    gt[int(row["difficulty"])] = int(row["hashes"])
            break
    if not gt:
        print("  [skip] difficulty_sweep.csv not found")
        return

    d = sorted(gt)
    n = [gt[k] for k in d]
    exp = [2 ** k for k in d]
    r = [a / b for a, b in zip(n, exp)]

    fig, (a1, a2) = plt.subplots(1, 2, figsize=(11.5, 4.4))

    a1.plot(d, exp, ls=(0, (4, 3)), lw=1.5, color=MUT, label="Theoretical expectation  $2^{d}$")
    a1.plot(d, n, lw=2, color=PC, marker="o", ms=7, mec=SURF, mew=1.6,
            label="Hashes actually required")
    a1.set_yscale("log"); a1.set_xticks(d)
    a1.set_xlabel("Difficulty  (required leading zero bits)")
    a1.set_ylabel("Total hashes to first solution")
    a1.set_title("Work doubles with each bit", color=INK, fontsize=12.5,
                 fontweight="bold", loc="left")
    a1.grid(color=GRID, lw=.8); a1.set_axisbelow(True)
    a1.legend(frameon=False, loc="upper left", fontsize=9, labelcolor=INK2)
    for s in ("top", "right"): a1.spines[s].set_visible(False)

    a2.axhline(1.0, color=MUT, ls=(0, (4, 3)), lw=1.5)
    a2.text(min(d), 1.05, "expected mean = 1", color=MUT, fontsize=8.5, ha="left")
    a2.bar(d, r, width=1.3, color=PC, zorder=3)
    for k, v in zip(d, r):
        a2.text(k, v + 0.04, f"{v:.2f}", ha="center", color=INK, fontsize=8.5)
    a2.set_xticks(d); a2.set_ylim(0, max(1.72, max(r) * 1.16))
    a2.set_xlabel("Difficulty  (required leading zero bits)")
    a2.set_ylabel("Observed hashes / $2^{d}$")
    a2.set_title("Deviation from expectation, per difficulty", color=INK,
                 fontsize=12.5, fontweight="bold", loc="left")
    a2.grid(axis="y", color=GRID, lw=.8); a2.set_axisbelow(True)
    for s in ("top", "right"): a2.spines[s].set_visible(False)

    fig.tight_layout(pad=1.8, w_pad=3)
    fig.savefig("fig5_difficulty.png", dpi=200, facecolor=SURF)
    print("  wrote fig5_difficulty.png")


# ============================================================ figure 6 =======
# Schematic, not a plot of raw rows. The four numbers below are read off the
# `decomp` rows of results_pc.csv (difficulty 26, np=4) and are restated in the
# caption so the diagram cannot drift away from the measurement.
DECOMP_FACTS = {
    "block_nonce":   "2,185,860,257",
    "block_work":    "150,474,914 hashes   ·   4.61 s",
    "strided_nonce": "78,891,794",
    "strided_work":  "77,732,549 hashes   ·   2.33 s",
}


def fig_decomposition():
    from matplotlib.patches import Rectangle
    PALE = "#cfe0f7"

    fig, (a1, a2) = plt.subplots(2, 1, figsize=(11.0, 5.0))
    for ax in (a1, a2):
        ax.set_xlim(0, 100); ax.set_ylim(0, 10); ax.axis("off")

    def slicebar(ax, y, h=2.2):
        for rk in range(4):
            x0 = rk * 25
            ax.add_patch(Rectangle((x0, y), 25, h, fc="none", ec=GRID, lw=1.2))
            ax.text(x0 + 12.5, y + h + 0.55, f"rank {rk}", ha="center", color=INK2, fontsize=9)

    a1.text(0, 8.9, "Block decomposition", color=INK, fontsize=12.5, fontweight="bold")
    a1.text(0, 8.0, "Each rank owns one contiguous slice. Rank 2 meets a solution early inside"
                    " its own slice, so the search stops before rank 0 reaches the smaller one.",
            color=INK2, fontsize=9)
    slicebar(a1, 3.4)
    for rk in range(4):
        a1.add_patch(Rectangle((rk * 25, 3.4), 9, 2.2, fc=PALE, ec="none"))
    a1.add_patch(Rectangle((0, 6.9), 3, 0.9, fc=PALE, ec="none"))
    a1.text(3.8, 7.35, "region each rank actually searched before the stop signal",
            va="center", color=INK2, fontsize=8.5)
    a1.plot([18], [4.5], marker="*", ms=17, color=MUT, mec=SURF, mew=1)
    a1.annotate(f"{DECOMP_FACTS['strided_nonce']}\nreference solution — never reached",
                (18, 4.5), textcoords="offset points", xytext=(0, -46),
                ha="center", color=MUT, fontsize=8.5)
    a1.plot([55], [4.5], marker="*", ms=17, color=COLAB, mec=SURF, mew=1.4)
    a1.annotate(f"{DECOMP_FACTS['block_nonce']}\nreturned instead", (55, 4.5),
                textcoords="offset points", xytext=(0, -40), ha="center",
                color=COLAB, fontsize=8.5, fontweight="bold")
    a1.text(100, 1.0, f"total work  {DECOMP_FACTS['block_work']}", ha="right",
            color=INK, fontsize=9.5, fontweight="bold")

    a2.text(0, 8.9, "Strided decomposition", color=INK, fontsize=12.5, fontweight="bold")
    a2.text(0, 8.0, "Every rank crosses the whole space at 1/P density, so all four advance"
                    " together and the smallest solution is reached first.",
            color=INK2, fontsize=9)
    a2.add_patch(Rectangle((0, 3.4), 100, 2.2, fc="none", ec=GRID, lw=1.2))
    for i in range(72):
        a2.add_patch(Rectangle((i * 0.25, 3.4), 0.19, 2.2,
                               fc=[PC, "#5c9ae4", PALE, "#8fbcee"][i % 4], ec="none"))
    a2.text(9, 6.15, "ranks 0-3 interleaved", color=INK2, fontsize=9)
    a2.plot([18], [4.5], marker="*", ms=17, color=PC, mec=SURF, mew=1)
    a2.annotate(f"{DECOMP_FACTS['strided_nonce']}\nreturned — matches the serial result",
                (18, 4.5), textcoords="offset points", xytext=(0, -46),
                ha="center", color=PC, fontsize=8.5, fontweight="bold")
    a2.annotate("", xy=(18, 7.0), xytext=(0, 7.0),
                arrowprops=dict(arrowstyle="->", color=INK2, lw=1.3))
    a2.text(9, 7.25, "each rank hashes ~19.7 M", ha="center", color=INK2, fontsize=8.5)
    a2.text(100, 1.0, f"total work  {DECOMP_FACTS['strided_work']}", ha="right",
            color=INK, fontsize=9.5, fontweight="bold")
    a2.text(0, 0.2, "Nonce space 0 to 2^32, not to scale.  Measured at difficulty 26,"
                    " four processes.", color=MUT, fontsize=8)

    fig.tight_layout(pad=1.0)
    fig.savefig("fig6_decomposition.png", dpi=200, facecolor=SURF)
    print("  wrote fig6_decomposition.png")


# =================================================================== main ====
if __name__ == "__main__":
    print("Reading data...")
    rows_pc = read_results(CONFIG["pc"]["results"])
    rows_colab = read_results(CONFIG["colab"]["results"])

    pc = read_scaling(CONFIG["pc"]["scaling"]) or scaling_from_results(rows_pc)
    colab = read_scaling(CONFIG["colab"]["scaling"]) or scaling_from_results(rows_colab)
    for d, cfg in ((pc, CONFIG["pc"]), (colab, CONFIG["colab"])):
        if d:
            d["label"] = cfg["label"]
            d["rate"] = [None] * len(d["np"])

    # attach absolute hash rates where we can
    for d, path in ((pc, _find(CONFIG["pc"]["scaling"])), (colab, _find(CONFIG["colab"]["scaling"]))):
        if d and path and os.path.exists(path):
            runs = {}
            with open(path) as f:
                for row in csv.DictReader(f):
                    runs.setdefault(int(row["np"]), []).append(float(row["rate_hs"]))
            d["rate"] = [st.median(runs[n]) for n in d["np"]]
    for d, rows in ((pc, rows_pc), (colab, rows_colab)):
        if d and d["rate"][0] is None and rows:
            sel = sorted([r for r in rows if r["experiment"] == "scaling" and r["midstate"] == "on"],
                         key=lambda r: int(r["np"]))
            if sel:
                d["rate"] = [float(r["rate_hs"]) for r in sel]

    print("Rendering...")
    fig_scaling(pc, colab)
    fig_throughput(pc, colab)
    fig_polling(rows_pc, rows_colab)
    fig_midstate(rows_pc, rows_colab)
    fig_difficulty()
    fig_decomposition()
    print("Done.")
