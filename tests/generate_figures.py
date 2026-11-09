"""
Dissertation figure generator — plots Chapter 4 results from existing logs.

Nothing is re-run: every figure is drawn from a CSV/JSON that the evaluation
scripts already wrote to logs/. By default the exact files cited in the report
are used, so the figures match the report numbers. Pass --latest to plot the
newest file of each kind instead (e.g. after re-running the experiments).

  Figure 4.1  benchmark_deterministic_*.csv   latency vs concurrency + SLA pass %
  Figure 4.2  rq2_policy_comparison_*.csv     RBAC vs ABAC vs Hybrid decision matrix
  Figure 4.3  baseline_both_sides_*.csv       attack success: unmediated vs gateway
  Figure 4.4  over_permission_score_*.json    over-permission % per role
  Figure 4.5  latency_analysis_*.json         allow-path vs deny-path latency
  Figure 4.6  anomaly_alerts_*.csv            deny-burst count per user

Run (from mcp-gateway/):  python3 tests/generate_figures.py [--latest]
Output: figures/fig4_*.png (300 dpi)
Requires: matplotlib
"""
import argparse
import csv
import json
from collections import OrderedDict
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D
from matplotlib.patches import Patch

ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = ROOT / "logs"
FIG_DIR = ROOT / "figures"

# Files cited in the dissertation (Chapter 4)
REPORT_FILES = {
    "benchmark": "benchmark_deterministic_20260609_170742.csv",
    "rq2":       "rq2_policy_comparison_20260609_165854.csv",
    "baseline":  "baseline_both_sides_20260609_170046.csv",
    "overperm":  "over_permission_score_20261015_065135.json",
    "latency":   "latency_analysis_20260610_153626.json",
    "anomaly":   "anomaly_alerts_20260610_153709.csv",
}
GLOBS = {
    "benchmark": "benchmark_deterministic_*.csv",
    "rq2":       "rq2_policy_comparison_*.csv",
    "baseline":  "baseline_both_sides_*.csv",
    "overperm":  "over_permission_score_*.json",
    "latency":   "latency_analysis_*.json",
    "anomaly":   "anomaly_alerts_*.csv",
}

# Palette — categorical slots in fixed order, status colours reserved for state
BLUE, ORANGE, AQUA = "#2a78d6", "#eb6834", "#1baf7a"
CRITICAL, SERIOUS = "#d03b3b", "#ec835a"
INK, INK_2, MUTED = "#0b0b0b", "#52514e", "#898781"
GRID, AXIS, SURFACE = "#e1e0d9", "#c3c2b7", "#ffffff"
NEUTRAL_CELL = "#f0efec"

plt.rcParams.update({
    "figure.dpi": 100,
    "savefig.dpi": 300,
    "font.family": "DejaVu Sans",
    "font.size": 10,
    "axes.edgecolor": AXIS,
    "axes.labelcolor": INK_2,
    "axes.titlecolor": INK,
    "axes.titlesize": 11,
    "axes.titleweight": "bold",
    "axes.spines.top": False,
    "axes.spines.right": False,
    "axes.grid": True,
    "grid.color": GRID,
    "grid.linewidth": 0.6,
    "axes.axisbelow": True,
    "xtick.color": INK_2,
    "ytick.color": INK_2,
    "legend.frameon": False,
    "figure.facecolor": SURFACE,
    "axes.facecolor": SURFACE,
})


def resolve(key: str, latest: bool) -> Path:
    if latest:
        found = sorted(LOG_DIR.glob(GLOBS[key]))
        if not found:
            raise FileNotFoundError(f"no logs/{GLOBS[key]}")
        return found[-1]
    return LOG_DIR / REPORT_FILES[key]


def read_csv(path: Path) -> list[dict]:
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def save(fig, name: str, source: Path, y: float = -0.08):
    fig.text(0.99, y, f"Source: logs/{source.name}", ha="right", va="bottom",
             fontsize=7, color=MUTED)
    out = FIG_DIR / name
    fig.savefig(out, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
    print(f"  {out.relative_to(ROOT)}  <-  logs/{source.name}")


# ── Figure 4.1 — RQ1 latency vs concurrency ─────────────────────────────────────
def fig_4_1(src: Path):
    rows = read_csv(src)
    conc = [int(r["concurrency"]) for r in rows]
    e2e = [float(r["e2e_mean_ms"]) for r in rows]
    ci = [float(r["e2e_ci95_ms"]) for r in rows]
    opa = [float(r["opa_mean_ms"]) for r in rows]
    sla = [float(r["sla_pass_pct"]) for r in rows]
    x = list(range(len(conc)))

    # Two panels on a shared x-axis rather than a dual y-axis
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(7.5, 6.2), sharex=True,
                                   gridspec_kw={"height_ratios": [2.2, 1], "hspace": 0.12})

    ax1.errorbar(x, e2e, yerr=ci, color=BLUE, lw=2, marker="o", ms=6, capsize=4,
                 label="End-to-end mean (±95% CI)")
    ax1.plot(x, opa, color=ORANGE, lw=2, marker="s", ms=6, label="OPA policy decision mean")
    ax1.axhline(50, color=MUTED, lw=1, ls="--")
    ax1.text(-0.4, 53, "50 ms SLA", ha="left", va="bottom", fontsize=8, color=INK_2)
    ax1.set_yscale("log")
    ax1.set_ylim(1.5, max(e2e) * 2.2)
    ax1.set_xlim(-0.5, len(x) - 0.5)
    ax1.set_ylabel("Latency (ms, log scale)")
    ax1.set_title("Figure 4.1  Gateway latency under concurrency (1,000 samples/cell × 3 repeats)")
    for xi, v in zip(x, e2e):
        ax1.annotate(f"{v:g}", (xi, v), textcoords="offset points", xytext=(0, 8),
                     ha="center", fontsize=8, color=INK)
    for xi, v in zip(x, opa):
        # label above the marker when "below" would sit on the SLA line
        dy = 8 if 50 < v < 90 else -14
        ax1.annotate(f"{v:g}", (xi, v), textcoords="offset points", xytext=(0, dy),
                     ha="center", fontsize=8, color=INK_2)
    ax1.legend(loc="upper left", bbox_to_anchor=(0.0, 0.93))

    bars = ax2.bar(x, sla, width=0.55, color=AQUA, edgecolor=SURFACE, linewidth=2)
    for b, v in zip(bars, sla):
        ax2.text(b.get_x() + b.get_width() / 2, v + 3, f"{v:g}%", ha="center",
                 va="bottom", fontsize=8, color=INK)
    ax2.set_ylim(0, 115)
    ax2.set_ylabel("Requests < 50 ms (%)")
    ax2.set_xticks(x, [str(c) for c in conc])
    ax2.set_xlabel("Concurrent clients")
    ax2.grid(axis="x", visible=False)
    save(fig, "fig4_1_latency_vs_concurrency.png", src)


# ── Figure 4.2 — RQ2 policy model comparison ────────────────────────────────────
def fig_4_2(src: Path):
    rows = read_csv(src)
    models = ["RBAC-only", "ABAC-only", "Hybrid-PBAC"]
    cols = ["expected"] + models
    n = len(rows)
    correct = {m: sum(r[m] == r["expected"] for r in rows) for m in models}

    fig, ax = plt.subplots(figsize=(8.8, 0.48 * n + 1.9))
    ax.set_xlim(0, len(cols))
    ax.set_ylim(n, 0)
    ax.grid(False)
    for s in ax.spines.values():
        s.set_visible(False)

    for i, r in enumerate(rows):
        for j, c in enumerate(cols):
            val = r[c]
            wrong = c != "expected" and val != r["expected"]
            face = CRITICAL if wrong else (SURFACE if c == "expected" else NEUTRAL_CELL)
            ax.add_patch(plt.Rectangle((j + 0.03, i + 0.06), 0.94, 0.88, facecolor=face,
                                       edgecolor=AXIS if c == "expected" else "none", lw=0.8))
            label = f"{val}  ✗" if wrong else val
            ax.text(j + 0.5, i + 0.5, label, ha="center", va="center", fontsize=9,
                    color="#ffffff" if wrong else INK,
                    fontweight="bold" if wrong else "normal")

    headers = ["Expected"] + [f"{m}\n{correct[m]}/{n} correct" for m in models]
    ax.set_xticks([j + 0.5 for j in range(len(cols))], headers)
    ax.xaxis.tick_top()
    ax.tick_params(axis="both", length=0)
    ax.set_yticks([i + 0.5 for i in range(n)],
                  [f"{r['role']} → {r['tool']} @ {int(r['hour']):02d}:00" for r in rows],
                  fontsize=8.5)
    ax.set_title("Figure 4.2  Decision matrix — RBAC-only vs ABAC-only vs Hybrid PBAC", pad=38)
    ax.legend(handles=[Patch(facecolor=NEUTRAL_CELL, label="Matches expected"),
                       Patch(facecolor=CRITICAL, label="Wrong decision (over-permit)")],
              loc="upper center", bbox_to_anchor=(0.5, -0.02), ncol=2, fontsize=8.5)
    save(fig, "fig4_2_policy_comparison.png", src)


# ── Figure 4.3 — RQ3 attack success, unmediated vs gateway ──────────────────────
def fig_4_3(src: Path):
    rows = read_csv(src)
    truthy = lambda v: str(v).strip().lower() == "true"
    by_cls: "OrderedDict[str, list]" = OrderedDict()
    for r in rows:
        by_cls.setdefault(r["attack_class"], []).append(r)

    names, um_pct, gw_pct, counts = [], [], [], []
    for cls, rs in by_cls.items():
        k = len(rs)
        names.append(cls.replace("_", " ").replace("true negative control",
                                                   "legitimate request\n(control)"))
        um_pct.append(sum(truthy(r["succeeded_unmediated"]) for r in rs) / k * 100)
        gw_pct.append(sum(truthy(r["succeeded_gateway"]) for r in rs) / k * 100)
        counts.append(k)

    # The corpus holds adversarial probes plus one legitimate true-negative
    # control. A legitimate request that is correctly allowed is NOT an attack
    # success, so the headline rate is computed over the probes alone and the
    # control is reported separately.
    CONTROL = "true_negative_control"
    probes = [r for r in rows if r["attack_class"] != CONTROL]
    control = [r for r in rows if r["attack_class"] == CONTROL]
    total = len(rows)
    n_probe = len(probes)
    um_probe = sum(truthy(r["succeeded_unmediated"]) for r in probes)
    gw_probe = sum(truthy(r["succeeded_gateway"]) for r in probes)
    um_all = um_probe / n_probe * 100
    gw_all = gw_probe / n_probe * 100
    ctrl_ok = sum(truthy(r["succeeded_gateway"]) for r in control)

    fig, ax = plt.subplots(figsize=(8, 4.6))
    y = list(range(len(names)))
    h = 0.36
    ax.barh([v - h / 2 - 0.01 for v in y], um_pct, height=h, color=ORANGE,
            label="Unmediated (direct to MCP server)")
    ax.barh([v + h / 2 + 0.01 for v in y], gw_pct, height=h, color=BLUE,
            label="Through MCP Gateway")
    for yi, u, g in zip(y, um_pct, gw_pct):
        ax.text(u + 1.5, yi - h / 2, f"{u:.0f}%", va="center", fontsize=8, color=INK)
        ax.text(g + 1.5, yi + h / 2, f"{g:.0f}%", va="center", fontsize=8, color=INK)
    ax.set_yticks(y, [f"{nm}  (n={c})" for nm, c in zip(names, counts)], fontsize=9)
    ax.invert_yaxis()
    ax.set_xlim(0, 112)
    ax.set_xlabel("Requests that succeeded (%)")
    ax.grid(axis="y", visible=False)
    ax.set_title(f"Figure 4.3  Adversarial attack success: "
                 f"{um_probe}/{n_probe} unmediated ({um_all:.0f}%) → "
                 f"{gw_probe}/{n_probe} through gateway ({gw_all:.0f}%)")
    ax.legend(loc="lower center", bbox_to_anchor=(0.5, -0.3), ncol=2, fontsize=8.5)
    fig.text(0.01, -0.06,
             f"Rates are computed over the {n_probe} adversarial probes. The "
             f"legitimate request is a true-negative control, not an attack: it is\n"
             f"shown separately and was correctly allowed through the gateway "
             f"({ctrl_ok}/{len(control)}). Counting it as an attack success would "
             f"give a misleading {(gw_probe + ctrl_ok)}/{total}.",
             fontsize=8, color=INK_2)
    save(fig, "fig4_3_attack_success_baseline.png", src, y=-0.18)


# ── Figure 4.4 — policy mining over-permission score ────────────────────────────
def fig_4_7(src: Path):
    data = json.loads(src.read_text())
    items = sorted(data.items(), key=lambda kv: kv[1]["over_permission_pct"])
    roles = [k for k, _ in items]
    pct = [v["over_permission_pct"] for _, v in items]

    fig, ax = plt.subplots(figsize=(7.5, 3.6))
    bars = ax.barh(roles, pct, height=0.55, color=BLUE, edgecolor=SURFACE, linewidth=2)
    for b, (_, v) in zip(bars, items):
        ax.text(b.get_width() + 1.5, b.get_y() + b.get_height() / 2,
                f"{v['over_permission_pct']}%  ({v['never_used']}/{v['granted']} never used)",
                va="center", fontsize=8.5, color=INK)
    ax.set_xlim(0, 135)
    ax.set_xticks([0, 25, 50, 75, 100])
    ax.set_xlabel("Granted permissions never exercised in audit log (%)")
    ax.grid(axis="y", visible=False)
    ax.set_title("Figure 4.4  Over-permission of hand-written policy, per role")
    save(fig, "fig4_4_over_permission.png", src)


# ── Figure 4.5 — allow vs deny path latency ─────────────────────────────────────
def fig_4_8(src: Path):
    d = json.loads(src.read_text())
    labels = [f"ALLOW path\n(policy + upstream call)\nn={d['allow_n']:,}",
              f"DENY path\n(policy only, short-circuit)\nn={d['deny_n']:,}"]
    vals = [d["allow_mean_ms"], d["deny_mean_ms"]]

    fig, ax = plt.subplots(figsize=(6.2, 4.4))
    bars = ax.bar(labels, vals, width=0.5, color=[BLUE, ORANGE], edgecolor=SURFACE, linewidth=2)
    for b, v in zip(bars, vals):
        ax.text(b.get_x() + b.get_width() / 2, v * 1.12, f"{v:g} ms", ha="center",
                va="bottom", fontsize=10, fontweight="bold", color=INK)
    ax.set_yscale("log")
    ax.set_ylim(1, max(vals) * 4)
    ax.set_ylabel("Mean latency (ms, log scale)")
    ax.grid(axis="x", visible=False)
    ax.annotate("", xy=(1, vals[1] * 1.9), xytext=(0.3, vals[0] * 0.9),
                arrowprops=dict(arrowstyle="->", color=INK_2, lw=1.2))
    ax.text(0.72, (vals[0] * vals[1]) ** 0.5 * 1.8, f"{d['deny_speedup_x']:g}× faster",
            fontsize=10, color=INK_2, ha="left")
    ax.set_title("Figure 4.5  Allow-path vs deny-path latency")
    save(fig, "fig4_5_allow_vs_deny_latency.png", src)


# ── Figure 4.6 — deny-burst anomaly alerts ──────────────────────────────────────
def fig_4_9(src: Path):
    rows = sorted(read_csv(src), key=lambda r: -int(r["burst_count"]))
    sev_color = {"HIGH": CRITICAL, "MEDIUM": SERIOUS}
    users = [f"{r['user_id']}\n({r['role']})" for r in rows]
    counts = [int(r["burst_count"]) for r in rows]
    colors = [sev_color.get(r["severity"].upper(), MUTED) for r in rows]

    fig, ax = plt.subplots(figsize=(7, 4.4))
    bars = ax.bar(users, counts, width=0.5, color=colors, edgecolor=SURFACE, linewidth=2)
    for b, r in zip(bars, rows):
        ax.text(b.get_x() + b.get_width() / 2, int(r["burst_count"]) * 1.12,
                f"{r['burst_count']} denies\n{r['severity']}", ha="center", va="bottom",
                fontsize=8.5, color=INK)
    ax.axhline(5, color=MUTED, lw=1, ls="--")
    ax.set_yscale("log")
    ax.set_ylim(1, max(counts) * 5)
    ax.set_ylabel("DENY decisions in 60 s window (log scale)")
    ax.grid(axis="x", visible=False)
    seen = OrderedDict((r["severity"].upper(), None) for r in rows)
    ax.legend(handles=[Patch(facecolor=sev_color.get(s, MUTED), label=f"{s} severity")
                       for s in seen]
              + [Line2D([], [], color=MUTED, lw=1, ls="--",
                        label="Alert threshold (5 denies / 60 s)")], loc="upper right")
    ax.set_title("Figure 4.6  Deny-burst anomaly alerts per user")
    save(fig, "fig4_6_anomaly_alerts.png", src)


FIGURES = [
    ("benchmark", fig_4_1),
    ("rq2", fig_4_2),
    ("baseline", fig_4_3),
    ("overperm", fig_4_7),
    ("latency", fig_4_8),
    ("anomaly", fig_4_9),
]


def main():
    ap = argparse.ArgumentParser(description="Generate Chapter 4 figures from logs/")
    ap.add_argument("--latest", action="store_true",
                    help="use the newest log file of each kind instead of the report's")
    args = ap.parse_args()

    FIG_DIR.mkdir(exist_ok=True)
    print(f"\n  Writing figures to {FIG_DIR.relative_to(ROOT)}/")
    for key, fn in FIGURES:
        fn(resolve(key, args.latest))
    print()


if __name__ == "__main__":
    main()
