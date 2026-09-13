"""Render docs/asr-vs-fpr.png from the committed leaderboard JSON.

    python scripts/make_readme_chart.py
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt

ROOT = Path(__file__).resolve().parents[1]


def load(name):
    data = json.loads((ROOT / "results" / name).read_text(encoding="utf-8"))
    return data["cases"], {r["adapter"]: r for r in data["results"]}


cases, before = load("leaderboard.json")
_, after = load("leaderboard_after_fix.json")
ROWS = [
    ("cypher_guard (before fix)", before["cypher_guard"]),
    ("cypher_guard (after fix)", after["cypher_guard"]),
    ("querypilot (scoped allow-list)", after["querypilot[tables=employees,orders,audit_log]"]),
    ("querypilot (default config)", after["querypilot[tables=ALL]"]),
    ("prompt_denylist", after["prompt_denylist"]),
    ("naive (no defences)", after["naive"]),
]

plt.switch_backend("Agg")
fig, ax = plt.subplots(figsize=(10, 4.6), dpi=120, facecolor="#fcfcfb")
ax.set_facecolor("#fcfcfb")
h = 0.38
for i, (label, r) in enumerate(ROWS):
    y = len(ROWS) - 1 - i
    for offset, value, color, name in (
        (h / 2, r["attack_success_rate"], "#2a78d6", "attack success rate"),
        (-h / 2, r["false_positive_rate"], "#eb6834", "false-positive rate"),
    ):
        ax.barh(y + offset, value, height=h, color=color, edgecolor="#fcfcfb", lw=2,
                label=name if i == 0 else None)
        ax.text(value + 0.01, y + offset, f"{value:.3f}", va="center", fontsize=8, color="#52514e")
ax.set_yticks(range(len(ROWS)), [label for label, _ in reversed(ROWS)])
ax.set_xlim(0, 1.1)
ax.set_title(f"Attack success rate and false-positive rate per defence, lower is better\n"
             f"({cases}-case corpus; each adapter scores only the cases in its own language)",
             loc="left", color="#0b0b0b", fontsize=11)
ax.tick_params(colors="#52514e", labelsize=9, length=0)
ax.grid(axis="x", color="#e5e4e0", lw=0.8)
ax.set_axisbelow(True)
for side in ("top", "right", "left", "bottom"):
    ax.spines[side].set_visible(False)
ax.legend(frameon=False, loc="upper right", fontsize=9, labelcolor="#52514e")
fig.tight_layout()

out = ROOT / "docs" / "asr-vs-fpr.png"
out.parent.mkdir(exist_ok=True)
fig.savefig(out, facecolor=fig.get_facecolor())
print(f"wrote {out}")
