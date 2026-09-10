"""Headless, TeX-free figures; plotting never launches encrypted experiments."""
import csv

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

from theory import capacity, coefficients, lut_values, threshold


LABELS = {"AKP": "AKP", "BKSS": "BKSS", "FULL_THI": "CKKL", "SPARSE_THI": "Sparse-THI"}


def style():
    plt.rcParams.update({"font.family": "DejaVu Serif", "font.size": 10, "axes.grid": True,
                         "grid.alpha": 0.3, "grid.linestyle": ":", "savefig.bbox": "tight"})


def save(fig, output, name):
    output.mkdir(parents=True, exist_ok=True)
    for extension in ("png", "pdf"):
        fig.savefig(output / f"{name}.{extension}", dpi=220)
    plt.close(fig)


def experimental_phase(rows, output):
    style()
    fig, ax = plt.subplots(figsize=(6.4, 4.8))
    groups = list(dict.fromkeys((r["method"], r["order"]) for r in rows if r["p"] == 16))
    for method, order in groups:
        points = sorted((r for r in rows if r["p"] == 16 and r["method"] == method and r["order"] == order),
                        key=lambda r: r["input_noise"])
        x = np.array([r["input_noise"] for r in points])
        y = np.array([r["lut_noise"] for r in points]) - x
        label = LABELS[method] + (f" (order {order})" if method in ("AKP", "SPARSE_THI") else "")
        ax.plot(x, y, marker="o", markersize=2, linestyle="--" if method == "AKP" else "-", label=label)
    ax.axhline(0, color="grey", linewidth=0.8)
    ax.set(xlabel=r"$\log_2 v$ (bits)", ylabel=r"$\log_2 v' - \log_2 v$ (bits)",
           xlim=(-33, -5), ylim=(-19, 1))
    ax.legend(fontsize=8)
    save(fig, output, "figure1")


def theoretical_figures(output):
    style()
    fig, ax = plt.subplots(figsize=(6.4, 4.8))
    x = np.linspace(-35, -5, 800)
    rows = []
    for n, log_b in ((1, -32), (2, -31.5)):
        log_t = threshold(lut_values("ID", 16), n, "SPARSE_THI")
        log_output = np.logaddexp2((n + 1) * x - n * log_t, log_b)
        line, = ax.plot(x, log_output - x, label=f"Sparse-THI (order {n})")
        log_i, log_at_i, c = capacity(log_t, log_b, n)
        ax.scatter([log_i], [log_at_i - log_i], color=line.get_color())
        ax.axvline(log_t, linestyle=":", color=line.get_color(), alpha=0.6)
        rows.append({"order": n, "log_t": log_t, "log_b": log_b, "log_i": log_i, "capacity_bits": c})
    ax.axhline(0, color="grey", linewidth=0.8)
    ax.set(xlabel=r"$\log_2 v$ (bits)", ylabel=r"$\log_2 v' - \log_2 v$ (bits)",
           xlim=(-35, -5), ylim=(-16, 5))
    ax.legend()
    save(fig, output, "figure2")
    with (output / "figure2-parameters.csv").open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=rows[0])
        writer.writeheader()
        writer.writerows(rows)

    fig = plt.figure(figsize=(10, 4.8))
    angles = np.linspace(0, 2 * np.pi, 1200)
    z = np.exp(1j * angles)
    roots = np.exp(2j * np.pi * np.arange(4) / 4)
    for index, method in enumerate(("SPARSE_THI", "AKP"), start=1):
        ax = fig.add_subplot(1, 2, index, projection="3d")
        # Figure 3 deliberately omits normalization by p and uses uncentered 0,1,2,3.
        c = coefficients(np.arange(4, dtype=float), 1, method) * 4
        values = 2 * np.polynomial.polynomial.polyval(z, c).real
        dc = np.arange(1, len(c)) * c[1:]
        ax.plot(z.real, z.imag, values, color="tab:blue", linewidth=1.8)
        for j, root in enumerate(roots):
            derivative = np.polynomial.polynomial.polyval(root, dc)
            gx, gy = 2 * derivative.real, -2 * derivative.imag
            radius, theta = np.meshgrid(np.linspace(0, 0.22, 8), np.linspace(0, 2 * np.pi, 48))
            dx, dy = radius * np.cos(theta), radius * np.sin(theta)
            ax.plot_surface(root.real + dx, root.imag + dy, j + gx * dx + gy * dy,
                            color="grey", alpha=0.35, linewidth=0)
            ax.scatter(root.real, root.imag, j, color="black", s=18)
            if np.hypot(gx, gy) > 1e-9:
                ax.quiver(root.real, root.imag, j, gx, gy, 0, color="red", length=0.12, arrow_length_ratio=0.18)
        ax.set(xlabel=r"$\Re z$", ylabel=r"$\Im z$", zlabel="LUT value", title=LABELS[method], zlim=(-1, 4))
        ax.view_init(elev=24, azim=-55)
    fig.tight_layout()
    save(fig, output, "figure3")
