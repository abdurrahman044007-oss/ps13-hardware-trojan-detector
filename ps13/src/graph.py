import os

import matplotlib.pyplot as plt

from parser import parse_netlist
from detector import analyze_circuit


# =========================================================
# Build graph from parsed gates
# =========================================================

def build_graph(gates):

    nodes = []
    edges = []

    added_nodes = set()

    for gate in gates:

        gate_name = gate["name"]

        gate_id = f"gate:{gate_name}"

        # -------------------------------------------------
        # Add gate node
        # -------------------------------------------------

        if gate_id not in added_nodes:

            nodes.append(
                {
                    "id": gate_id,
                    "label": gate_name,
                    "type": "gate",
                    "gate_type": gate["type"]
                }
            )

            added_nodes.add(gate_id)

        # -------------------------------------------------
        # Add input signals
        # -------------------------------------------------

        for signal in gate["inputs"]:

            signal_id = f"signal:{signal}"

            if signal_id not in added_nodes:

                nodes.append(
                    {
                        "id": signal_id,
                        "label": signal,
                        "type": "signal"
                    }
                )

                added_nodes.add(signal_id)

            edges.append(
                (
                    signal_id,
                    gate_id
                )
            )

        # -------------------------------------------------
        # Add output signal
        # -------------------------------------------------

        output = gate["output"]

        output_id = f"signal:{output}"

        if output_id not in added_nodes:

            nodes.append(
                {
                    "id": output_id,
                    "label": output,
                    "type": "signal"
                }
            )

            added_nodes.add(output_id)

        edges.append(
            (
                gate_id,
                output_id
            )
        )

    return nodes, edges


# =========================================================
# Calculate node positions
# =========================================================

def calculate_positions(gates):

    positions = {}

    signal_level = {}

    # -----------------------------------------------------
    # Determine approximate signal levels
    # -----------------------------------------------------

    for gate_index, gate in enumerate(gates):

        level = gate_index

        for signal in gate["inputs"]:

            if signal not in signal_level:

                signal_level[signal] = level

        output = gate["output"]

        signal_level[output] = level + 1

    # -----------------------------------------------------
    # Position signals
    # -----------------------------------------------------

    signals = list(signal_level.keys())

    signal_positions = {}

    for index, signal in enumerate(signals):

        x = signal_level.get(
            signal,
            0
        )

        y = -index

        signal_positions[signal] = (
            x,
            y
        )

    # -----------------------------------------------------
    # Position gates
    # -----------------------------------------------------

    for index, gate in enumerate(gates):

        gate_name = gate["name"]

        input_levels = []

        for signal in gate["inputs"]:

            input_levels.append(
                signal_level.get(
                    signal,
                    index
                )
            )

        if input_levels:

            x = max(input_levels) + 0.5

        else:

            x = index

        y = -index

        positions[f"gate:{gate_name}"] = (
            x,
            y
        )

    # -----------------------------------------------------
    # Add signal positions
    # -----------------------------------------------------

    for signal, position in signal_positions.items():

        positions[f"signal:{signal}"] = position

    return positions


# =========================================================
# Draw circuit graph
# =========================================================

def draw_graph(
    filename,
    output_filename
):

    print(
        f"\nReading circuit: {filename}"
    )

    # -----------------------------------------------------
    # Parse Verilog
    # -----------------------------------------------------

    gates = parse_netlist(filename)

    if not gates:

        print(
            "ERROR: No gates found."
        )

        return

    print(
        f"Found {len(gates)} gates."
    )

    # -----------------------------------------------------
    # Detect suspicious signals
    # -----------------------------------------------------

    candidates = analyze_circuit(
        gates
    )

    suspicious_signals = set()

    for candidate in candidates:

        suspicious_signals.add(
            candidate["signal"]
        )

    print(
        f"Suspicious signals: "
        f"{len(suspicious_signals)}"
    )

    # -----------------------------------------------------
    # Build graph
    # -----------------------------------------------------

    nodes, edges = build_graph(
        gates
    )

    positions = calculate_positions(
        gates
    )

    # -----------------------------------------------------
    # Create figure
    # -----------------------------------------------------

    plt.figure(
        figsize=(16, 9)
    )

    # -----------------------------------------------------
    # Draw edges
    # -----------------------------------------------------

    for source, target in edges:

        if (
            source not in positions
            or target not in positions
        ):

            continue

        x1, y1 = positions[source]

        x2, y2 = positions[target]

        plt.annotate(
            "",
            xy=(x2, y2),
            xytext=(x1, y1),
            arrowprops={
                "arrowstyle": "->",
                "linewidth": 1.2
            }
        )

    # -----------------------------------------------------
    # Draw nodes
    # -----------------------------------------------------

    for node in nodes:

        node_id = node["id"]

        if node_id not in positions:

            continue

        x, y = positions[node_id]

        label = node["label"]

        node_type = node["type"]

        # -------------------------------------------------
        # Signal node
        # -------------------------------------------------

        if node_type == "signal":

            signal_name = node["label"]

            if signal_name in suspicious_signals:

                plt.scatter(
                    x,
                    y,
                    s=900,
                    marker="o"
                )

                plt.text(
                    x,
                    y,
                    signal_name,
                    ha="center",
                    va="center",
                    fontsize=9,
                    fontweight="bold"
                )

            else:

                plt.scatter(
                    x,
                    y,
                    s=700,
                    marker="o"
                )

                plt.text(
                    x,
                    y,
                    signal_name,
                    ha="center",
                    va="center",
                    fontsize=9
                )

        # -------------------------------------------------
        # Gate node
        # -------------------------------------------------

        else:

            gate_type = node["gate_type"]

            plt.scatter(
                x,
                y,
                s=1200,
                marker="s"
            )

            plt.text(
                x,
                y,
                f"{gate_type.upper()}\n{label}",
                ha="center",
                va="center",
                fontsize=8,
                fontweight="bold"
            )

    # -----------------------------------------------------
    # Title
    # -----------------------------------------------------

    if suspicious_signals:

        title = (
            "Hardware Trojan Detection - "
            f"{os.path.basename(filename)}"
        )

    else:

        title = (
            "Circuit Graph - "
            f"{os.path.basename(filename)}"
        )

    plt.title(
        title,
        fontsize=16,
        fontweight="bold"
    )

    # -----------------------------------------------------
    # Axis
    # -----------------------------------------------------

    plt.axis("off")

    # -----------------------------------------------------
    # Add legend
    # -----------------------------------------------------

    plt.text(
        0.02,
        0.96,
        "○ Signal\n"
        "□ Logic Gate\n"
        "Highlighted signal = suspicious candidate",
        transform=plt.gca().transAxes,
        fontsize=10,
        verticalalignment="top"
    )

    # -----------------------------------------------------
    # Save image
    # -----------------------------------------------------

    os.makedirs(
        "reports",
        exist_ok=True
    )

    plt.tight_layout()

    plt.savefig(
        output_filename,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close()

    print(
        f"Graph saved to: "
        f"{output_filename}"
    )


# =========================================================
# Main
# =========================================================

def main():

    print("\n")

    print("=" * 70)

    print(
        "             PS13 CIRCUIT GRAPH VISUALIZATION"
    )

    print("=" * 70)

    # -----------------------------------------------------
    # Find project root
    # -----------------------------------------------------

    src_dir = os.path.dirname(
        os.path.abspath(__file__)
    )

    project_dir = os.path.dirname(
        src_dir
    )

    # -----------------------------------------------------
    # Correct file paths
    # -----------------------------------------------------

    clean_file = os.path.join(
        project_dir,
        "examples",
        "clean.v"
    )

    trojan_file = os.path.join(
        project_dir,
        "examples",
        "trojan.v"
    )

    reports_dir = os.path.join(
        project_dir,
        "reports"
    )

    os.makedirs(
        reports_dir,
        exist_ok=True
    )

    clean_graph = os.path.join(
        reports_dir,
        "clean_circuit_graph.png"
    )

    trojan_graph = os.path.join(
        reports_dir,
        "trojan_circuit_graph.png"
    )

    # -----------------------------------------------------
    # Clean circuit
    # -----------------------------------------------------

    draw_graph(
        clean_file,
        clean_graph
    )

    # -----------------------------------------------------
    # Trojan circuit
    # -----------------------------------------------------

    draw_graph(
        trojan_file,
        trojan_graph
    )

    # -----------------------------------------------------
    # Finished
    # -----------------------------------------------------

    print("\n" + "=" * 70)

    print(
        "                 GRAPH GENERATION COMPLETE"
    )

    print("=" * 70)

    print("\nGenerated files:")

    print(
        clean_graph
    )

    print(
        trojan_graph
    )


if __name__ == "__main__":

    main()