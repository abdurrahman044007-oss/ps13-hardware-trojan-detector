import os
import sys
import json
import inspect

from parser import parse_netlist
from probability import calculate_probabilities
from detector import analyze_circuit
from timing import analyze_timing


# ============================================================
# CONFIGURATION
# ============================================================

CLEAN_FILE = "examples/clean.v"
TROJAN_FILE = "examples/trojan.v"

REPORT_DIR = "reports"
GRAPH_DIR = os.path.join(REPORT_DIR, "graphs")

JSON_REPORT = os.path.join(
    REPORT_DIR,
    "trojan_report.json"
)

RARE_THRESHOLD = 0.05


# ============================================================
# GENERAL UTILITIES
# ============================================================

def safe_float(value):
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def make_json_safe(value):
    """
    Convert objects into JSON-safe structures.
    """

    if isinstance(value, dict):
        return {
            str(k): make_json_safe(v)
            for k, v in value.items()
        }

    if isinstance(value, (list, tuple, set)):
        return [
            make_json_safe(v)
            for v in value
        ]

    if isinstance(value, float):

        if value != value:
            return None

        if value == float("inf"):
            return None

        if value == float("-inf"):
            return None

    # Handle custom objects returned by timing code
    if hasattr(value, "__dict__"):
        return make_json_safe(
            value.__dict__
        )

    return value


# ============================================================
# BASIC NET INFORMATION
# ============================================================

def get_net_information(gates):

    created_nets = set()
    input_nets = set()

    for gate in gates:

        created_nets.add(
            gate["output"]
        )

        for signal in gate["inputs"]:
            input_nets.add(signal)

    all_nets = (
        created_nets |
        input_nets
    )

    primary_inputs = (
        input_nets -
        created_nets
    )

    primary_outputs = (
        created_nets -
        input_nets
    )

    return {
        "total_nets": len(all_nets),

        "primary_inputs":
            sorted(primary_inputs),

        "primary_outputs":
            sorted(primary_outputs),

        "all_nets":
            sorted(all_nets)
    }


# ============================================================
# FAN-IN / FAN-OUT
# ============================================================

def calculate_fan_in_out(gates):

    """
    Calculate fan-in and fan-out for gates and nets.

    Gate fan-in:
        Number of input signals.

    Gate fan-out:
        Number of gates driven by its output.

    Net fan-in:
        Number of gate outputs driving the net.
        Primary input nets have fan-in 0.

    Net fan-out:
        Number of gates using that net.
    """

    # --------------------------------------------------------
    # Net -> gates using it
    # --------------------------------------------------------

    net_consumers = {}

    # --------------------------------------------------------
    # Net -> gates creating it
    # --------------------------------------------------------

    net_creators = {}

    for gate in gates:

        gate_name = gate["name"]
        output = gate["output"]

        net_creators.setdefault(
            output,
            []
        )

        net_creators[
            output
        ].append(gate_name)

        for signal in gate["inputs"]:

            net_consumers.setdefault(
                signal,
                []
            )

            net_consumers[
                signal
            ].append(gate_name)

    # --------------------------------------------------------
    # Gate fan-in / fan-out
    # --------------------------------------------------------

    gate_info = {}

    for gate in gates:

        name = gate["name"]
        output = gate["output"]

        gate_fan_in = len(
            gate["inputs"]
        )

        gate_fan_out = len(
            net_consumers.get(
                output,
                []
            )
        )

        gate_info[name] = {

            "type":
                gate["type"],

            "inputs":
                list(gate["inputs"]),

            "output":
                output,

            "fan_in":
                gate_fan_in,

            "fan_out":
                gate_fan_out,

            "consumers":
                list(
                    net_consumers.get(
                        output,
                        []
                    )
                )
        }

    # --------------------------------------------------------
    # Net fan-in / fan-out
    # --------------------------------------------------------

    all_nets = set(
        net_creators.keys()
    ) | set(
        net_consumers.keys()
    )

    net_info = {}

    for net in sorted(all_nets):

        creators = net_creators.get(
            net,
            []
        )

        consumers = net_consumers.get(
            net,
            []
        )

        net_info[net] = {

            "fan_in":
                len(creators),

            "fan_out":
                len(consumers),

            "drivers":
                list(creators),

            "consumers":
                list(consumers)
        }

    return {
        "gates": gate_info,
        "nets": net_info
    }


# ============================================================
# RARE SIGNAL DETECTION
# ============================================================

def detect_rare_signals(
    probabilities,
    threshold=RARE_THRESHOLD
):

    rare_1 = []
    rare_0 = []

    for signal, probability in (
        probabilities.items()
    ):

        probability = safe_float(
            probability
        )

        if probability is None:
            continue

        probability_0 = (
            1.0 -
            probability
        )

        # ----------------------------------------------------
        # Rare 1
        # ----------------------------------------------------

        if probability <= threshold:

            rare_1.append({

                "signal":
                    signal,

                "probability_1":
                    probability,

                "probability_0":
                    probability_0,

                "status":
                    "RARE-1"
            })

        # ----------------------------------------------------
        # Rare 0
        # ----------------------------------------------------

        elif probability >= (
            1.0 - threshold
        ):

            rare_0.append({

                "signal":
                    signal,

                "probability_1":
                    probability,

                "probability_0":
                    probability_0,

                "status":
                    "RARE-0"
            })

    return {

        "threshold":
            threshold,

        "rare_1":
            rare_1,

        "rare_0":
            rare_0,

        "total_rare_signals":
            len(rare_1) +
            len(rare_0)
    }


# ============================================================
# LOGIC DEPTH
# ============================================================

def calculate_logic_depth(gates):

    """
    Calculate gate-level logic depth.

    Primary inputs are depth 0.
    First logic gate is depth 1.
    """

    depths = {}

    remaining = list(gates)

    changed = True

    while remaining and changed:

        changed = False
        unresolved = []

        for gate in remaining:

            inputs = gate["inputs"]

            input_depths = []

            can_process = True

            for signal in inputs:

                if signal in depths:

                    input_depths.append(
                        depths[signal]
                    )

                else:

                    # Signal can be a primary input
                    input_depths.append(0)

            if not can_process:

                unresolved.append(
                    gate
                )

                continue

            if input_depths:

                depth = (
                    max(input_depths)
                    + 1
                )

            else:

                depth = 1

            depths[
                gate["output"]
            ] = depth

            changed = True

        remaining = unresolved

    # --------------------------------------------------------
    # Critical depth
    # --------------------------------------------------------

    critical_depth = 0
    critical_signal = None

    for signal, depth in depths.items():

        if depth > critical_depth:

            critical_depth = depth
            critical_signal = signal

    # --------------------------------------------------------
    # Gate depth
    # --------------------------------------------------------

    gate_depths = {}

    for gate in gates:

        gate_depths[
            gate["name"]
        ] = depths.get(
            gate["output"],
            0
        )

    return {

        "signal_depths":
            depths,

        "gate_depths":
            gate_depths,

        "critical_depth":
            critical_depth,

        "critical_signal":
            critical_signal
    }


# ============================================================
# BUILD GRAPH DATA
# ============================================================

def build_graph_data(gates):

    nodes = []
    edges = []

    # --------------------------------------------------------
    # Gate nodes
    # --------------------------------------------------------

    for gate in gates:

        gate_name = gate["name"]

        nodes.append({

            "id":
                "gate:" + gate_name,

            "type":
                "gate",

            "name":
                gate_name,

            "gate_type":
                gate["type"],

            "label":
                (
                    gate_name +
                    "\n" +
                    gate["type"].upper()
                )
        })

    # --------------------------------------------------------
    # Net nodes
    # --------------------------------------------------------

    nets = set()

    for gate in gates:

        nets.add(
            gate["output"]
        )

        for signal in gate["inputs"]:

            nets.add(
                signal
            )

    for net in sorted(nets):

        nodes.append({

            "id":
                "net:" + net,

            "type":
                "net",

            "name":
                net,

            "label":
                net
        })

    # --------------------------------------------------------
    # Edges
    # --------------------------------------------------------

    for gate in gates:

        gate_id = (
            "gate:" +
            gate["name"]
        )

        output_id = (
            "net:" +
            gate["output"]
        )

        # Gate -> output net
        edges.append({

            "from":
                gate_id,

            "to":
                output_id,

            "relationship":
                "drives"
        })

        # Input net -> gate
        for signal in gate["inputs"]:

            input_id = (
                "net:" +
                signal
            )

            edges.append({

                "from":
                    input_id,

                "to":
                    gate_id,

                "relationship":
                    "feeds"
            })

    return {
        "nodes": nodes,
        "edges": edges
    }


# ============================================================
# VISUAL PNG GRAPH
# ============================================================

def generate_visual_graph(
    gates,
    filename,
    suspicious_signal=None,
    payload_signal=None,
    victim_signal=None
):

    """
    Generate a visual circuit graph using matplotlib.

    No Graphviz required.
    """

    os.makedirs(
        GRAPH_DIR,
        exist_ok=True
    )

    base_name = os.path.splitext(
        os.path.basename(filename)
    )[0]

    png_file = os.path.join(
        GRAPH_DIR,
        base_name +
        "_circuit.png"
    )

    dot_file = os.path.join(
        GRAPH_DIR,
        base_name +
        "_circuit.dot"
    )

    # --------------------------------------------------------
    # Import matplotlib
    # --------------------------------------------------------

    try:

        import matplotlib.pyplot as plt
        from matplotlib.patches import FancyBboxPatch

    except ImportError:

        return {

            "png":
                None,

            "dot":
                None,

            "generated":
                False,

            "error":
                (
                    "matplotlib is not installed. "
                    "Run: python -m pip install matplotlib"
                )
        }

    # --------------------------------------------------------
    # Build graph data
    # --------------------------------------------------------

    graph_data = build_graph_data(
        gates
    )

    # --------------------------------------------------------
    # Write DOT file
    # --------------------------------------------------------

    dot_lines = [
        "digraph Circuit {",
        "    rankdir=LR;"
    ]

    for gate in gates:

        dot_lines.append(
            f'    "{gate["name"]}" '
            f'[shape=box, '
            f'label="{gate["name"]}\\n'
            f'{gate["type"].upper()}"];'
        )

        for signal in gate["inputs"]:

            dot_lines.append(
                f'    "{signal}" -> '
                f'"{gate["name"]}";'
            )

        dot_lines.append(
            f'    "{gate["name"]}" -> '
            f'"{gate["output"]}";'
        )

    dot_lines.append("}")

    try:

        with open(
            dot_file,
            "w",
            encoding="utf-8"
        ) as file:

            file.write(
                "\n".join(dot_lines)
            )

    except Exception:

        dot_file = None

    # --------------------------------------------------------
    # Determine graph positions
    # --------------------------------------------------------

    positions = {}

    gate_x = {}
    net_x = {}

    # Determine stages using logic depth
    depth_info = calculate_logic_depth(
        gates
    )

    max_depth = max(
        depth_info["critical_depth"],
        1
    )

    # Gates
    for gate in gates:

        depth = depth_info[
            "gate_depths"
        ].get(
            gate["name"],
            1
        )

        gate_x[
            gate["name"]
        ] = depth

    # Nets
    for gate in gates:

        output = gate["output"]

        depth = depth_info[
            "signal_depths"
        ].get(
            output,
            1
        )

        net_x[output] = depth + 0.45

        for signal in gate["inputs"]:

            if signal not in net_x:

                # Primary inputs
                net_x[signal] = 0

    # --------------------------------------------------------
    # Vertical arrangement
    # --------------------------------------------------------

    all_nets = sorted(
        net_x.keys()
    )

    net_y = {}

    for index, net in enumerate(
        all_nets
    ):

        net_y[net] = (
            len(all_nets)
            - index
        )

    gate_y = {}

    for gate in gates:

        output = gate["output"]

        if output in net_y:

            gate_y[
                gate["name"]
            ] = net_y[output]

        else:

            gate_y[
                gate["name"]
            ] = 0

    # --------------------------------------------------------
    # Create figure
    # --------------------------------------------------------

    height = max(
        6,
        len(all_nets) * 0.65
    )

    width = max(
        12,
        (max_depth + 2) * 2.2
    )

    fig, ax = plt.subplots(
        figsize=(width, height)
    )

    # --------------------------------------------------------
    # Draw edges first
    # --------------------------------------------------------

    for gate in gates:

        gx = gate_x[
            gate["name"]
        ]

        gy = gate_y[
            gate["name"]
        ]

        for signal in gate["inputs"]:

            if signal not in net_y:
                continue

            nx = net_x[
                signal
            ]

            ny = net_y[
                signal
            ]

            ax.annotate(
                "",
                xy=(gx - 0.28, gy),
                xytext=(nx + 0.18, ny),
                arrowprops=dict(
                    arrowstyle="->",
                    linewidth=1.3
                )
            )

        # Gate output
        output = gate["output"]

        if output in net_y:

            nx = net_x[
                output
            ]

            ny = net_y[
                output
            ]

            ax.annotate(
                "",
                xy=(nx - 0.18, ny),
                xytext=(gx + 0.28, gy),
                arrowprops=dict(
                    arrowstyle="->",
                    linewidth=1.3
                )
            )

    # --------------------------------------------------------
    # Draw net nodes
    # --------------------------------------------------------

    for net in all_nets:

        x = net_x[net]
        y = net_y[net]

        if net == suspicious_signal:

            face = "red"

        elif net == payload_signal:

            face = "orange"

        elif net == victim_signal:

            face = "yellow"

        else:

            face = "white"

        ax.scatter(
            x,
            y,
            s=900,
            marker="o",
            facecolors=face,
            edgecolors="black",
            linewidths=1.4,
            zorder=3
        )

        ax.text(
            x,
            y,
            net,
            ha="center",
            va="center",
            fontsize=9,
            zorder=4
        )

    # --------------------------------------------------------
    # Draw gate nodes
    # --------------------------------------------------------

    for gate in gates:

        name = gate["name"]

        x = gate_x[name]
        y = gate_y[name]

        if (
            gate["output"] ==
            suspicious_signal
        ):

            face = "red"

        elif (
            gate["output"] ==
            payload_signal
        ):

            face = "orange"

        else:

            face = "lightgray"

        patch = FancyBboxPatch(
            (
                x - 0.28,
                y - 0.22
            ),
            0.56,
            0.44,
            boxstyle="round,pad=0.03",
            facecolor=face,
            edgecolor="black",
            linewidth=1.5,
            zorder=3
        )

        ax.add_patch(
            patch
        )

        ax.text(
            x,
            y,
            name +
            "\n" +
            gate["type"].upper(),
            ha="center",
            va="center",
            fontsize=8,
            zorder=4
        )

    # --------------------------------------------------------
    # Labels
    # --------------------------------------------------------

    ax.set_title(
        "PS13 Hardware Trojan Circuit Graph\n"
        + os.path.basename(filename),
        fontsize=15
    )

    ax.text(
        0.01,
        0.01,
        "Red = suspicious | "
        "Orange = payload | "
        "Yellow = victim",
        transform=ax.transAxes,
        fontsize=9
    )

    ax.set_xlim(
        -0.7,
        max_depth + 1.5
    )

    ax.set_ylim(
        0,
        len(all_nets) + 1
    )

    ax.axis(
        "off"
    )

    plt.tight_layout()

    try:

        plt.savefig(
            png_file,
            dpi=180,
            bbox_inches="tight"
        )

        plt.close(
            fig
        )

        generated = os.path.exists(
            png_file
        )

    except Exception as error:

        plt.close(
            fig
        )

        return {

            "png":
                None,

            "dot":
                dot_file,

            "generated":
                False,

            "error":
                str(error)
        }

    return {

        "png":
            png_file
            if generated
            else None,

        "dot":
            dot_file,

        "generated":
            generated,

        "nodes":
            graph_data["nodes"],

        "edges":
            graph_data["edges"]
    }


# ============================================================
# PAYLOAD / VICTIM ANALYSIS
# ============================================================

def find_payload_victim(
    gates,
    candidates
):

    if not candidates:

        return {
            "found":
                False
        }

    # --------------------------------------------------------
    # Highest suspicion candidate
    # --------------------------------------------------------

    candidate = candidates[0]

    trigger = candidate[
        "signal"
    ]

    creator = candidate.get(
        "creator"
    )

    trigger_gate = None

    if creator:

        trigger_gate = creator[
            "name"
        ]

    # --------------------------------------------------------
    # Build downstream map
    # --------------------------------------------------------

    downstream = {}

    for gate in gates:

        for signal in gate[
            "inputs"
        ]:

            downstream.setdefault(
                signal,
                []
            ).append(
                gate
            )

    # --------------------------------------------------------
    # Find payload gate
    # --------------------------------------------------------

    payload_gate = None

    queue = [
        trigger
    ]

    visited = set()

    while queue:

        current = queue.pop(0)

        if current in visited:
            continue

        visited.add(
            current
        )

        for gate in downstream.get(
            current,
            []
        ):

            if current == trigger:

                payload_gate = gate
                break

            queue.append(
                gate["output"]
            )

        if payload_gate:
            break

    if not payload_gate:

        return {

            "found":
                False,

            "trigger":
                trigger,

            "trigger_gate":
                trigger_gate
        }

    # --------------------------------------------------------
    # Payload information
    # --------------------------------------------------------

    payload_signal = (
        payload_gate["output"]
    )

    payload_gate_name = (
        payload_gate["name"]
    )

    payload_gate_type = (
        payload_gate["type"]
    )

    # --------------------------------------------------------
    # Victim signal
    # --------------------------------------------------------

    victim_signal = None

    for signal in payload_gate[
        "inputs"
    ]:

        if signal != trigger:

            victim_signal = signal
            break

    # --------------------------------------------------------
    # Circuit outputs
    # --------------------------------------------------------

    created = {
        gate["output"]
        for gate in gates
    }

    used = {
        signal
        for gate in gates
        for signal in gate["inputs"]
    }

    circuit_outputs = (
        created - used
    )

    # --------------------------------------------------------
    # Trace payload to output
    # --------------------------------------------------------

    trace = [
        payload_signal
    ]

    current = payload_signal

    visited = set()

    while current not in (
        circuit_outputs
    ):

        if current in visited:
            break

        visited.add(
            current
        )

        next_gate = None

        for gate in gates:

            if current in gate[
                "inputs"
            ]:

                next_gate = gate
                break

        if not next_gate:
            break

        current = next_gate[
            "output"
        ]

        trace.append(
            current
        )

    affected_output = (
        current
        if current in circuit_outputs
        else None
    )

    return {

        "found":
            True,

        "trigger":
            trigger,

        "trigger_gate":
            trigger_gate,

        "payload_gate":
            payload_gate_name,

        "payload_gate_type":
            payload_gate_type,

        "payload_signal":
            payload_signal,

        "victim_signal":
            victim_signal,

        "affected_output":
            affected_output,

        "trace":
            trace
    }


# ============================================================
# TIMING ANALYSIS
# ============================================================

def run_timing_analysis(gates):

    """
    Calls the user's timing.py.

    Supports timing.py implementations that accept:
        analyze_timing(gates)

    or, if necessary, attempts a no-argument call.
    """

    try:

        signature = inspect.signature(
            analyze_timing
        )

        parameters = list(
            signature.parameters.values()
        )

        required = [
            p for p in parameters
            if p.default is inspect.Parameter.empty
            and p.kind in (
                inspect.Parameter.POSITIONAL_ONLY,
                inspect.Parameter.POSITIONAL_OR_KEYWORD
            )
        ]

        if len(required) >= 1:

            return analyze_timing(
                gates
            )

        return analyze_timing()

    except Exception as error:

        return {

            "status":
                "TIMING ANALYSIS ERROR",

            "error":
                str(error)
        }


# ============================================================
# TERMINAL: PARSING
# ============================================================

def print_parsing(
    filename,
    gates,
    net_info,
    fan_info
):

    print(
        "\n[1] PARSING DETAILS"
    )

    print(
        "-" * 80
    )

    print(
        f"File                : {filename}"
    )

    print(
        f"Total gates         : {len(gates)}"
    )

    print(
        f"Total nets          : "
        f"{net_info['total_nets']}"
    )

    print(
        f"Primary inputs      : "
        f"{len(net_info['primary_inputs'])}"
    )

    print(
        f"Primary outputs     : "
        f"{len(net_info['primary_outputs'])}"
    )

    print(
        "\nPrimary inputs:"
    )

    print(
        "  "
        + (
            ", ".join(
                net_info[
                    "primary_inputs"
                ]
            )
            or "None"
        )
    )

    print(
        "\nPrimary outputs:"
    )

    print(
        "  "
        + (
            ", ".join(
                net_info[
                    "primary_outputs"
                ]
            )
            or "None"
        )
    )

    # --------------------------------------------------------
    # Gate table
    # --------------------------------------------------------

    print(
        "\nGate details:"
    )

    print(
        f"{'Gate':<10}"
        f"{'Type':<10}"
        f"{'Output':<15}"
        f"{'Fan-in':<10}"
        f"{'Fan-out':<10}"
    )

    print(
        "-" * 80
    )

    for gate in gates:

        info = fan_info[
            "gates"
        ][
            gate["name"]
        ]

        print(
            f"{gate['name']:<10}"
            f"{gate['type'].upper():<10}"
            f"{gate['output']:<15}"
            f"{info['fan_in']:<10}"
            f"{info['fan_out']:<10}"
        )

    # --------------------------------------------------------
    # Net table
    # --------------------------------------------------------

    print(
        "\nNet details:"
    )

    print(
        f"{'Net':<18}"
        f"{'Fan-in':<10}"
        f"{'Fan-out':<10}"
        f"{'Drivers':<20}"
    )

    print(
        "-" * 80
    )

    for net, info in (
        fan_info["nets"].items()
    ):

        print(
            f"{net:<18}"
            f"{info['fan_in']:<10}"
            f"{info['fan_out']:<10}"
            f"{', '.join(info['drivers']) or 'PRIMARY INPUT':<20}"
        )


# ============================================================
# TERMINAL: PROBABILITY + RARE SIGNALS
# ============================================================

def print_probability(
    probabilities,
    rare_info,
    fan_info
):

    print(
        "\n[2] PROBABILITY ANALYSIS"
    )

    print(
        "-" * 80
    )

    print(
        f"{'Signal':<18}"
        f"{'P(1)':<14}"
        f"{'P(0)':<14}"
        f"{'Fan-in':<10}"
        f"{'Fan-out':<10}"
        f"{'Status'}"
    )

    print(
        "-" * 80
    )

    rare_map = {}

    for item in (
        rare_info["rare_1"] +
        rare_info["rare_0"]
    ):

        rare_map[
            item["signal"]
        ] = item["status"]

    for signal, probability in (
        probabilities.items()
    ):

        net_data = fan_info[
            "nets"
        ].get(
            signal,
            {}
        )

        status = rare_map.get(
            signal,
            "NORMAL"
        )

        print(
            f"{signal:<18}"
            f"{probability:<14.6f}"
            f"{1.0-probability:<14.6f}"
            f"{net_data.get('fan_in', 0):<10}"
            f"{net_data.get('fan_out', 0):<10}"
            f"{status}"
        )

    # --------------------------------------------------------
    # Rare signals
    # --------------------------------------------------------

    print(
        "\n[3] RARE SIGNAL DETECTION"
    )

    print(
        "-" * 80
    )

    print(
        f"Threshold           : "
        f"{rare_info['threshold']}"
    )

    print(
        f"Total rare signals  : "
        f"{rare_info['total_rare_signals']}"
    )

    print(
        "\nRare-1 signals:"
    )

    if rare_info["rare_1"]:

        for item in rare_info[
            "rare_1"
        ]:

            signal = item[
                "signal"
            ]

            net_data = fan_info[
                "nets"
            ].get(
                signal,
                {}
            )

            print(
                f"  {signal:<15}"
                f"P(1) = "
                f"{item['probability_1']:.6f}   "
                f"Fan-in = "
                f"{net_data.get('fan_in', 0)}   "
                f"Fan-out = "
                f"{net_data.get('fan_out', 0)}   "
                f"Drivers = "
                f"{', '.join(net_data.get('drivers', [])) or 'PRIMARY INPUT'}"
            )

    else:

        print(
            "  None"
        )

    print(
        "\nRare-0 signals:"
    )

    if rare_info["rare_0"]:

        for item in rare_info[
            "rare_0"
        ]:

            signal = item[
                "signal"
            ]

            net_data = fan_info[
                "nets"
            ].get(
                signal,
                {}
            )

            print(
                f"  {signal:<15}"
                f"P(1) = "
                f"{item['probability_1']:.6f}   "
                f"Fan-in = "
                f"{net_data.get('fan_in', 0)}   "
                f"Fan-out = "
                f"{net_data.get('fan_out', 0)}"
            )

    else:

        print(
            "  None"
        )


# ============================================================
# TERMINAL: TROJAN ANALYSIS
# ============================================================

def print_detector(
    candidates,
    payload_victim,
    fan_info
):

    print(
        "\n[4] TROJAN / STRUCTURAL ANALYSIS"
    )

    print(
        "-" * 80
    )

    if not candidates:

        print(
            "No suspicious candidates found."
        )

        return

    candidate = candidates[0]

    signal = candidate[
        "signal"
    ]

    print(
        f"Suspicious / malicious net : "
        f"{signal}"
    )

    if candidate.get(
        "creator"
    ):

        creator = candidate[
            "creator"
        ]

        creator_name = creator[
            "name"
        ]

        gate_info = fan_info[
            "gates"
        ].get(
            creator_name,
            {}
        )

        print(
            f"Suspicious gate            : "
            f"{creator_name}"
        )

        print(
            f"Gate type                  : "
            f"{creator['type'].upper()}"
        )

        print(
            f"Gate fan-in                : "
            f"{gate_info.get('fan_in', 0)}"
        )

        print(
            f"Gate fan-out               : "
            f"{gate_info.get('fan_out', 0)}"
        )

    net_data = fan_info[
        "nets"
    ].get(
        signal,
        {}
    )

    print(
        f"Net fan-in                 : "
        f"{net_data.get('fan_in', 0)}"
    )

    print(
        f"Net fan-out                : "
        f"{net_data.get('fan_out', 0)}"
    )

    print(
        f"Probability P(1)           : "
        f"{candidate['probability']:.6f}"
    )

    print(
        f"Probability P(0)           : "
        f"{1.0 - candidate['probability']:.6f}"
    )

    print(
        f"Suspicion score             : "
        f"{candidate['score']}/100"
    )

    print(
        f"Reaches circuit output      : "
        f"{candidate['reaches_output']}"
    )

    print(
        "\nEvidence:"
    )

    for evidence in candidate[
        "evidence"
    ]:

        print(
            f"  [+] {evidence}"
        )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if candidate["score"] >= 70:

        print(
            "\nClassification              : "
            "HIGHLY SUSPICIOUS"
        )

    elif candidate["score"] >= 50:

        print(
            "\nClassification              : "
            "SUSPICIOUS"
        )

    else:

        print(
            "\nClassification              : "
            "LOW SUSPICION"
        )


# ============================================================
# TERMINAL: PAYLOAD / VICTIM
# ============================================================

def print_payload_victim(
    payload_victim,
    fan_info
):

    print(
        "\n[5] TRIGGER / PAYLOAD / VICTIM"
    )

    print(
        "-" * 80
    )

    if not payload_victim.get(
        "found"
    ):

        print(
            "Payload/victim trace "
            "could not be established."
        )

        return

    trigger = payload_victim[
        "trigger"
    ]

    payload = payload_victim[
        "payload_signal"
    ]

    victim = payload_victim[
        "victim_signal"
    ]

    trigger_data = fan_info[
        "nets"
    ].get(
        trigger,
        {}
    )

    payload_data = fan_info[
        "nets"
    ].get(
        payload,
        {}
    )

    victim_data = fan_info[
        "nets"
    ].get(
        victim,
        {}
    )

    print(
        f"Trigger net                : "
        f"{trigger}"
    )

    print(
        f"Trigger gate               : "
        f"{payload_victim['trigger_gate']}"
    )

    print(
        f"Trigger fan-in             : "
        f"{trigger_data.get('fan_in', 0)}"
    )

    print(
        f"Trigger fan-out            : "
        f"{trigger_data.get('fan_out', 0)}"
    )

    print(
        f"\nPayload gate               : "
        f"{payload_victim['payload_gate']}"
    )

    print(
        f"Payload operation          : "
        f"{payload_victim['payload_gate_type'].upper()}"
    )

    print(
        f"Payload signal             : "
        f"{payload}"
    )

    print(
        f"Payload fan-in             : "
        f"{payload_data.get('fan_in', 0)}"
    )

    print(
        f"Payload fan-out            : "
        f"{payload_data.get('fan_out', 0)}"
    )

    print(
        f"\nVictim signal              : "
        f"{victim}"
    )

    print(
        f"Victim fan-in              : "
        f"{victim_data.get('fan_in', 0)}"
    )

    print(
        f"Victim fan-out             : "
        f"{victim_data.get('fan_out', 0)}"
    )

    print(
        f"\nAffected output            : "
        f"{payload_victim['affected_output']}"
    )

    print(
        "\nPayload trace:"
    )

    print(
        "  "
        + " -> ".join(
            payload_victim[
                "trace"
            ]
        )
    )


# ============================================================
# TERMINAL: LOGIC DEPTH
# ============================================================

def print_logic_depth(
    logic_depth
):

    print(
        "\n[6] LOGIC DEPTH"
    )

    print(
        "-" * 80
    )

    print(
        f"{'Signal':<20}"
        f"{'Depth'}"
    )

    print(
        "-" * 40
    )

    for signal, depth in (
        logic_depth[
            "signal_depths"
        ].items()
    ):

        print(
            f"{signal:<20}"
            f"{depth}"
        )

    print(
        f"\nCritical logic depth     : "
        f"{logic_depth['critical_depth']}"
    )

    print(
        f"Critical signal          : "
        f"{logic_depth['critical_signal']}"
    )


# ============================================================
# TERMINAL: TIMING
# ============================================================

def print_timing(
    timing_result
):

    print(
        "\n[7] STATIC TIMING / "
        "SIDE-CHANNEL TIMING"
    )

    print(
        "-" * 80
    )

    if not isinstance(
        timing_result,
        dict
    ):

        print(
            timing_result
        )

        return

    if "error" in timing_result:

        print(
            f"Timing error             : "
            f"{timing_result['error']}"
        )

        return

    # --------------------------------------------------------
    # Display all timing fields
    # --------------------------------------------------------

    for key, value in (
        timing_result.items()
    ):

        display_key = (
            str(key)
            .replace("_", " ")
            .title()
        )

        if isinstance(
            value,
            dict
        ):

            print(
                f"\n{display_key}:"
            )

            for sub_key, sub_value in (
                value.items()
            ):

                print(
                    f"  {str(sub_key):<25}"
                    f": {sub_value}"
                )

        elif isinstance(
            value,
            list
        ):

            print(
                f"\n{display_key}:"
            )

            for item in value:

                print(
                    f"  {item}"
                )

        else:

            print(
                f"{display_key:<30}"
                f": {value}"
            )


# ============================================================
# TERMINAL: GRAPH
# ============================================================

def print_graph(
    graph_info
):

    print(
        "\n[8] VISUAL CIRCUIT GRAPH"
    )

    print(
        "-" * 80
    )

    if graph_info.get(
        "generated"
    ):

        print(
            "Visual PNG generated successfully."
        )

        print(
            f"PNG graph                : "
            f"{graph_info['png']}"
        )

    else:

        print(
            "Visual graph was not generated."
        )

        if graph_info.get(
            "error"
        ):

            print(
                f"Reason                   : "
                f"{graph_info['error']}"
            )

    if graph_info.get(
        "dot"
    ):

        print(
            f"DOT graph                : "
            f"{graph_info['dot']}"
        )


# ============================================================
# ANALYZE ONE CIRCUIT
# ============================================================

def analyze_circuit_file(
    title,
    filename
):

    print(
        "\n"
        + "=" * 80
    )

    print(title)

    print(
        "=" * 80
    )

    # --------------------------------------------------------
    # Parsing
    # --------------------------------------------------------

    gates = parse_netlist(
        filename
    )

    if not gates:

        raise RuntimeError(
            "No gates found in netlist."
        )

    net_info = get_net_information(
        gates
    )

    fan_info = calculate_fan_in_out(
        gates
    )

    print_parsing(
        filename,
        gates,
        net_info,
        fan_info
    )

    # --------------------------------------------------------
    # Probability
    # --------------------------------------------------------

    probabilities = (
        calculate_probabilities(
            gates
        )
    )

    rare_info = (
        detect_rare_signals(
            probabilities
        )
    )

    print_probability(
        probabilities,
        rare_info,
        fan_info
    )

    # --------------------------------------------------------
    # Detector
    # --------------------------------------------------------

    candidates = analyze_circuit(
        gates
    )

    payload_victim = (
        find_payload_victim(
            gates,
            candidates
        )
    )

    print_detector(
        candidates,
        payload_victim,
        fan_info
    )

    # --------------------------------------------------------
    # Payload / victim
    # --------------------------------------------------------

    print_payload_victim(
        payload_victim,
        fan_info
    )

    # --------------------------------------------------------
    # Logic depth
    # --------------------------------------------------------

    logic_depth = (
        calculate_logic_depth(
            gates
        )
    )

    print_logic_depth(
        logic_depth
    )

    # --------------------------------------------------------
    # Timing
    # --------------------------------------------------------

    timing_result = (
        run_timing_analysis(
            gates
        )
    )

    print_timing(
        timing_result
    )

    # --------------------------------------------------------
    # Identify suspicious graph elements
    # --------------------------------------------------------

    suspicious_signal = None
    payload_signal = None
    victim_signal = None

    if candidates:

        suspicious_signal = (
            candidates[0]["signal"]
        )

    if payload_victim.get(
        "found"
    ):

        payload_signal = (
            payload_victim[
                "payload_signal"
            ]
        )

        victim_signal = (
            payload_victim[
                "victim_signal"
            ]
        )

    # --------------------------------------------------------
    # Visual graph
    # --------------------------------------------------------

    graph_info = (
        generate_visual_graph(
            gates,
            filename,
            suspicious_signal,
            payload_signal,
            victim_signal
        )
    )

    print_graph(
        graph_info
    )

    # --------------------------------------------------------
    # Complete result
    # --------------------------------------------------------

    return {

        "file":
            filename,

        "parsing": {

            "total_gates":
                len(gates),

            "total_nets":
                net_info[
                    "total_nets"
                ],

            "primary_inputs":
                net_info[
                    "primary_inputs"
                ],

            "primary_outputs":
                net_info[
                    "primary_outputs"
                ],

            "all_nets":
                net_info[
                    "all_nets"
                ],

            "gates":
                gates
        },

        "fan_in_fan_out":
            fan_info,

        "probability_analysis": {

            "signals":
                probabilities
        },

        "rare_signal_detection":
            rare_info,

        "trojan_detection": {

            "candidates":
                candidates,

            "top_candidate":
                (
                    candidates[0]
                    if candidates
                    else None
                )
        },

        "trigger_payload_victim":
            payload_victim,

        "logic_depth":
            logic_depth,

        "timing_analysis":
            timing_result,

        "graph":
            graph_info
    }


# ============================================================
# MAIN
# ============================================================

def main():

    os.makedirs(
        REPORT_DIR,
        exist_ok=True
    )

    os.makedirs(
        GRAPH_DIR,
        exist_ok=True
    )

    print(
        "\n"
        + "=" * 80
    )

    print(
        "       PS13 HARDWARE TROJAN DETECTION & ANALYSIS"
    )

    print(
        "=" * 80
    )

    # --------------------------------------------------------
    # Check input files
    # --------------------------------------------------------

    if not os.path.exists(
        CLEAN_FILE
    ):

        print(
            f"\nERROR: {CLEAN_FILE} not found."
        )

        sys.exit(1)

    if not os.path.exists(
        TROJAN_FILE
    ):

        print(
            f"\nERROR: {TROJAN_FILE} not found."
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Clean circuit
    # --------------------------------------------------------

    try:

        clean_result = (
            analyze_circuit_file(
                "1. CLEAN CIRCUIT",
                CLEAN_FILE
            )
        )

    except Exception as error:

        print(
            "\nERROR analyzing clean circuit:"
        )

        print(
            error
        )

        sys.exit(1)

    # --------------------------------------------------------
    # Trojan circuit
    # --------------------------------------------------------

    try:

        trojan_result = (
            analyze_circuit_file(
                "2. TROJAN CIRCUIT",
                TROJAN_FILE
            )
        )

    except Exception as error:

        print(
            "\nERROR analyzing Trojan circuit:"
        )

        print(
            error
        )

        sys.exit(1)

    # ========================================================
    # FINAL COMPARISON
    # ========================================================

    print(
        "\n"
        + "=" * 80
    )

    print(
        "                    FINAL COMPARISON"
    )

    print(
        "=" * 80
    )

    clean_candidates = (
        clean_result[
            "trojan_detection"
        ][
            "candidates"
        ]
    )

    trojan_candidates = (
        trojan_result[
            "trojan_detection"
        ][
            "candidates"
        ]
    )

    clean_rare = (
        clean_result[
            "rare_signal_detection"
        ][
            "total_rare_signals"
        ]
    )

    trojan_rare = (
        trojan_result[
            "rare_signal_detection"
        ][
            "total_rare_signals"
        ]
    )

    clean_score = 0

    if clean_candidates:

        clean_score = max(
            c["score"]
            for c in clean_candidates
        )

    trojan_score = 0

    if trojan_candidates:

        trojan_score = max(
            c["score"]
            for c in trojan_candidates
        )

    print(
        f"\nClean suspicious candidates : "
        f"{len(clean_candidates)}"
    )

    print(
        f"Trojan suspicious candidates: "
        f"{len(trojan_candidates)}"
    )

    print(
        f"\nClean rare signals          : "
        f"{clean_rare}"
    )

    print(
        f"Trojan rare signals         : "
        f"{trojan_rare}"
    )

    print(
        f"\nClean maximum score         : "
        f"{clean_score}/100"
    )

    print(
        f"Trojan maximum score        : "
        f"{trojan_score}/100"
    )

    # --------------------------------------------------------
    # Final classification
    # --------------------------------------------------------

    if (
        trojan_candidates
        and not clean_candidates
    ):

        classification = (
            "TROJAN DETECTED"
        )

        print(
            "\n🚨 TROJAN DETECTED"
        )

    elif trojan_candidates:

        classification = (
            "SUSPICIOUS LOGIC DETECTED"
        )

        print(
            "\n⚠️ SUSPICIOUS LOGIC DETECTED"
        )

    else:

        classification = (
            "NO TROJAN INDICATORS DETECTED"
        )

        print(
            "\n✅ NO TROJAN INDICATORS DETECTED"
        )

    # ========================================================
    # JSON REPORT
    # ========================================================

    report = {

        "project":
            "PS13 Hardware Trojan Detection",

        "classification":
            classification,

        "configuration": {

            "rare_signal_threshold":
                RARE_THRESHOLD
        },

        "clean_circuit":
            clean_result,

        "trojan_circuit":
            trojan_result,

        "comparison": {

            "clean_rare_signals":
                clean_rare,

            "trojan_rare_signals":
                trojan_rare,

            "clean_suspicious_candidates":
                len(clean_candidates),

            "trojan_suspicious_candidates":
                len(trojan_candidates),

            "clean_max_suspicion_score":
                clean_score,

            "trojan_max_suspicion_score":
                trojan_score
        }
    }

    # --------------------------------------------------------
    # Make JSON safe
    # --------------------------------------------------------

    report = make_json_safe(
        report
    )

    # --------------------------------------------------------
    # Write JSON
    # --------------------------------------------------------

    with open(
        JSON_REPORT,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            report,
            file,
            indent=4
        )

    # ========================================================
    # FINAL
    # ========================================================

    print(
        "\n"
        + "=" * 80
    )

    print(
        "                    REPORT GENERATED"
    )

    print(
        "=" * 80
    )

    print(
        f"\nJSON report:"
    )

    print(
        f"  {JSON_REPORT}"
    )

    print(
        "\nVisual graphs:"
    )

    print(
        f"  {GRAPH_DIR}"
    )

    print(
        "\nFiles generated:"
    )

    print(
        "  ✓ trojan_report.json"
    )

    print(
        "  ✓ clean_circuit.png"
    )

    print(
        "  ✓ trojan_circuit.png"
    )

    print(
        "  ✓ clean_circuit.dot"
    )

    print(
        "  ✓ trojan_circuit.dot"
    )

    print(
        "\n"
        + "=" * 80
    )

    print(
        "                  ANALYSIS COMPLETE"
    )

    print(
        "=" * 80
    )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()