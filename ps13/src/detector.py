import sys

from parser import parse_netlist
from probability import calculate_probabilities


# =========================================================
# CONFIGURATION
# =========================================================

RARE_THRESHOLD = 0.05


# =========================================================
# BUILD CIRCUIT RELATIONSHIPS
# =========================================================

def build_circuit_maps(gates):
    """
    Build useful relationships between signals and gates.
    """

    creators = {}
    downstream = {}

    for gate in gates:

        output = gate["output"]

        # Gate that creates each signal
        creators[output] = gate

        # Gates that consume each signal
        for signal in gate["inputs"]:

            if signal not in downstream:
                downstream[signal] = []

            downstream[signal].append(gate)

    return creators, downstream


# =========================================================
# FIND CIRCUIT OUTPUTS
# =========================================================

def find_circuit_outputs(gates, creators):
    """
    A gate output that is never used as another gate's
    input is considered a circuit output.
    """

    used_as_input = set()

    for gate in gates:

        for signal in gate["inputs"]:

            used_as_input.add(signal)

    all_outputs = set(creators.keys())

    return all_outputs - used_as_input


# =========================================================
# FIND PATH TO OUTPUT
# =========================================================

def find_output_path(
    signal,
    downstream,
    circuit_outputs
):
    """
    Trace a signal through downstream gates until a
    circuit output is reached.

    Returns a list describing the path.
    """

    queue = [
        (signal, [signal])
    ]

    visited = set()

    while queue:

        current, path = queue.pop(0)

        if current in visited:
            continue

        visited.add(current)

        # Circuit output reached
        if current in circuit_outputs:

            return path

        for gate in downstream.get(
            current,
            []
        ):

            next_signal = gate["output"]

            new_path = path + [
                gate["name"],
                next_signal
            ]

            queue.append(
                (
                    next_signal,
                    new_path
                )
            )

    return []


# =========================================================
# PAYLOAD / VICTIM TRACING
# =========================================================

def trace_payload_victim(
    gates,
    suspicious_signal
):
    """
    Trace a suspicious signal and attempt to identify:

        Trigger
        Payload gate
        Payload signal
        Victim signal
        Affected output

    This is designed for structural Trojan analysis.

    For the supplied Trojan:

        trigger -> T2 XOR -> y

    where:

        T2(y, normal_y, trigger)

    Therefore:

        trigger = trigger
        payload gate = T2
        payload signal = y
        victim = normal_y
        affected output = y
    """

    creators, downstream = build_circuit_maps(
        gates
    )

    circuit_outputs = find_circuit_outputs(
        gates,
        creators
    )

    # -----------------------------------------------------
    # Candidate trigger
    # -----------------------------------------------------

    trigger = suspicious_signal

    trigger_creator = creators.get(
        trigger
    )

    # -----------------------------------------------------
    # Search gates using trigger
    # -----------------------------------------------------

    payload_gate = None

    for gate in downstream.get(
        trigger,
        []
    ):

        gate_type = gate["type"].lower()

        # XOR/XNOR is a strong structural indication
        # of payload modification in this example.
        if gate_type in (
            "xor",
            "xnor"
        ):

            payload_gate = gate
            break

    # If no XOR/XNOR gate uses it directly,
    # inspect the first downstream gate.
    if payload_gate is None:

        next_gates = downstream.get(
            trigger,
            []
        )

        if next_gates:

            payload_gate = next_gates[0]

    # -----------------------------------------------------
    # No payload found
    # -----------------------------------------------------

    if payload_gate is None:

        return {
            "found": False,
            "trigger": trigger,
            "trigger_gate": (
                trigger_creator["name"]
                if trigger_creator
                else None
            ),
            "payload_gate": None,
            "payload_signal": None,
            "victim_signal": None,
            "affected_output": None,
            "trace": []
        }

    # -----------------------------------------------------
    # Payload output
    # -----------------------------------------------------

    payload_signal = payload_gate[
        "output"
    ]

    # -----------------------------------------------------
    # Identify victim
    # -----------------------------------------------------
    #
    # In a typical XOR payload:
    #
    #   xor output, legitimate_signal, trigger
    #
    # The input other than the trigger is the
    # legitimate/victim signal.
    # -----------------------------------------------------

    victim_signal = None

    for signal in payload_gate["inputs"]:

        if signal != trigger:

            victim_signal = signal

            break

    # -----------------------------------------------------
    # Find affected output
    # -----------------------------------------------------

    affected_output = None

    if payload_signal in circuit_outputs:

        affected_output = payload_signal

    else:

        output_path = find_output_path(
            payload_signal,
            downstream,
            circuit_outputs
        )

        if output_path:

            affected_output = output_path[-1]

    # -----------------------------------------------------
    # Build readable trace
    # -----------------------------------------------------

    trace = [
        trigger,
        payload_gate["name"],
        payload_signal
    ]

    if victim_signal:

        # Victim is an input to payload gate,
        # so represent it separately rather than
        # pretending it is downstream.
        pass

    # -----------------------------------------------------
    # Return result
    # -----------------------------------------------------

    return {
        "found": True,

        "trigger": trigger,

        "trigger_gate": (
            trigger_creator["name"]
            if trigger_creator
            else None
        ),

        "payload_gate": payload_gate[
            "name"
        ],

        "payload_gate_type": payload_gate[
            "type"
        ],

        "payload_signal": payload_signal,

        "victim_signal": victim_signal,

        "affected_output": affected_output,

        "trace": trace
    }


# =========================================================
# ANALYZE CIRCUIT
# =========================================================

def analyze_circuit(gates):
    """
    Find rare signals, examine their structural influence,
    and perform payload/victim tracing.
    """

    probabilities = calculate_probabilities(
        gates
    )

    creators, downstream = build_circuit_maps(
        gates
    )

    circuit_outputs = find_circuit_outputs(
        gates,
        creators
    )

    candidates = []

    # -----------------------------------------------------
    # Examine every signal
    # -----------------------------------------------------

    for signal, probability in probabilities.items():

        # Rare 1 or rare 0
        rarity = (
            probability <= RARE_THRESHOLD
            or
            probability >= (
                1.0 - RARE_THRESHOLD
            )
        )

        if not rarity:
            continue

        score = 0
        evidence = []

        # -------------------------------------------------
        # Evidence 1: rarity
        # -------------------------------------------------

        score += 40

        evidence.append(
            "Rare signal probability"
        )

        # -------------------------------------------------
        # Evidence 2: creator gate
        # -------------------------------------------------

        creator = creators.get(
            signal
        )

        if creator:

            fanin = len(
                creator["inputs"]
            )

            if fanin >= 4:

                score += 20

                evidence.append(
                    f"High fan-in ({fanin})"
                )

            else:

                score += 10

                evidence.append(
                    f"Gate fan-in ({fanin})"
                )

        # -------------------------------------------------
        # Evidence 3: downstream influence
        # -------------------------------------------------

        next_gates = downstream.get(
            signal,
            []
        )

        if next_gates:

            score += 15

            evidence.append(
                f"Feeds "
                f"{len(next_gates)} "
                f"downstream gate(s)"
            )

        # -------------------------------------------------
        # Evidence 4: output influence
        # -------------------------------------------------

        reaches_output = False

        output_path = find_output_path(
            signal,
            downstream,
            circuit_outputs
        )

        if output_path:

            reaches_output = True

            score += 25

            evidence.append(
                "Can influence circuit output"
            )

        # -------------------------------------------------
        # Evidence 5: payload relationship
        # -------------------------------------------------

        payload_trace = trace_payload_victim(
            gates,
            signal
        )

        if payload_trace["found"]:

            score += 20

            evidence.append(
                "Directly connected to "
                "potential payload logic"
            )

            if payload_trace[
                "victim_signal"
            ]:

                evidence.append(
                    "Potential victim signal: "
                    +
                    payload_trace[
                        "victim_signal"
                    ]
                )

        # -------------------------------------------------
        # Store candidate
        # -------------------------------------------------

        candidates.append(
            {
                "signal": signal,

                "probability": probability,

                "score": score,

                "creator": creator,

                "downstream": next_gates,

                "reaches_output":
                    reaches_output,

                "output_path":
                    output_path,

                "evidence":
                    evidence,

                "payload_victim_trace":
                    payload_trace
            }
        )

    # -----------------------------------------------------
    # Highest score first
    # -----------------------------------------------------

    candidates.sort(
        key=lambda x: x["score"],
        reverse=True
    )

    return candidates


# =========================================================
# PRINT REPORT
# =========================================================

def print_report(candidates):

    print("\n")

    print(
        "=" * 70
    )

    print(
        "              PS13 TROJAN ANALYSIS"
    )

    print(
        "=" * 70
    )

    if not candidates:

        print(
            "\nNo rare suspicious signals found."
        )

        print(
            "\nClassification: LOW SUSPICION"
        )

        return

    for number, candidate in enumerate(
        candidates,
        start=1
    ):

        signal = candidate[
            "signal"
        ]

        probability = candidate[
            "probability"
        ]

        score = candidate[
            "score"
        ]

        creator = candidate[
            "creator"
        ]

        print(
            "\n" + "-" * 70
        )

        print(
            f"Candidate #{number}: {signal}"
        )

        print(
            f"Probability P(1): "
            f"{probability:.6f}"
        )

        if creator:

            print(
                f"Creator gate: "
                f"{creator['name']}"
            )

            print(
                f"Gate type: "
                f"{creator['type']}"
            )

            print(
                f"Fan-in: "
                f"{len(creator['inputs'])}"
            )

        print(
            f"Downstream gates: "
            f"{len(candidate['downstream'])}"
        )

        print(
            f"Reaches output: "
            f"{candidate['reaches_output']}"
        )

        # -------------------------------------------------
        # Output path
        # -------------------------------------------------

        if candidate["output_path"]:

            print(
                "\nOutput path:"
            )

            print(
                "  "
                +
                " -> ".join(
                    candidate[
                        "output_path"
                    ]
                )
            )

        # -------------------------------------------------
        # Evidence
        # -------------------------------------------------

        print(
            "\nEvidence:"
        )

        for item in candidate[
            "evidence"
        ]:

            print(
                f"  [+] {item}"
            )

        # -------------------------------------------------
        # Payload / victim
        # -------------------------------------------------

        trace = candidate[
            "payload_victim_trace"
        ]

        if trace["found"]:

            print(
                "\nPayload / Victim Tracing:"
            )

            print(
                f"  Trigger        : "
                f"{trace['trigger']}"
            )

            print(
                f"  Trigger gate   : "
                f"{trace['trigger_gate']}"
            )

            print(
                f"  Payload gate   : "
                f"{trace['payload_gate']}"
            )

            print(
                f"  Payload type   : "
                f"{trace['payload_gate_type']}"
            )

            print(
                f"  Payload signal : "
                f"{trace['payload_signal']}"
            )

            print(
                f"  Victim signal  : "
                f"{trace['victim_signal']}"
            )

            print(
                f"  Affected output: "
                f"{trace['affected_output']}"
            )

            print(
                "  Trace          : "
                +
                " -> ".join(
                    trace["trace"]
                )
            )

        # -------------------------------------------------
        # Score
        # -------------------------------------------------

        print(
            f"\nSUSPICION SCORE: "
            f"{score}/100"
        )

        if score >= 70:

            print(
                "CLASSIFICATION: "
                "HIGHLY SUSPICIOUS"
            )

        elif score >= 50:

            print(
                "CLASSIFICATION: "
                "SUSPICIOUS"
            )

        else:

            print(
                "CLASSIFICATION: "
                "LOW SUSPICION"
            )

    print(
        "\n" + "=" * 70
    )


# =========================================================
# MAIN
# =========================================================

def main():

    if len(sys.argv) != 2:

        print(
            "Usage:"
        )

        print(
            "python src/detector.py "
            "examples/trojan.v"
        )

        sys.exit(1)

    filename = sys.argv[1]

    print(
        f"\nAnalyzing: {filename}"
    )

    try:

        gates = parse_netlist(
            filename
        )

    except Exception as error:

        print(
            f"ERROR parsing netlist: "
            f"{error}"
        )

        sys.exit(1)

    if not gates:

        print(
            "ERROR: No gates found."
        )

        sys.exit(1)

    print(
        f"Parsed {len(gates)} gates."
    )

    candidates = analyze_circuit(
        gates
    )

    print_report(
        candidates
    )


# =========================================================
# ENTRY POINT
# =========================================================

if __name__ == "__main__":

    main()