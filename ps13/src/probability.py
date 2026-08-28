import sys

from parser import parse_netlist


# ---------------------------------------------------------
# Calculate output probability for different logic gates
# ---------------------------------------------------------

def calculate_gate_probability(gate_type, inputs):

    if gate_type == "and":
        probability = 1.0

        for p in inputs:
            probability *= p

        return probability

    elif gate_type == "or":
        probability = 1.0

        for p in inputs:
            probability *= (1.0 - p)

        return 1.0 - probability

    elif gate_type == "not":
        return 1.0 - inputs[0]

    elif gate_type == "nand":
        probability = 1.0

        for p in inputs:
            probability *= p

        return 1.0 - probability

    elif gate_type == "nor":
        probability = 1.0

        for p in inputs:
            probability *= (1.0 - p)

        return probability

    elif gate_type == "xor":

        if len(inputs) != 2:
            raise ValueError("XOR currently supports 2 inputs.")

        p_a = inputs[0]
        p_b = inputs[1]

        return (
            p_a * (1.0 - p_b)
            +
            (1.0 - p_a) * p_b
        )

    elif gate_type == "xnor":

        if len(inputs) != 2:
            raise ValueError("XNOR currently supports 2 inputs.")

        p_a = inputs[0]
        p_b = inputs[1]

        return (
            p_a * p_b
            +
            (1.0 - p_a) * (1.0 - p_b)
        )

    else:
        raise ValueError(
            f"Unsupported gate type: {gate_type}"
        )


# ---------------------------------------------------------
# Calculate probability of every signal
# ---------------------------------------------------------

def calculate_probabilities(gates):

    # Primary inputs start with probability 0.5
    probabilities = {}

    # Process gates in the order they appear in the netlist
    for gate in gates:

        gate_name = gate["name"]
        gate_type = gate["type"]
        input_names = gate["inputs"]
        output_name = gate["output"]

        input_probabilities = []

        for signal in input_names:

            # If signal is already calculated
            if signal in probabilities:

                input_probabilities.append(
                    probabilities[signal]
                )

            else:
                # Assume unknown primary input = 0.5
                probabilities[signal] = 0.5

                input_probabilities.append(0.5)

        # Calculate gate output probability
        output_probability = calculate_gate_probability(
            gate_type,
            input_probabilities
        )

        probabilities[output_name] = output_probability

    return probabilities


# ---------------------------------------------------------
# Find rare signals
# ---------------------------------------------------------

def find_rare_signals(probabilities, threshold=0.05):

    rare_signals = []

    for signal, probability in probabilities.items():

        if probability <= threshold or probability >= (1.0 - threshold):

            rare_signals.append(
                (signal, probability)
            )

    return rare_signals


# ---------------------------------------------------------
# Print analysis
# ---------------------------------------------------------

def print_analysis(probabilities):

    print("\n" + "=" * 60)
    print("          PS13 SIGNAL PROBABILITY ANALYSIS")
    print("=" * 60)

    print("\nSignal probabilities:")
    print("-" * 40)

    print(
        f"{'Signal':<15}"
        f"{'P(1)':<12}"
        f"{'P(0)':<12}"
    )

    print("-" * 40)

    for signal, probability in probabilities.items():

        probability_zero = 1.0 - probability

        print(
            f"{signal:<15}"
            f"{probability:<12.4f}"
            f"{probability_zero:<12.4f}"
        )

    # Rare signal analysis
    rare_signals = find_rare_signals(
        probabilities,
        threshold=0.05
    )

    print("\n" + "-" * 40)
    print("RARE SIGNAL CANDIDATES")
    print("-" * 40)

    if rare_signals:

        for signal, probability in rare_signals:

            if probability <= 0.05:
                print(
                    f"{signal:<15} "
                    f"P(1) = {probability:.4f} "
                    f"--> RARE 1"
                )

            else:
                print(
                    f"{signal:<15} "
                    f"P(1) = {probability:.4f} "
                    f"--> RARE 0"
                )

    else:

        print("No rare signals detected.")

    print("\n" + "=" * 60)
    print("             ANALYSIS COMPLETE")
    print("=" * 60)


# ---------------------------------------------------------
# Main program
# ---------------------------------------------------------

def main():

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
            "\npython src/probability.py examples/clean.v"
        )

        sys.exit(1)

    filename = sys.argv[1]

    print(
        f"\nReading netlist: {filename}"
    )

    # Parse Verilog
    gates = parse_netlist(filename)

    if not gates:

        print(
            "\nERROR: No gates found."
        )

        sys.exit(1)

    print(
        f"Found {len(gates)} gates."
    )

    # Calculate probabilities
    probabilities = calculate_probabilities(
        gates
    )

    # Display results
    print_analysis(
        probabilities
    )


if __name__ == "__main__":
    main()