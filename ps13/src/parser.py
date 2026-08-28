import re


# =========================================================
# PS13 VERILOG NETLIST PARSER
# =========================================================
#
# Supports:
#
#   and g1 (out, a, b);
#
#   and g1 (
#       out,
#       a,
#       b
#   );
#
#   and
#   g1
#   (
#       out,
#       a,
#       b
#   );
#
# Also supports:
#   // comments
#   /* multi-line comments */
#   extra whitespace
#   multiple gates
#
# =========================================================


SUPPORTED_GATES = {
    "and",
    "or",
    "not",
    "nand",
    "nor",
    "xor",
    "xnor",
    "buf"
}


# ---------------------------------------------------------
# Remove Verilog comments
# ---------------------------------------------------------

def remove_comments(text):
    """
    Remove both single-line and multi-line Verilog comments.
    """

    # Remove /* ... */ comments
    text = re.sub(
        r"/\*.*?\*/",
        "",
        text,
        flags=re.DOTALL
    )

    # Remove // comments
    text = re.sub(
        r"//.*",
        "",
        text
    )

    return text


# ---------------------------------------------------------
# Clean whitespace
# ---------------------------------------------------------

def normalize_text(text):
    """
    Convert newlines and repeated whitespace into spaces.

    This allows multi-line gate declarations to be parsed
    exactly like single-line declarations.
    """

    text = text.replace(
        "\r",
        " "
    )

    text = text.replace(
        "\n",
        " "
    )

    text = re.sub(
        r"\s+",
        " ",
        text
    )

    return text.strip()


# ---------------------------------------------------------
# Parse one gate declaration
# ---------------------------------------------------------

def parse_gate(gate_type, gate_name, connection_text):
    """
    Convert one Verilog gate declaration into the dictionary
    format used by detector.py, probability.py and timing.py.
    """

    gate_type = gate_type.lower()
    gate_name = gate_name.strip()

    # -----------------------------------------------------
    # Split ports
    # -----------------------------------------------------

    signals = [
        signal.strip()
        for signal in connection_text.split(",")
        if signal.strip()
    ]

    if len(signals) < 2:

        raise ValueError(
            f"Gate {gate_name} has insufficient connections: "
            f"{signals}"
        )

    # First connection = output
    output = signals[0]

    # Remaining connections = inputs
    inputs = signals[1:]

    return {
        "name": gate_name,
        "type": gate_type,
        "inputs": inputs,
        "output": output
    }


# ---------------------------------------------------------
# Parse complete Verilog netlist
# ---------------------------------------------------------

def parse_netlist(filename):
    """
    Parse a Verilog netlist containing single-line or
    multi-line primitive gate declarations.
    """

    with open(
        filename,
        "r",
        encoding="utf-8"
    ) as file:

        text = file.read()

    # -----------------------------------------------------
    # Remove comments
    # -----------------------------------------------------

    text = remove_comments(text)

    # -----------------------------------------------------
    # Normalize whitespace
    # -----------------------------------------------------

    text = normalize_text(text)

    gates = []

    # -----------------------------------------------------
    # Gate declaration pattern
    # -----------------------------------------------------
    #
    # Matches:
    #
    # and g1 (n1, a, b);
    #
    # and g1(n1,a,b);
    #
    # and
    # g1
    # (
    #   n1,
    #   a,
    #   b
    # );
    #
    # Since whitespace has already been normalized,
    # all of these become equivalent.
    # -----------------------------------------------------

    pattern = re.compile(
        r"\b"
        r"(and|or|not|nand|nor|xor|xnor|buf)"
        r"\s+"
        r"([A-Za-z_][A-Za-z0-9_$]*)"
        r"\s*"
        r"\("
        r"(.*?)"
        r"\)"
        r"\s*;",
        re.IGNORECASE
    )

    matches = pattern.finditer(text)

    for match in matches:

        gate_type = match.group(1)
        gate_name = match.group(2)
        connections = match.group(3)

        gate_type = gate_type.lower()

        if gate_type not in SUPPORTED_GATES:

            continue

        gate = parse_gate(
            gate_type,
            gate_name,
            connections
        )

        gates.append(gate)

    return gates


# ---------------------------------------------------------
# Print parsed gates
# ---------------------------------------------------------

def print_gates(gates):
    """
    Display parsed gates for debugging.
    """

    print("\n" + "=" * 65)
    print("                 PARSED NETLIST")
    print("=" * 65)

    print(
        f"\nTotal gates: {len(gates)}"
    )

    for number, gate in enumerate(
        gates,
        start=1
    ):

        print(
            f"\nGate #{number}"
        )

        print(
            f"  Name   : {gate['name']}"
        )

        print(
            f"  Type   : {gate['type']}"
        )

        print(
            f"  Output : {gate['output']}"
        )

        print(
            f"  Inputs : {gate['inputs']}"
        )

    print("\n" + "=" * 65)


# ---------------------------------------------------------
# Standalone testing
# ---------------------------------------------------------

def main():

    import sys

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
        )

        print(
            "python src/parser.py examples/clean.v"
        )

        sys.exit(1)

    filename = sys.argv[1]

    print(
        f"\nReading netlist: {filename}"
    )

    try:

        gates = parse_netlist(
            filename
        )

        if not gates:

            print(
                "\nERROR: No supported gates found."
            )

            sys.exit(1)

        print_gates(
            gates
        )

    except FileNotFoundError:

        print(
            f"\nERROR: File not found: {filename}"
        )

        sys.exit(1)

    except Exception as error:

        print(
            f"\nERROR: {error}"
        )

        sys.exit(1)


if __name__ == "__main__":
    main()