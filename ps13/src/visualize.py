import sys
import os
import networkx as nx
import matplotlib.pyplot as plt

from parser import parse_netlist
from graph import build_graph


def visualize_graph(graph, output_file):
    """
    Draw the circuit graph and save it as a PNG image.
    """

    # Create layout
    position = nx.spring_layout(
        graph,
        seed=42,
        k=2
    )

    plt.figure(figsize=(12, 7))

    # Separate gates and nets
    gate_nodes = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("node_type") == "gate"
    ]

    net_nodes = [
        node
        for node, data in graph.nodes(data=True)
        if data.get("node_type") == "net"
    ]

    # Draw net nodes
    nx.draw_networkx_nodes(
        graph,
        position,
        nodelist=net_nodes,
        node_shape="o",
        node_size=1000
    )

    # Draw gate nodes
    nx.draw_networkx_nodes(
        graph,
        position,
        nodelist=gate_nodes,
        node_shape="s",
        node_size=1400
    )

    # Draw connections
    nx.draw_networkx_edges(
        graph,
        position,
        arrows=True,
        arrowsize=20,
        width=2
    )

    # Labels
    labels = {}

    for node in graph.nodes():

        if graph.nodes[node].get("node_type") == "gate":

            gate_type = graph.nodes[node].get(
                "gate_type",
                ""
            )

            labels[node] = f"{node}\n{gate_type.upper()}"

        else:
            labels[node] = node

    nx.draw_networkx_labels(
        graph,
        position,
        labels=labels,
        font_size=9
    )

    plt.title("PS13 Circuit Graph")

    plt.axis("off")

    # Create output directory if required
    os.makedirs(
        os.path.dirname(output_file),
        exist_ok=True
    )

    plt.savefig(
        output_file,
        dpi=200,
        bbox_inches="tight"
    )

    plt.close()

    print(f"\nGraph saved to:")
    print(output_file)


def main():

    if len(sys.argv) != 2:

        print(
            "\nUsage:"
            "\npython src/visualize.py examples/clean.v"
        )

        sys.exit(1)

    filename = sys.argv[1]

    print(f"\nReading netlist: {filename}")

    # Parse netlist
    gates = parse_netlist(filename)

    if not gates:

        print("ERROR: No gates found.")

        sys.exit(1)

    # Build graph
    graph = build_graph(gates)

    # Output location
    output_file = "graphs/circuit_graph.png"

    # Draw graph
    visualize_graph(
        graph,
        output_file
    )


if __name__ == "__main__":
    main()