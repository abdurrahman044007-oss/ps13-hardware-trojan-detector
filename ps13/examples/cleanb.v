module security_clean (
    input  [3:0] A,
    input  [3:0] B,
    input        enable,
    output       access_granted,
    output       alarm
);

wire match;

assign match = (A == B);

assign access_granted = enable & match;

assign alarm = enable & ~match;

endmodule 