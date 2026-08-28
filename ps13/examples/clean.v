module clean(
    input a,
    input b,
    input c,
    output y
);

wire n1;
wire n2;

and U1(n1, a, b);
or  U2(n2, n1, c);
not U3(y, n2);

endmodule