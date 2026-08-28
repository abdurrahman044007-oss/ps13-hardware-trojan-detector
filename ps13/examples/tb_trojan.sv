`timescale 1ns / 1ps

module tb_trojan;

    reg a, b, c, d, e, f, g, h;
    wire y;

    // Instantiate Trojan DUT
    trojan uut (
        .a(a), .b(b), .c(c), .d(d),
        .e(e), .f(f), .g(g), .h(h),
        .y(y)
    );

    initial begin
        // VCD Waveform Dump for GTKWave
        $dumpfile("trojan_sim.vcd");
        $dumpvars(0, tb_trojan);

        // 1. Normal Test Case (Trigger = 0)
        a=1; b=1; c=0; d=0; e=0; f=0; g=0; h=0;
        #10;

        // 2. Another Normal Case (Trigger = 0)
        a=0; b=1; c=1; d=1; e=0; f=0; g=0; h=0;
        #10;

        // 3. Rare Trigger Case (All Inputs 1 -> Trigger = 1 -> Payload Inverts y)
        a=1; b=1; c=1; d=1; e=1; f=1; g=1; h=1;
        #10;

        $finish;
    end

endmodule