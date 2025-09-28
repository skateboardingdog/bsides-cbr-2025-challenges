The Winged Thong of Hermes
============

To solve this challenge we need to patch the global `flipflops` variable to
`true` in certain places in order to bypass a check. Otherwise, the `quit()`
function will be called, terminating the program early.

AFAIK there are a lot of disassemblers for Hermes bytecode but not many
assemblers. The one [assembler on
Github](https://github.com/lucasbaizer2/hasmer) doesn't seem to support the
latest bytecode versions.

We can use [`hermes_rs`](https://github.com/Pilfer/hermes_rs) to disassemble the
binary. To make things easier, we also patch the disassembler to print out the bytecode it is deserialising:
```diff
diff --git a/src/hermes/mod.rs b/src/hermes/mod.rs
index 93a1648..553db22 100644
--- a/src/hermes/mod.rs
+++ b/src/hermes/mod.rs
@@ -688,8 +688,13 @@ macro_rules! define_opcode {
 
       )*
       // format!("{} // has_ret_target {}", display_string.trim_end_matches(", ").trim().to_string(), self.has_ret_target())
-      format!("{}", display_string.trim_end_matches(", ").trim().to_string())
-
+      let mut writer = Vec::new();
+      self.serialize(&mut writer);
+      let hex_instructions = writer.iter()
+        .map(|b| format!("{:02x}", b))
+        .collect::<Vec<_>>()
+        .join(" ");
+      format!("{} // {}", display_string.trim_end_matches(", ").trim().to_string(), hex_instructions)
     }
   }
 };
```

Running the disassembler and looking for all references to the identifier
`flipflops`, we find an instructions which declares the global:

```
0x00000000      DeclareGlobalVar  "flipflops" // 34 f5 00 00 00
0x00000001      DeclareGlobalVar  "a0_0x3508d0" // 34 f0 00 00 00
0x00000002      DeclareGlobalVar  "a0_0x594467" // 34 f3 00 00 00
```

A bit further down, we find the first instance of a value being stored into `flipflop`:

```
0x00000026      NewArray  r2,  0 // 07 02 00 00
0x00000027      Not  r3,  r2 // 0b 03 02
0x00000028      GetGlobalObject  r2 // 30 02
0x00000029      PutById  r2,  r3,  3,  "flipflops" // 3b 02 03 03 f5 00
```

This code creates a new empty array, negates it, and stores the value into
`flipflops`. So the value of `flipflops` is `![]` (i.e `false`).

The `Not` instruction negates its second argument and stores the value in its
first argument. So if we can overwrite that `Not` instruction to something like
`Mov`, then the value of `flipflops` will be set to `[]` which is truthy in JS.

Running xxd and looking for the instructions, we find it at offset `0x00001423`.
The opcode for `Not` is 0x0b, and the opcode for Mov is 0x8. So changing the 0xb
byte to 0x8 and running `xxd -r`, we get a patched version of the binary which
passes that set.

The next instance where `flipflops` is modified occurs, further down, where the value is negated and then stored back into the global variable:
```
0x0000013D      GetByIdShort  r0,  r0,  1,  "flipflops" // 36 00 00 01 f5
0x0000013E      Not  r3,  r0 // 0b 03 00
0x0000013F      GetGlobalObject  r0 // 30 00
0x00000140      PutById  r0,  r3,  1,  "flipflops" // 3b 00 03 01 f5 00
```

Since we previously set `flipflops` to `true`, this negation will again store
`false` into `flipflops`. To bypass this, we can again manually patch the `Not`
instruction into a `Mov`.

Continuing the pattern, there are two further places where `flipflops` is modified. One where the value of `flipflops` is bit-negated and stored:

```
0x00000A41      GetByIdShort  r0,  r0,  1,  "flipflops" // 36 00 00 01 f5
0x00000A42      BitNot  r3,  r0 // 0c 03 00
0x00000A43      GetGlobalObject  r0 // 30 00
0x00000A44      PutById  r0,  r3,  1,  "flipflops" // 3b 00 03 01 f5 00
```

Since the `BitNot` instruction has arity 2, we can again bypass this by manually patching `BitNot` to `Mov`.

In the final location `flipflops` where `flipflops` is modified, its value is
subtracted from the result of a long series of arithmetic operations. The jump
afterwards only occurs in the value is falsy.

```
0x00000270      LoadConstInt  r3,  1799 // 6f 03 07 07 00 00
0x00000271      LoadConstUInt8  r1,  5 // 6e 01 05
0x00000272      MulN  r3,  r3,  r1 // 19 03 03 01
0x00000273      LoadConstUInt8  r4,  9 // 6e 04 09
0x00000274      LoadConstUInt8  r1,  210 // 6e 01 d2
0x00000275      MulN  r1,  r4,  r1 // 19 01 04 01
0x00000276      Add  r3,  r3,  r1 // 16 03 03 01
0x00000277      LoadConstInt  r1,  2177 // 6f 01 81 08 00 00
0x00000278      Negate  r4,  r1 // 0a 04 01
0x00000279      LoadConstUInt8  r1,  5 // 6e 01 05
0x0000027A      Mul  r1,  r4,  r1 // 18 01 04 01
0x0000027B      Add  r3,  r3,  r1 // 16 03 03 01
0x0000027C      GetGlobalObject  r1 // 30 01
0x0000027D      GetByIdShort  r1,  r1,  10,  "flipflops" // 36 01 01 0a f5
0x0000027E      Sub  r3,  r3,  r1 // 1d 03 03 01
0x0000027F      GetGlobalObject  r1 // 30 01
0x00000280      PutById  r1,  r3,  1,  "flipflops" // 3b 01 03 01 f5 00
```

We know that due to our patches, at this point our `flipflops` variable has
value `[]`. Doing some local testing in the Hermes REPL, we find that for any
integer `i`, it looks like `i-[]` is only falsy if `i == 0`, and moreover,
`i+[]`is truthy for any `i`. Hence by changing the final `Sub` instruction into
an `Add` instruction, we can make `flipflops` have a truthy value and bypass the
`JmpFalseLong` which occurs after.

Finally, running `hermes patched.hbc` reveals the flag.

```
❯ hermes patched.hbc
The winged thong of Hermes has had a plugger blowout! Can you help him manage his flipflops??
skbdg{fl33t_as_f3ath3rs_and_swift_0f_s0ng}
```

The final diff between the two files is:
```diff
❯ diff --unified main.hbc.xxd patched.hbc.xxd
--- main.hbc.xxd        2025-09-10 10:58:55.536576380 +1000
+++ patched.hbc.xxd     2025-09-10 10:56:40.359563922 +1000
@@ -386,7 +386,7 @@
 00001810: 038c 9f00 006f 0206 f909 0017 0303 026f  .....o.........o
 00001820: 0206 a001 000a 0202 1603 0302 7602 0808  ............v...
 00001830: 0208 0704 0806 034f 0205 0308 0002 0702  .......O........
-00001840: 0000 0b03 0230 023b 0203 03f5 0064 0301  .....0.;.....d..
+00001840: 0000 0803 0230 023b 0203 03f5 0064 0301  .....0.;.....d..
 00001850: 0600 7602 0808 024f 0203 012a 0100 0230  ..v....O...*...0
 00001860: 0239 0402 02f9 0073 0329 0173 0239 0116  .9.....s.).s.9..
 00001870: 0303 0273 0235 0116 0303 0273 0200 0116  ...s.5.....s....
@@ -13456,7 +13456,7 @@
 000348f0: 0016 0506 0544 0005 0308 0e04 080d 004f  .....D.........O
 00034900: 0003 022e 0002 017e 0000 2500 002a 0201  .......~..%..*..
 00034910: 002e 0302 012e 0002 0013 0003 0091 5ffd  .............._.
-00034920: ffff 0030 0036 0000 01f5 0b03 0030 003b  ...0.6.......0.;
+00034920: ffff 0030 0036 0000 01f5 0803 0030 003b  ...0.6.......0.;
 00034930: 0003 01f5 0030 0336 0303 01f5 0b03 0308  .....0.6........
 00034940: 0003 9312 0100 0003 7304 1e01 7303 4101  ........s...s.A.
 00034950: 1604 0403 7303 3c01 1604 0403 7303 1701  ....s.<.....s...
@@ -14042,7 +14042,7 @@
 00036d90: 0002 0312 0003 0092 1500 2e03 0208 2e00  ................
 00036da0: 0202 1200 0300 9113 f8ff ff00 2e03 0208  ................
 00036db0: 2e00 0202 1200 0300 9108 e5ff ff00 3000  ..............0.
-00036dc0: 3600 0001 f50c 0300 3000 3b00 0301 f500  6.......0.;.....
+00036dc0: 3600 0001 f508 0300 3000 3b00 0301 f500  6.......0.;.....
 00036dd0: 3000 3600 0001 f591 6903 0000 0073 034a  0.6.....i....s.J
 00036de0: 0173 0024 0116 0303 0073 003b 0116 0303  .s.$.....s.;....
 00036df0: 0073 002b 0116 0303 0073 003c 0116 0303  .s.+.....s.<....
@@ -14559,7 +14559,7 @@
 00038de0: 0301 91d9 fbff ff01 6f03 0707 0000 6e01  ........o.....n.
 00038df0: 0519 0303 016e 0409 6e01 d219 0104 0116  .....n..n.......
 00038e00: 0303 016f 0181 0800 000a 0401 6e01 0518  ...o........n...
-00038e10: 0104 0116 0303 0130 0136 0101 0af5 1d03  .......0.6......
+00038e10: 0104 0116 0303 0130 0136 0101 0af5 1603  .......0.6......
 00038e20: 0301 3001 3b01 0301 f500 3003 3603 030a  ..0.;.....0.6...
 00038e30: f50b 0303 0801 0392 1703 3003 3904 030b  ..........0.9...
 00038e40: fc00 7603 080c 034f 0304 0108 0103 2901  ..v....O......).
```
