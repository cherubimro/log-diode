# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this is

An Ada/SPARK, AoRTE-proved encrypted syslog **data-diode amplifier**: syslog/UDP arrives on the
low-security side, is severity-gated / batched / AEAD-sealed / Reed-Solomon-coded, crosses a
physically one-way link (no ACK, no retransmission, no feedback), and is verified, de-duplicated and
re-emitted as syslog/UDP on the high-security side. It reimplements Anton et al., *Sensors* 2024,
24(20), 6537, with the paper's weak points closed (ChaCha20-Poly1305 instead of unauthenticated
Speck-R; interleaved repetition + RS instead of a plain repeat factor; `--batch N`).

There is **no C anywhere in the tree** — SPARKNaCl, the crypto dependency, is itself pure Ada/SPARK.
Do not introduce C, bindings to C libraries, or heap allocation on the data path.

## Build, test, prove

The toolchain (GNAT 14.2.0 + gprbuild + gnatprove) is *not* on the default `PATH`; every script in
`tools/` sources `tools/env.sh`, which hard-codes discovered install roots. **If a build fails with
"no gnat/gprbuild/gnatprove", fix `tools/env.sh` first** — the paths recorded there
(`/home/bu/Downloads/gnat-x86_64-linux-14.2.0-1`, `/home/bu/Downloads/opt/{gprbuild,gnatprove}`) may
not exist on the current host.

```sh
./tools/build.sh          # builds SPARKNaCl once, then -> bin/{test_core, ld_amp, ld_deamp}
./tools/prove.sh          # gnatprove over this project's units: expect 86 checks, 0 unproved
./bin/test_core           # functional sanity of the proven core
./tools/loopback-test.sh  # end-to-end: syslog -> ld_amp -> UDP -> ld_deamp -> syslog
./tools/check.sh          # all of the above, gated: fails if any check is unproved
```

`prove.sh` does `rm -rf obj` first, which also wipes the SPARKNaCl objects — **after proving, re-run
`./tools/build.sh` before running any binary.** (`check.sh` already does this at the end.)

There is no unit-test framework: `bin/test_core` is a single procedure of `Check (label, condition)`
assertions that prints `>>> CORE SANITY PASSED`. To run "a single test", add or narrow a section in
`tests/test_core.adb` and rebuild. `loopback-test.sh` needs `python3` (it fakes the syslog senders and
the collector) and skips silently without it.

## Architecture: the proven core vs. the trusted shell

The whole design is organized around one boundary, documented in `docs/ASSURANCE.md`. Respect it —
it *is* the contribution of the project.

| Layer | Files | `SPARK_Mode` |
|---|---|---|
| Proven here | `src/core/{syslog,log_batch,secure,wire_types}` | `On` |
| Vendored, proven upstream | `src/core/{gf256,rs_matrix,rs,diode_wire,relay}` (from `../opc-diode`), `deps/sparknacl` | `On` |
| Trusted I/O shell | `src/{ld_amp,ld_deamp,ld_key}`, `tests/test_core` | `Off` |

The core **never names a socket**. It is handed buffers and hands back verdicts. All UDP, timers,
CLI parsing and key marshalling live in the shell, which is justified only because it cannot cause
the failures the claim covers — the core, not the shell, decides that a message is authentic.

### Data path

Sender (`ld_amp`): datagram → `Syslog.Parse` (PRI, severity gate) → `Log_Batch.Append` (length-prefixed
records into one buffer) → `Secure.Seal` (ChaCha20-Poly1305; nonce = per-run random salt ‖ monotone
`Msg_Ctr`) → `Relay.Protect` (split into K data + M parity fragments, frame each with `Diode_Wire`) →
interleaved flush across up to `--interleave D` messages, column-major.

Receiver (`ld_deamp`): datagram → `Relay.Offer` (regroup by (stream, seq), RS-decode at K, dedup,
anti-replay window) → `Secure.Open` (bad tag ⇒ dropped, never forwarded) → `Log_Batch.Next` walk →
one UDP datagram per recovered record, byte-identical.

**Encrypt-then-encode is deliberate**: AEAD is applied *before* RS coding, so a mis-decode (loss) and
a forgery are the same event to the receiver — a failed Poly1305 tag.

### Proof scope

`tools/prove.sh` proves exactly three bodies: `syslog.adb`, `log_batch.adb`, `secure.adb`. Anything
else is out of scope by design — `--no-subprojects` keeps SPARKNaCl's bodies out, and the RS/relay
units are relied on through their contracts, proved in `../opc-diode`. `tests/test_core.adb` is also
the **proof anchor**: it `with`s every core unit so gnatprove's mains-closure analysis reaches them.
Don't remove `with` clauses from it just because a test section stopped using one.

Proof settings live in `log_diode.gpr`'s `package Prove` (`--level=2 --steps=25000`); the raised step
count is needed because the K = 72 RS instance makes index/overflow VCs large.

The proof carries **no `pragma Assume` and no justifications** — the "Justified" column must stay
empty. If a new check will not discharge, restructure the code (tighter subtypes, a loop invariant
coupling the accumulator to the iteration count) rather than assuming it away.

## Conventions that carry proof weight

- **Bounded-cursor discipline.** A length read from a buffer is validated against what remains
  *before* it is ever used as an index (`Log_Batch.Next`, `Diode_Wire.Parse`). A lying length ends
  the walk; it never becomes an index.
- **Constrained record fields.** `Relay.Assembly` stores `K : Natural range 0 .. Rs.Max_K` etc. so
  bounds survive storage and the prover needs no re-validation on read-back.
- **Bounds as subtypes, not as arithmetic.** `Rs.Encode` takes `K_Range`/`M_Range` so `K + M <= Max_N`
  is structural.
- **Fixed capacity, no allocation** in the core. Capacities are the analyzed instance
  (`Rs.Max_K = 72`, `Syslog.Max_Record = 65535`, `Secure.Max_Plain = 65536`, `Relay.Replay_Win = 1024`);
  changing one changes what was proved and requires re-proving.
- **Loop bounds are proof-relevant.** The PRI digit loop is capped at 3 with an invariant bounding
  `Prival` by digit count — that is what makes the `* 10` and `* 8` non-overflowing.
- Every file starts with the SPDX header; every core spec carries a "WHY THIS IS PROVEN" comment
  explaining which obligation it discharges and why that matters for a diode. Keep both when adding
  units.
- Compiler switches are `-gnat2022 -gnatwa` (all warnings). Keep new code warning-clean.

## Running it

```sh
# HIGH side (aggregator)
./bin/ld_deamp <diode_port> <out_ip> [<out_port=514>] [--key HEX64]

# LOW side (amplifier)
./bin/ld_amp <listen_port> <diode_ip> <diode_port> [--key HEX64] [--batch N] [--parity M] \
             [--interleave D] [--min-severity 0..7] [--pace-us N] [--flush-ms T]
```

The 64-hex-char key is pre-shared out of band and must match on both ends; without `--key` logs cross
in the clear. `--batch 1` (default) is one record per message, i.e. RS at K = 1 = repetition; larger
`N` buys real coding gain at the cost of coupling records. A record whose PRI does not parse is
forwarded, not dropped — unparseable logs may be the interesting ones.

## Changing behaviour

- Touching `src/core/{syslog,log_batch,secure}` requires `./tools/prove.sh` to still report 0
  unproved, 0 justified. Run `./tools/check.sh` before claiming anything works.
- The vendored RS/relay units are upstream code from `../opc-diode`; prefer fixing them there and
  re-vendoring over local divergence. Their comments still refer to OPC UA NetworkMessages — that is
  expected, the payload here is a syslog batch.
- `deps/sparknacl/` is vendored third-party BSD code. Do not modify it.
- `docs/ASSURANCE.md` is the assurance case, including the check count and the residual-risk list. If
  a change alters what is proven, what is trusted, or the capacities, update it in the same commit.

## Licence

AGPL-3.0-or-later, © 2026 Alin-Adrian Anton. SPARKNaCl under `deps/` is BSD (© Protean Code Limited).
