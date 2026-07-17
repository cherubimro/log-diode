# Trusted-boundary assurance argument

This is the assurance case for **log-diode**, the Ada/SPARK reimplementation of the encrypted syslog
diode amplifier of Anton et al. (*Sensors* 2024, 24, 6537): what is formally proven, what is trusted,
where the line is drawn and why.

## 1. Claim

> On the path that carries a syslog message from the low-security network to the high-security
> aggregator, the parsing and reconstruction code **cannot commit a language-defined run-time error**
> (no overflow, no out-of-bounds access, no division by zero, no range violation), every loop
> **terminates**, and every functional contract holds — machine-checked, no assumptions injected.
>
> A forged, tampered, or replayed message is **never re-emitted**: the Poly1305 tag is checked by the
> proven core, so anything that fails authentication is dropped, not forwarded.

It is a **safety + integrity** claim plus **confidentiality** from the AEAD — not a proof of the
cryptographic primitives (SPARKNaCl's), nor an availability guarantee (a diode's honest failure mode is
loss).

### 1.1 Why AoRTE matters *here* specifically

On the paper's topology, logs flow **low → high**: the amplifier ingests syslog from the *less-trusted*
datacenter network, and the aggregator sits on the high-security side. So the bytes parsed by the
receiver are **attacker-influenced** — a compromised low-side device can inject any datagram, and log
injection is a real technique for hiding tracks or framing a peer. A parser that could fault, or read
out of bounds, on a hostile log line is a foothold. The proof removes that entire class.

## 2. The boundary

| Layer | Files | `SPARK_Mode` | Status |
|---|---|---|---|
| **Proven here** | `src/core/syslog`, `src/core/log_batch`, `src/core/secure`, `src/core/wire_types` | `On` | proved by `gnatprove` — 86 checks, 0 unproved, 0 justified |
| **Vendored, proven upstream** | `src/core/{gf256,rs_matrix,rs,diode_wire,relay}` (Reed-Solomon + interleaving relay, from opc-diode); `deps/sparknacl` (ChaCha20-Poly1305) | `On` | proved in their own homes; relied upon |
| **Trusted I/O shell** | `src/ld_amp`, `src/ld_deamp`, `src/ld_key` | `Off` | reviewed + loopback-tested |

## 3. What the proof establishes

`gnatprove` (level 2, `--steps=25000`) over the units added here discharges **86 verification
conditions, 0 unproved, 0 justified** (47 run-time checks, 16 assertions + functional contracts, 4
loop-termination, 19 initialization). Reproduce with `./tools/prove.sh`.

Three obligations carry the security weight:

- **`Syslog.Parse` never faults on hostile input.** Any datagram, however malformed, yields a verdict
  with no run-time error. The digit loop is capped at three and a loop invariant couples the
  accumulator's magnitude to the digit count, so the PRI value cannot overflow and the body index
  cannot run past the datagram.
- **`Log_Batch.Next` never reads past the buffer.** A length prefix that claims more than remains ends
  the walk with `More => False`; it never becomes an index. This is the same bounded-cursor discipline
  as the sibling projects' framing.
- **`Secure` is AoRTE and meets SPARKNaCl's preconditions**, so ChaCha20-Poly1305's strength is
  inherited, not re-established.

### 3.1 What the proof does not establish

Not recovery ("the RS decoder rebuilds the message when K fragments arrive") — that is functional,
validated by `test_core` and contained by the authentication gate, not proved. Not the crypto
primitives (SPARKNaCl's). Not the trusted shell.

## 4. Assumptions (the proof's TCB)

1. **Toolchain soundness** — GNAT 14.2.0 and `gnatprove` (CVC5/Z3) are sound.
2. **No injected assumptions** — no `pragma Assume`, no justification; the "Justified" column is empty.
3. **The vendored proofs** — the Reed-Solomon relay (opc-diode) and SPARKNaCl are used through their
   contracts, proved in their own projects; `--no-subprojects` keeps their bodies out of scope here.
4. **Analyzed instance** — the concrete capacities (RS `Max_K = 72`, `Max_Record = 65535`, batch ≤
   `Secure.Max_Plain = 65536`, anti-replay window 1024). Over-capacity input is dropped, never overflows.

## 5. The trusted shell

`ld_amp` and `ld_deamp` open sockets, run the batch flush timer, and call the proven core. They are
justified because they cannot cause the failures we care about — the core, not the shell, decides that
a message is authentic (the Poly1305 tag) and parses it safely; the worst a buggy shell can do is lose
data (which the diode's failure model already admits). They are small and exercised end-to-end by
`tools/loopback-test.sh` (cleartext, encrypted, batched, the severity gate, and a wrong key that drops
everything).

## 6. The integrity gate, and what changed from the paper

**Encrypt-then-encode.** A message is AEAD-sealed *before* Reed-Solomon coding, so the erasure code
protects ciphertext. A mis-decode (loss) and a forgery (an attacker on the fibre) are the same event to
the receiver: a Poly1305 tag that fails → dropped, never re-emitted.

This is the paper's design with its stated weak points closed: **ChaCha20-Poly1305 replaces Speck-R**
(a real authenticator instead of CTR + an ASCII-printable heuristic), **interleaved repetition + RS
replaces plain repeat-factor** (burst resilience), and **`--batch N`** turns the K = 1 repetition of a
single line into a genuine RS block over many lines. All of it is AoRTE-proved; none of it needs the
sender and receiver to keep a cipher counter bit-synchronized, which the paper required.

## 7. Residual risks

- **Loss beyond the code's capacity** is unrecoverable on a one-way link — inherent, not a defect.
  Raise `--parity`, `--interleave`, or the amplification.
- **Batching couples records**: if an RS block fails to decode, the whole batch is lost. `--batch 1`
  (the default) removes the coupling.
- **Nonce uniqueness** rests on the per-run random salt plus a monotone counter; a salt collision
  across runs would weaken AEAD.
- **The link is assumed physically one-way.**

## 8. Reproducing the evidence

```sh
./tools/build.sh
./tools/prove.sh          # 86 checks, 0 unproved, 0 justified
./bin/test_core           # functional sanity, incl. hostile-input and batch round-trips
./tools/loopback-test.sh  # syslog in -> amp -> diode -> deamp -> syslog out
```
