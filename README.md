# log-diode

*Made 🄯 libre (free as in freedom) with ❤️ at Politehnica University of Timișoara — quite possibly the first formally-verified (machine-checked proof of no run-time errors) **encrypted syslog data-diode amplifier** for one-way log shipping across an air gap. Built specifically for industrial control and SCADA — power grids, water treatment plants, oil & gas pipelines, railways, and telecommunications networks — where the SOC must see the plant's logs without the corporate side being able to reach, or write to, the plant.*

*Because we care — and because critical-infrastructure protection should not depend on proprietary / closed-source systems, and should be made FREE.*

**A high-assurance Ada/SPARK reimplementation of** Anton, Csereoka, Capota & Cioargă,
*"Enhancing Syslog Message Security and Reliability over Unidirectional Fiber Optics"*, **Sensors 2024,
24(20), 6537** ([doi:10.3390/s24206537](https://doi.org/10.3390/s24206537)) — the encrypted syslog
redirector/amplifier of that paper, with the reconstruction and parsing path *proved* free of run-time
errors and every one of the paper's own noted limitations closed.

syslog/UDP is received on the low-security side, crosses a data diode (a media converter with the TX
fibre only — **no ACK, no retransmission, no feedback**), and is re-emitted as syslog/UDP to a
collector (rsyslog, Logstash, Graylog, a SIEM — anything) on the high-security side. The information
flows **up** only: a classic Bell–LaPadula arrangement in which the low network can never read from, or
write to, the high one.

## What this improves over the paper (and why each is safe)

The paper is the design; this is the hardened, proven build. Four deliberate upgrades:

| Paper (Sensors 2024) | Here | Why it is strictly better |
|---|---|---|
| **Speck-R** cipher, CTR mode | **ChaCha20-Poly1305** ([SPARKNaCl](https://github.com/rod-chapman/SPARKNaCl)) | Speck-R gives confidentiality but **no authentication tag** — CTR is malleable, and "did it decrypt to printable ASCII" is a heuristic, not integrity. AEAD drops a forged *or* bit-flipped line with a real 128-bit tag. |
| Replay = a synchronized 64-bit counter | a proven **anti-replay window** + the AEAD nonce binds the counter | A replayed datagram fails the tag, not just "decrypts to garbage". |
| **Repetition ×R, back-to-back, no interleaving** | **interleaved repetition + Reed-Solomon** sized to the message | The paper's own point: plain repetition dies to a burst that takes all R copies. Interleaving spreads them in time; RS (K ≥ 2) beats copies outright for multi-datagram messages. |
| repeat every line (K = 1) | optional **`--batch N`**: pack N lines into one RS block | A single log line is RS at K = 1 = repetition (no coding gain). Batching lets a real RS block protect N lines at once — far cheaper on the wire under congestion. |
| an unverified reference implementation | **AoRTE machine-checked** (`gnatprove`) | The syslog parser chews attacker-influenced bytes (logs flow from the *less* trusted side); a hostile line can never fault the daemon. |

This is **not a port of anyone's C** — it is a from-scratch, **pure Ada/SPARK** implementation of the
paper's design whose distinguishing contribution *is* the machine-checked security proof. There is no C
anywhere in the tree (SPARKNaCl, the crypto dependency, is itself pure Ada/SPARK), so the memory-safety
attack surface of a C codec on the data path simply does not exist here.

## What is proven, and why these particular things

The units this project adds are proved AoRTE by `gnatprove`: **86 checks, 0 unproved, 0 justified**
(`./tools/prove.sh`). They never name a socket; the trusted shell hands them buffers and they hand back
verdicts.

| Unit | What it is, and the obligation it discharges |
|---|---|
| `syslog` | The RFC 5424 / 3164 **PRI parser**. **Proves any 0..65535-byte datagram yields a verdict without a run-time error** — a missing `<`, a non-digit, a runaway number all give `Valid => False`, never an out-of-bounds read. This matters because logs arrive from the less-trusted low side, and log injection is a real technique. It extracts facility/severity for the optional severity gate (forward only `crit` and above, say) — a feature the paper lacks. |
| `log_batch` | The **batch framing**: pack N length-prefixed records into one sealed message, and walk them back out. **Proves a lying length ends the walk, never reads past the buffer** — the bounded-cursor discipline. |
| `secure` | The ChaCha20-Poly1305 wrapper over SPARKNaCl — proved AoRTE and proved to satisfy SPARKNaCl's preconditions. |

**Vendored, proven upstream — relied on, not re-proved here.** The Reed-Solomon codec + interleaving
relay (`gf256`, `rs`, `rs_matrix`, `diode_wire`, `relay`) come from the sibling
[opc-diode](../opc) (part of its 387 checks); ChaCha20-Poly1305 is
[SPARKNaCl](https://github.com/rod-chapman/SPARKNaCl)'s own published proof. All are exercised
end-to-end for *function* by `bin/test_core`. Trusted, and unprovable by nature (SPARK_Mode Off): the
UDP sockets and the batch flush timer (`src/ld_amp`, `src/ld_deamp`, `src/ld_key`).

## Build, test, prove

Toolchain: **GNAT 14.2.0 + gprbuild + gnatprove** (SPARK). `tools/env.sh` puts them on `PATH`.

```sh
./tools/build.sh          # -> bin/{test_core, ld_amp, ld_deamp}
./tools/prove.sh          # gnatprove over this project's units: 86 checks, 0 unproved
./tools/check.sh          # build + proof + core sanity + syslog loopback
./tools/loopback-test.sh  # syslog in -> amp -> diode -> deamp -> syslog out
```

## Running it

```sh
# HIGH-security side (aggregator): recover, verify, re-emit to a local rsyslog on :514
./bin/ld_deamp 6514 127.0.0.1 514 --key <64 hex>

# LOW-security side (amplifier): take syslog/UDP on :1514, ship it across the diode
./bin/ld_amp 1514 <diode_ip> 6514 --key <64 hex> [--batch N] [--parity M] \
             [--interleave D] [--min-severity 0..7] [--flush-ms T]
```

Point your senders at the amplifier (in `/etc/rsyslog.conf`: `*.* @amplifier-host:1514`), and on the
high side run a local rsyslog UDP listener on `:514`. The `--key` (64 hex chars, ChaCha20-Poly1305) is
pre-shared out of band and must match; without it logs cross in the clear. `--min-severity 4` forwards
only warnings and worse; `--batch 8` packs eight lines per RS block; `--interleave 16` spreads a
burst across sixteen messages. All one-way: the deamplifier never transmits.

## Licence

**AGPL-3.0-or-later.** Copyright © 2026 Alin-Adrian Anton. SPARKNaCl is BSD (© Protean Code Limited),
vendored under `deps/`; the Reed-Solomon core is reused from the AGPL sibling projects.
