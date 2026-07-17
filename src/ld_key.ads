--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Ld_Key -- key material handling for the trusted shell (not proven).
--
--  Parses a 32-byte symmetric key from 64 hex characters, and supplies a
--  per-run random nonce salt.  Trusted: it only marshals bytes and reads the
--  OS entropy source.

with Wire_Types; use Wire_Types;
with Secure;

package Ld_Key with SPARK_Mode => Off is

   --  Parse exactly 64 hex chars into a 32-byte key.  Ok is False on any other
   --  length or a non-hex character.
   procedure Parse_Hex (S : String; Key : out Secure.Key_Bytes; Ok : out Boolean);

   --  A per-run random 32-bit value from the OS CSPRNG (getrandom(2), or
   --  /dev/urandom, or a clock/PID mix as a last resort).  It forms the high 4
   --  bytes of every nonce, so two runs cannot collide a nonce even if started
   --  in the same clock tick.  Combined with a strictly-increasing per-run
   --  message counter (the low 8 bytes), this makes ChaCha20-Poly1305 nonce
   --  reuse under one key negligible.
   function Random_Salt return U32;

end Ld_Key;
