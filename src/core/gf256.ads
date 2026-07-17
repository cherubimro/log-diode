--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Gf256 -- arithmetic in the Galois field GF(2^8).
--
--  This is the algebra the Reed-Solomon erasure code is built on.  Every value
--  is one byte, addition is exclusive-or, and multiplication is a table lookup.
--  There is no carry, no overflow, and no rounding: the field is finite and
--  exact.  That is precisely why an erasure code over GF(2^8) is a good fit for
--  a high-assurance diode -- the arithmetic cannot go wrong, and SPARK can say
--  so.
--
--  The body carries frozen log/antilog tables (primitive polynomial 0x11D),
--  generated and verified offline.  See gf256.adb.

with Wire_Types;

package Gf256 with SPARK_Mode => On, Pure is

   use type Wire_Types.U8;

   --  The field element is the shared wire byte, so RS fragments, UADP bytes
   --  and diode payloads are all the same type -- no conversion at the seams.
   subtype Byte is Wire_Types.U8;

   --  0 .. 511, not 0 .. 254: the doubled antilog table is what lets Mul index
   --  with Log (A) + Log (B) directly -- worst case 510 -- with no modulo and,
   --  more to the point, no possibility of an out-of-range index.  The proof of
   --  Mul is then immediate.
   subtype Exp_Index is Natural range 0 .. 511;

   --  Addition and subtraction coincide in a field of characteristic 2.
   function Add (A, B : Byte) return Byte is (A xor B);
   function Sub (A, B : Byte) return Byte is (A xor B);

   function Mul (A, B : Byte) return Byte;

   --  The multiplicative inverse.  Zero has none -- hence the precondition,
   --  which is discharged at every call site rather than papered over with a
   --  silent zero result.
   function Inv (A : Byte) return Byte
     with Pre => A /= 0;

   function Div (A, B : Byte) return Byte
     with Pre => B /= 0;

end Gf256;
