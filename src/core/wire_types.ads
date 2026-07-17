--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Wire_Types -- the scalar types every on-the-wire byte agrees on.
--
--  One byte type (U8) is shared by the GF(2^8) algebra, the UADP parser, the
--  diode framing and the relay, so a datagram buffer can be viewed as field
--  elements or as protocol bytes with no conversion at the boundary.  All are
--  modular, so little-endian byte assembly (Part 6 5.2.2) never overflows and
--  carries no run-time check to fail.

package Wire_Types with SPARK_Mode => On, Pure is

   type U8  is mod 2 ** 8;
   type U16 is mod 2 ** 16;
   type U32 is mod 2 ** 32;
   type U64 is mod 2 ** 64;

end Wire_Types;
