--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Rs -- a systematic Reed-Solomon ERASURE code over GF(2^8).
--
--  Purpose on a diode: protect a message that spans a small number of packets.
--  Split it into K data fragments, add M parity fragments, and send all K + M.
--  ANY K of the K + M that arrive reconstruct the message exactly -- this is
--  the MDS (maximum-distance-separable) property, and it comes for free from
--  the Cauchy generator matrix (Rs_Matrix), every square submatrix of which is
--  invertible.  There are no unlucky loss patterns: only the COUNT matters.
--
--  Why RS here rather than the LT fountain of gnat-lt-pro: at small K (a
--  handful of packets) RS is optimal -- exactly K survivors suffice -- whereas
--  the soliton distribution behaves poorly and wastes overhead.  LT wins only
--  at large K (bulk transfers).  This code owns the small-message regime.
--
--  The code is "systematic": data fragments are sent verbatim (slots 1 .. K),
--  parity follows (slots K+1 .. K+M).  So in the common no-loss case the
--  receiver does no arithmetic at all -- the data fragments ARE the message.

with Gf256; use Gf256;
with Rs_Matrix;

package Rs with SPARK_Mode => On is

   --  The Cauchy matrix (Rs_Matrix) is the single source of truth for the code
   --  dimensions, so the index bounds the prover sees on Cauchy accesses are
   --  the SAME constants as K_Range / M_Range below -- no cross-unit "48 = 48"
   --  obligation to discharge.
   Max_K   : constant := Rs_Matrix.Max_K;   --  data fragments (72; covers 64KB UADP)
   Max_M   : constant := Rs_Matrix.Max_M;   --  parity fragments (48)
   Max_N   : constant := Max_K + Max_M;
   Max_Len : constant := 1400;    --  bytes per fragment (fits one UADP datagram)

   subtype Frag_Len   is Natural  range 0 .. Max_Len;
   subtype K_Range    is Positive range 1 .. Max_K;
   subtype M_Range    is Positive range 1 .. Max_M;
   subtype Slot_Range is Positive range 1 .. Max_N;

   type Fragment     is array (1 .. Max_Len) of Byte;
   type Frag_Array   is array (Slot_Range) of Fragment;
   type Present_Array is array (Slot_Range) of Boolean;

   --  Encode: given K data fragments (slots 1 .. K of Frags, each Len bytes),
   --  fill in the M parity fragments (slots K+1 .. K+M).  Data slots are left
   --  untouched, so the result is systematic.
   --  K and M are the bounded index subtypes, so K + M <= Max_N is structural
   --  (no overflow to prove, and the slot indices K+1 .. K+M are in range by
   --  construction rather than by an arithmetic argument the prover must find).
   procedure Encode
     (K   : K_Range;
      M   : M_Range;
      Len : Frag_Len;
      Frags : in out Frag_Array);

   --  Decode: Present (s) says whether fragment s arrived.  On success every
   --  data slot 1 .. K of Frags holds the original bytes (missing ones are
   --  reconstructed; ones that arrived are unchanged).  Ok is False iff fewer
   --  than K fragments arrived -- the only genuine failure, since any K suffice.
   procedure Decode
     (K       : K_Range;
      M       : M_Range;
      Len     : Frag_Len;
      Present : Present_Array;
      Frags   : in out Frag_Array;
      Ok      : out Boolean);

end Rs;
