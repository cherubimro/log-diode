--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Diode framing body.  Fixed offsets, little-endian scalars.  Serialize writes
--  known-in-range indices (the preconditions bound K, M, Frag_Idx, Frag_Len).
--  Parse validates every field before trusting it and refuses (Valid => False)
--  on anything malformed, so it is safe on hostile input.

package body Diode_Wire with SPARK_Mode => On is

   use type Wire_Types.U8, Wire_Types.U16, Wire_Types.U32, Wire_Types.U64;

   --  ---- little-endian writers into a Packet at a fixed offset ----------

   procedure Put16 (Buf : in out Packet; Off : Pkt_Index; V : U16)
     with Pre => Off <= Max_Packet - 2
   is
   begin
      Buf (Off)     := U8 (V and 16#FF#);
      Buf (Off + 1) := U8 (V / 256);
   end Put16;

   procedure Put32 (Buf : in out Packet; Off : Pkt_Index; V : U32)
     with Pre => Off <= Max_Packet - 4
   is
   begin
      Buf (Off)     := U8 (V and 16#FF#);
      Buf (Off + 1) := U8 ((V / 2 ** 8) and 16#FF#);
      Buf (Off + 2) := U8 ((V / 2 ** 16) and 16#FF#);
      Buf (Off + 3) := U8 ((V / 2 ** 24) and 16#FF#);
   end Put32;

   procedure Put64 (Buf : in out Packet; Off : Pkt_Index; V : U64)
     with Pre => Off <= Max_Packet - 8
   is
   begin
      Put32 (Buf, Off,     U32 (V and 16#FFFF_FFFF#));
      Put32 (Buf, Off + 4, U32 (V / 2 ** 32));
   end Put64;

   --  ---- little-endian readers (bounds guaranteed by callers) -----------

   function Get16 (Buf : Packet; Off : Pkt_Index) return U16 is
     (U16 (Buf (Off)) + U16 (Buf (Off + 1)) * 256)
     with Pre => Off <= Max_Packet - 2;

   function Get32 (Buf : Packet; Off : Pkt_Index) return U32 is
     (U32 (Buf (Off))
      + U32 (Buf (Off + 1)) * 2 ** 8
      + U32 (Buf (Off + 2)) * 2 ** 16
      + U32 (Buf (Off + 3)) * 2 ** 24)
     with Pre => Off <= Max_Packet - 4;

   function Get64 (Buf : Packet; Off : Pkt_Index) return U64 is
     (U64 (Get32 (Buf, Off)) + U64 (Get32 (Buf, Off + 4)) * 2 ** 32)
     with Pre => Off <= Max_Packet - 8;

   ---------------
   -- Serialize --
   ---------------

   procedure Serialize
     (Scheme    : U8;
      Stream_Id : U64;
      Msg_Seq   : U32;
      Msg_Len   : U32;
      Frag_Len  : Payload_Length;
      K, M      : Natural;
      Frag_Idx  : Natural;
      Payload   : Rs.Fragment;
      Buf       : out Packet;
      Total     : out Pkt_Length)
   is
   begin
      Buf := (others => 0);
      Buf (0) := Magic0;
      Buf (1) := Magic1;
      Buf (2) := Version;
      Buf (3) := Scheme;
      Put64 (Buf, 4, Stream_Id);
      Put32 (Buf, 12, Msg_Seq);
      Put32 (Buf, 16, Msg_Len);
      Put16 (Buf, 20, U16 (Frag_Len));
      Buf (22) := U8 (K);
      Buf (23) := U8 (M);
      Buf (24) := U8 (Frag_Idx);

      --  Payload bytes follow the header.  Frag_Len <= Max_Payload, so the
      --  last index Header_Len + Frag_Len - 1 <= Max_Packet - 1.
      for I in 1 .. Frag_Len loop
         pragma Loop_Invariant (I <= Max_Payload);
         Buf (Header_Len + I - 1) := Payload (I);
      end loop;

      Total := Header_Len + Frag_Len;
   end Serialize;

   -----------
   -- Parse --
   -----------

   procedure Parse (Buf : Packet; Len : Pkt_Length; H : out Header) is
      LK, LM, LIdx : Natural;
      LFrag        : Natural;
   begin
      H := (Valid => False, Scheme => 0, Stream_Id => 0, Msg_Seq => 0,
            Msg_Len => 0, Frag_Len => 0, K => 0, M => 0, Frag_Idx => 0);

      --  Must hold a full fixed header.
      if Len < Header_Len then
         return;
      end if;

      if Buf (0) /= Magic0 or else Buf (1) /= Magic1
        or else Buf (2) /= Version
      then
         return;
      end if;

      LFrag := Natural (Get16 (Buf, 20));
      LK    := Natural (Buf (22));
      LM    := Natural (Buf (23));
      LIdx  := Natural (Buf (24));

      --  Validate every structural field before it is trusted downstream.
      if LFrag > Max_Payload
        or else LK not in 1 .. Rs.Max_K
        or else LM not in 0 .. Rs.Max_M
        or else LIdx not in 1 .. LK + LM
        or else Len /= Header_Len + LFrag
      then
         return;
      end if;

      H := (Valid     => True,
            Scheme    => Buf (3),
            Stream_Id => Get64 (Buf, 4),
            Msg_Seq   => Get32 (Buf, 12),
            Msg_Len   => Get32 (Buf, 16),
            Frag_Len  => LFrag,
            K         => LK,
            M         => LM,
            Frag_Idx  => LIdx);
   end Parse;

end Diode_Wire;
