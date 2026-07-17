--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Diode_Wire -- the framing WE put on each packet crossing the diode.
--
--  This is our own fixed binary header, not OPC UA: it carries exactly what the
--  receiver needs to regroup fragments, run erasure decoding, deduplicate, and
--  recover the original NetworkMessage.  The OPC UA payload rides inside,
--  opaque and verbatim.  Same discipline as gnat-lt-pro's lt_wire: fixed
--  offsets, proven Serialize/Parse, no dynamic parsing on the receive path.
--
--  Layout (little-endian, 25-byte header):
--    0    magic 'O','D'
--    2    version (=1)
--    3    scheme  (0 = Reed-Solomon; other values reserved)
--    4    stream_id   : U64  -- identifies one (publisher, writer-group) stream
--    12   msg_seq     : U32  -- our per-stream message counter (dedup + grouping)
--    16   msg_len     : U32  -- length of the reconstructed NetworkMessage
--    20   frag_len    : U16  -- payload bytes carried in THIS packet
--    22   k           : U8   -- data fragments
--    23   m           : U8   -- parity fragments
--    24   frag_idx    : U8   -- which fragment/slot this is, 1 .. k+m
--    25   payload[frag_len]

with Wire_Types; use Wire_Types;
with Gf256;      use Gf256;
with Rs;

package Diode_Wire with SPARK_Mode => On is

   Magic0 : constant := 16#4F#;   --  'O'
   Magic1 : constant := 16#44#;   --  'D'
   Version : constant := 1;

   --  The only transport scheme.  Reed-Solomon (K=72) covers the full UADP
   --  NetworkMessage size range, so there is no second scheme; the byte stays
   --  in the frame purely as a version/variant guard, and the receiver accepts
   --  only Scheme_RS.
   Scheme_RS : constant U8 := 0;

   Header_Len  : constant := 25;
   Max_Payload : constant := 1400;             --  = Rs.Max_Len
   Max_Packet  : constant := Header_Len + Max_Payload;

   subtype Pkt_Index  is Natural range 0 .. Max_Packet - 1;
   subtype Pkt_Length is Natural range 0 .. Max_Packet;
   type Packet is array (Pkt_Index) of Byte;

   subtype Payload_Length is Natural range 0 .. Max_Payload;

   --  Parsed diode header.  Valid is False for anything that is not a
   --  well-formed packet of this protocol (bad magic/version, impossible
   --  lengths or indices, or a buffer too short for the declared payload).
   type Header is record
      Valid     : Boolean := False;
      Scheme    : U8  := 0;
      Stream_Id : U64 := 0;
      Msg_Seq   : U32 := 0;
      Msg_Len   : U32 := 0;
      Frag_Len  : Payload_Length := 0;
      K         : Natural := 0;      --  1 .. Rs.Max_K
      M         : Natural := 0;      --  0 .. Rs.Max_M
      Frag_Idx  : Natural := 0;      --  1 .. K+M
   end record;

   --  Serialize a header + Frag_Len payload bytes taken from Payload (1-based)
   --  into Buf; Total is the packet length (Header_Len + Frag_Len).
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
     with Pre => K in 1 .. Rs.Max_K and then M in 0 .. Rs.Max_M
                 and then Frag_Idx in 1 .. K + M
                 and then Frag_Len <= Rs.Max_Len;

   --  Parse the first Len bytes of Buf.  Total on any input.  On success the
   --  payload occupies Buf (Header_Len .. Header_Len + Frag_Len - 1).  The
   --  postcondition hands the validated field bounds to callers, so the relay
   --  can index its RS structures without re-checking.
   procedure Parse
     (Buf : Packet; Len : Pkt_Length; H : out Header)
     with Post =>
       (if H.Valid then
          H.K in 1 .. Rs.Max_K
          and then H.M in 0 .. Rs.Max_M
          and then H.Frag_Idx in 1 .. H.K + H.M
          and then H.Frag_Len <= Max_Payload
          and then Len = Header_Len + H.Frag_Len);

end Diode_Wire;
