--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later
--
--  Log_Batch -- proven packing of N syslog records into one coded message.
--
--  A single syslog line is tiny (30 B .. ~1 KB), so protecting each one on its
--  own is Reed-Solomon at K = 1 -- which degenerates to plain repetition, the
--  paper's scheme (Anton et al., Sensors 2024) with no coding gain.  Batching
--  packs up to --batch N records into ONE message before it is sealed and
--  erasure-coded, so a genuine RS block (K >= 2) protects the whole batch: any
--  K of K+M diode packets rebuild all N lines.  Far cheaper on the wire than
--  repeating every line, at the cost of coupling them (a decode failure loses
--  the batch) and a bounded flush latency.  --batch 1 (the default) packs one
--  record per message, reproducing the faithful per-line path.
--
--  Wire layout inside the batch buffer -- length-prefixed records back to back:
--
--      [ u16 len_1 | bytes_1 ] [ u16 len_2 | bytes_2 ] ... up to Max_Batch
--
--  and it is that buffer (<= Secure.Max_Plain) that is AEAD-sealed, then RS-
--  coded.  No explicit record count: the walk stops when the buffer is spent.
--
--  WHY THIS IS PROVEN.  Unpack runs on the receiver, over bytes that (after the
--  Poly1305 tag has already been checked) are trusted for authenticity but must
--  still be parsed safely -- a truncated or internally inconsistent buffer (a
--  length field that runs past the end) must NOT cause an out-of-bounds read.
--  Next therefore *proves* that a lying length ends the walk with Ok => False
--  rather than reading past Total: the same bounded-cursor discipline as the
--  chunk framing in the sibling projects.

with Wire_Types; use Wire_Types;
with Secure;
with Syslog;

package Log_Batch with SPARK_Mode => On is

   --  The batch is packed into a Secure plaintext buffer, so it is bounded by
   --  what the AEAD can seal in one go.
   Max_Batch : constant := Secure.Max_Plain;   --  65536
   Len_Prefix : constant := 2;                  --  u16 length field

   subtype Batch_Len is Natural range 0 .. Max_Batch;

   --  === Pack (sender) ===================================================
   --
   --  Append record Rec (0 .. Rec_Len-1) to Buf at Cursor, framed as
   --  [u16 len][bytes], advancing Cursor.  Ok => False (Cursor unchanged) if it
   --  would not fit -- the caller then flushes the batch and starts a new one.
   procedure Append
     (Buf     : in out Secure.Plain_Buffer;
      Cursor  : in out Batch_Len;
      Rec     : Syslog.Record_Bytes;
      Rec_Len : Syslog.Rec_Length;
      Ok      : out Boolean)
     with Pre  => Cursor <= Max_Batch,
          Post => Cursor <= Max_Batch
                    and then (if Ok then Cursor >= Cursor'Old)
                    and then (if not Ok then Cursor = Cursor'Old);

   --  === Unpack (receiver) ================================================
   --
   --  Extract the record starting at Cursor from Buf (valid bytes 1 .. Total).
   --  More => False means the walk is finished OR the framing is malformed
   --  (both end iteration safely).  On More => True, Rec (0 .. Rec_Len-1) is the
   --  record and Cursor has advanced past it.  Proven never to read past Total.
   procedure Next
     (Buf     : Secure.Plain_Buffer;
      Total   : Batch_Len;
      Cursor  : in out Batch_Len;
      Rec     : out Syslog.Record_Bytes;
      Rec_Len : out Syslog.Rec_Length;
      More    : out Boolean)
     with Pre  => Cursor <= Total,
          Post => Cursor <= Total;

end Log_Batch;
