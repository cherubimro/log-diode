--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later

package body Log_Batch with SPARK_Mode => On is

   --  === Append ==========================================================

   procedure Append
     (Buf     : in out Secure.Plain_Buffer;
      Cursor  : in out Batch_Len;
      Rec     : Syslog.Record_Bytes;
      Rec_Len : Syslog.Rec_Length;
      Ok      : out Boolean)
   is
      Need : constant Natural := Len_Prefix + Rec_Len;
   begin
      --  Won't fit?  Leave Cursor untouched so the caller can flush and retry.
      if Rec_Len > Syslog.Max_Record or else Cursor > Max_Batch - Need then
         Ok := False;
         return;
      end if;

      --  Big-endian u16 length prefix.  Buf is 1-based; Cursor is a 0-based
      --  byte offset, so byte k lands at Buf (Cursor + k + 1).
      Buf (Cursor + 1) := U8 (Rec_Len / 256);
      Buf (Cursor + 2) := U8 (Rec_Len mod 256);
      for I in 0 .. Rec_Len - 1 loop
         Buf (Cursor + Len_Prefix + I + 1) := Rec (I);
         pragma Loop_Invariant (Cursor = Cursor'Loop_Entry);
      end loop;

      Cursor := Cursor + Need;
      Ok := True;
   end Append;

   --  === Next ============================================================

   procedure Next
     (Buf     : Secure.Plain_Buffer;
      Total   : Batch_Len;
      Cursor  : in out Batch_Len;
      Rec     : out Syslog.Record_Bytes;
      Rec_Len : out Syslog.Rec_Length;
      More    : out Boolean)
   is
      Len : Natural;
   begin
      Rec     := (others => 0);
      Rec_Len := 0;
      More    := False;

      --  Need a full 2-byte length header still inside the buffer.
      if Cursor > Total - Len_Prefix or else Total < Len_Prefix then
         return;
      end if;

      Len := Natural (Buf (Cursor + 1)) * 256 + Natural (Buf (Cursor + 2));

      --  THE bounded-read gate: a length that runs past Total, or past a single
      --  record's capacity, ends the walk -- it never becomes an index.
      if Len > Syslog.Max_Record
        or else Len > Total - Cursor - Len_Prefix
      then
         return;
      end if;

      for I in 0 .. Len - 1 loop
         Rec (I) := Buf (Cursor + Len_Prefix + I + 1);
         pragma Loop_Invariant (Cursor = Cursor'Loop_Entry);
      end loop;

      Rec_Len := Len;
      Cursor  := Cursor + Len_Prefix + Len;
      More    := True;
   end Next;

end Log_Batch;
