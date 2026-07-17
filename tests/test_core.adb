--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later
--
--  Functional sanity for the proven core.  The proof establishes that none of
--  this can fault; these tests establish that it computes the right answer.
--  Also the PROOF ANCHOR: it withs every core unit so gnatprove's mains-closure
--  analysis covers them, while --no-subprojects keeps SPARKNaCl's bodies out.

pragma SPARK_Mode (Off);   --  test harness: I/O

with Ada.Text_IO;   use Ada.Text_IO;
with Wire_Types;     use Wire_Types;
with Syslog;
with Log_Batch;
with Secure;
with Relay;
with Diode_Wire;

procedure Test_Core is

   Failures : Natural := 0;

   procedure Check (What : String; Cond : Boolean) is
   begin
      if not Cond then
         Put_Line ("  FAIL: " & What);
         Failures := Failures + 1;
      end if;
   end Check;

   --  A syslog record from a String.
   function Rec_Of (S : String) return Syslog.Record_Bytes is
      R : Syslog.Record_Bytes := (others => 0);
   begin
      for I in S'Range loop
         R (I - S'First) := U8 (Character'Pos (S (I)));
      end loop;
      return R;
   end Rec_Of;

begin
   ---------------------------------------------------------------------------
   Put_Line ("== syslog PRI parse: valid RFC 5424 / 3164 ==");
   declare
      use Syslog;
      Info  : Pri_Info;
      Ok    : Boolean;
      S     : constant String := "<13>Oct 11 22:14:15 host app: hello";
      R     : constant Record_Bytes := Rec_Of (S);
   begin
      Parse (R, S'Length, Info, Ok);
      Check ("valid", Ok);
      Check ("facility 1", Info.Facility = 1);   --  13 / 8 = 1
      Check ("severity 5 (notice)", Info.Severity = Sev_Notice);   --  13 mod 8
      Check ("body after '>'", Info.Body_At = 4);

      --  <165> = facility 20, severity 5.
      declare
         S2 : constant String := "<165>1 2003-10-11T22:14:15.003Z host - - - msg";
         R2 : constant Record_Bytes := Rec_Of (S2);
      begin
         Parse (R2, S2'Length, Info, Ok);
         Check ("165 valid", Ok);
         Check ("165 facility 20", Info.Facility = 20);
         Check ("165 severity 5", Info.Severity = 5);
      end;

      --  <0> emergency, kernel.
      declare
         S3 : constant String := "<0>panic";
         R3 : constant Record_Bytes := Rec_Of (S3);
      begin
         Parse (R3, S3'Length, Info, Ok);
         Check ("0 valid", Ok);
         Check ("0 = emergency", Info.Severity = Sev_Emergency);
      end;
   end;

   ---------------------------------------------------------------------------
   Put_Line ("== syslog PRI parse: hostile input never faults ==");
   declare
      use Syslog;
      Info : Pri_Info;
      Ok   : Boolean;

      procedure Reject (S : String; What : String) is
         R : constant Record_Bytes := Rec_Of (S);
      begin
         Parse (R, S'Length, Info, Ok);
         Check (What, not Ok);
      end Reject;
   begin
      Reject ("", "empty rejected");
      Reject ("no pri here", "no '<' rejected");
      Reject ("<>x", "empty pri rejected");
      Reject ("<abc>x", "non-digit rejected");
      Reject ("<9999>x", "too many digits rejected");
      Reject ("<192>x", "prival > 191 rejected");
      Reject ("<13", "missing '>' rejected");
      Reject ("<13x", "no '>' after digits rejected");

      --  Every single-byte mutation of a good record must parse-or-reject,
      --  never fault -- the property the proof makes unconditional.
      declare
         Good : constant Record_Bytes := Rec_Of ("<13>ok");
         M    : Record_Bytes;
      begin
         for I in 0 .. 5 loop
            for D in 1 .. 3 loop
               M := Good;
               M (I) := M (I) xor U8 (D * 85);
               Parse (M, 6, Info, Ok);   --  must not raise
            end loop;
         end loop;
         Check ("mutations survived", True);
      end;
   end;

   ---------------------------------------------------------------------------
   Put_Line ("== severity gate ==");
   declare
      use Syslog;
   begin
      Check ("crit passes warn-gate", Passes_Gate (Sev_Critical, Sev_Warning));
      Check ("info blocked by warn-gate", not Passes_Gate (Sev_Info, Sev_Warning));
      Check ("debug passes debug-gate", Passes_Gate (Sev_Debug, Sev_Debug));
   end;

   ---------------------------------------------------------------------------
   Put_Line ("== batch pack/unpack: round-trip of N records ==");
   declare
      Buf    : Secure.Plain_Buffer := (others => 0);
      Cursor : Log_Batch.Batch_Len := 0;
      Ok     : Boolean;
      L1     : constant String := "<13>first line";
      L2     : constant String := "<165>second, a bit longer line here";
      L3     : constant String := "<0>third";
   begin
      Log_Batch.Append (Buf, Cursor, Rec_Of (L1), L1'Length, Ok);
      Check ("append 1", Ok);
      Log_Batch.Append (Buf, Cursor, Rec_Of (L2), L2'Length, Ok);
      Check ("append 2", Ok);
      Log_Batch.Append (Buf, Cursor, Rec_Of (L3), L3'Length, Ok);
      Check ("append 3", Ok);

      declare
         Total : constant Log_Batch.Batch_Len := Cursor;
         C     : Log_Batch.Batch_Len := 0;
         Rec   : Syslog.Record_Bytes;
         RLen  : Syslog.Rec_Length;
         More  : Boolean;

         function Str (R : Syslog.Record_Bytes; N : Natural) return String is
            S : String (1 .. N);
         begin
            for I in 1 .. N loop S (I) := Character'Val (Natural (R (I - 1))); end loop;
            return S;
         end Str;
      begin
         Log_Batch.Next (Buf, Total, C, Rec, RLen, More);
         Check ("rec 1 present", More and then Str (Rec, RLen) = L1);
         Log_Batch.Next (Buf, Total, C, Rec, RLen, More);
         Check ("rec 2 present", More and then Str (Rec, RLen) = L2);
         Log_Batch.Next (Buf, Total, C, Rec, RLen, More);
         Check ("rec 3 present", More and then Str (Rec, RLen) = L3);
         Log_Batch.Next (Buf, Total, C, Rec, RLen, More);
         Check ("end of batch", not More);
      end;
   end;

   ---------------------------------------------------------------------------
   Put_Line ("== batch unpack: malformed length stops safely ==");
   declare
      Buf   : Secure.Plain_Buffer := (others => 0);
      C     : Log_Batch.Batch_Len := 0;
      Rec   : Syslog.Record_Bytes;
      RLen  : Syslog.Rec_Length;
      More  : Boolean;
   begin
      --  A length prefix that claims 60000 bytes in a 10-byte buffer.
      Buf (1) := 234;  Buf (2) := 96;   --  60000 = 234*256+96
      Log_Batch.Next (Buf, 10, C, Rec, RLen, More);
      Check ("lying length -> stop, no OOB", not More);
   end;

   ---------------------------------------------------------------------------
   Put_Line ("== full path: batch -> seal -> RS -> lose parity -> recover ==");
   declare
      Key   : constant Secure.Key_Bytes := (others => 7);
      Nonce : constant Secure.Nonce_Bytes := (1 => 1, others => 0);
      Plain : Secure.Plain_Buffer := (others => 0);
      Cur   : Log_Batch.Batch_Len := 0;
      Blob  : Secure.Blob_Buffer;
      BLen  : Secure.Blob_Len_T;
      Ok    : Boolean;
      L     : constant String := "<134>full path line crossing the diode";
      Msg   : Relay.Msg_Bytes := (others => 0);
      Pkts  : Relay.Packet_Array;
      Lens  : Relay.Length_Array;
      N_Out : Relay.Out_Count;
      C     : Relay.Collector;
      Produced : Boolean;
      Out_Msg  : Relay.Msg_Bytes;
      Out_Len  : Relay.Msg_Byte_Count;
   begin
      --  pack one record, seal, RS-protect
      Log_Batch.Append (Plain, Cur, Rec_Of (L), L'Length, Ok);
      Check ("packed", Ok);
      Secure.Seal (Plain, Cur, Key, Nonce, Blob, BLen);
      for I in 1 .. BLen loop Msg (I) := Blob (I); end loop;
      Relay.Protect (Msg, BLen, Stream_Id => 1, Msg_Seq => 1, M_Parity => 3,
                     Pkts => Pkts, Lens => Lens, N_Out => N_Out, Ok => Ok);
      Check ("protect ok", Ok and then N_Out >= 1);

      --  feed all fragments except the first 3 (simulate loss up to M)
      Relay.Init (C);
      Produced := False; Out_Len := 0;
      for I in 4 .. N_Out loop
         Relay.Offer (C, Pkts (I), Lens (I), Produced, Out_Msg, Out_Len);
         exit when Produced;
      end loop;
      Check ("recovered despite loss", Produced);

      --  open + unpack, verify the line survived byte-identical
      declare
         RBlob : Secure.Blob_Buffer := (others => 0);
         RPlain : Secure.Plain_Buffer;
         RPLen  : Secure.Plain_Len_T;
         ROk    : Boolean;
         C2     : Log_Batch.Batch_Len := 0;
         Rec    : Syslog.Record_Bytes;
         RLen   : Syslog.Rec_Length;
         More   : Boolean;
         Match  : Boolean := True;
      begin
         for I in 1 .. Out_Len loop RBlob (I) := Out_Msg (I); end loop;
         Secure.Open (RBlob, Out_Len, Key, RPlain, RPLen, ROk);
         Check ("AEAD opened", ROk);
         Log_Batch.Next (RPlain, Log_Batch.Batch_Len (RPLen), C2, Rec, RLen, More);
         Check ("unpacked one record", More and then RLen = L'Length);
         for I in 0 .. RLen - 1 loop
            if Rec (I) /= U8 (Character'Pos (L (L'First + I))) then Match := False; end if;
         end loop;
         Check ("line byte-identical across the diode", Match);
      end;
   end;

   ---------------------------------------------------------------------------
   New_Line;
   if Failures = 0 then
      Put_Line (">>> CORE SANITY PASSED");
   else
      Put_Line (">>> CORE SANITY FAILED:" & Failures'Image & " check(s)");
   end if;
end Test_Core;
