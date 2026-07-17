--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later

pragma SPARK_Mode (Off);   --  trusted I/O shell over the proven codec core

with Ada.Command_Line;      use Ada.Command_Line;
with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Streams;           use Ada.Streams;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Unchecked_Conversion;
with GNAT.Sockets;         use GNAT.Sockets;
with GNAT.OS_Lib;

with Wire_Types;           use Wire_Types;
with Syslog;
with Log_Batch;
with Secure;
with Relay;
with Diode_Wire;
with Ld_Key;

--  DEAMPLIFIER (high-security side).  The receiver-forwarder of Anton et al.
--  (Sensors 2024), hardened:
--
--    ld_deamp <diode_port> <out_ip> <out_port> [--key HEX64]
--
--  It captures the Reed-Solomon fragments on <diode_port>, hands each to
--  Relay.Offer (which regroups by message, erasure-decodes at K, de-duplicates
--  the interleaved repetitions and enforces the anti-replay window), and on a
--  recovered message opens the AEAD chunk (a wrong key, a tamper, or a replayed
--  message fails the Poly1305 tag and is dropped -- a real authenticator, not
--  the paper's "did it decrypt to printable ASCII" heuristic), unpacks the batch
--  into its individual syslog records with the proven Log_Batch, and re-emits
--  each as syslog/UDP to a local rsyslog on <out_port> (default 514).
procedure Ld_Deamp is

   subtype Wire_SEA is Stream_Element_Array (1 .. Diode_Wire.Max_Packet);
   function To_Pkt is
     new Ada.Unchecked_Conversion (Wire_SEA, Diode_Wire.Packet);

   procedure Die (Msg : String) is
   begin
      Put_Line (Standard_Error, "[ld_deamp] " & Msg);
      GNAT.OS_Lib.OS_Exit (1);
   end Die;

   ---------------------------------------------------------------------------
   --  CLI
   ---------------------------------------------------------------------------
   Diode_Port : Port_Type := 0;
   Out_Ip     : Unbounded_String := Null_Unbounded_String;
   Out_Port   : Port_Type := 514;
   Use_Key    : Boolean := False;
   Key        : Secure.Key_Bytes := (others => 0);

   procedure Parse_Cli is
      Pos : Natural := 0;
      I   : Natural := 1;
   begin
      while I <= Argument_Count loop
         declare
            A : constant String := Argument (I);
         begin
            if A = "--key" and then I < Argument_Count then
               I := I + 1;
               declare
                  Ok : Boolean;
               begin
                  Ld_Key.Parse_Hex (Argument (I), Key, Ok);
                  if not Ok then Die ("--key needs 64 hex chars"); end if;
                  Use_Key := True;
               end;
            elsif A'Length >= 2 and then A (A'First .. A'First + 1) = "--" then
               Die ("unknown option " & A);
            else
               Pos := Pos + 1;
               case Pos is
                  when 1 => Diode_Port := Port_Type'Value (A);
                  when 2 => Out_Ip     := To_Unbounded_String (A);
                  when 3 => Out_Port   := Port_Type'Value (A);
                  when others => Die ("too many arguments");
               end case;
            end if;
         end;
         I := I + 1;
      end loop;
      if Pos < 2 then
         Die ("usage: ld_deamp <diode_port> <out_ip> [<out_port>] [--key HEX64]");
      end if;
   end Parse_Cli;

   ---------------------------------------------------------------------------
   --  Sockets
   ---------------------------------------------------------------------------
   In_Sock  : Socket_Type;
   Out_Sock : Socket_Type;
   Out_Addr : Sock_Addr_Type;

   procedure Open_Sockets is
      In_Addr : Sock_Addr_Type;
   begin
      Create_Socket (In_Sock, Family_Inet, Socket_Datagram);
      Set_Socket_Option (In_Sock, Socket_Level, (Reuse_Address, True));
      Set_Socket_Option (In_Sock, Socket_Level, (Receive_Buffer, 16#0080_0000#));
      In_Addr.Addr := Any_Inet_Addr;
      In_Addr.Port := Diode_Port;
      Bind_Socket (In_Sock, In_Addr);

      Create_Socket (Out_Sock, Family_Inet, Socket_Datagram);
      Out_Addr.Addr := Addresses (Get_Host_By_Name (To_String (Out_Ip)), 1);
      Out_Addr.Port := Out_Port;
   end Open_Sockets;

   --  Re-emit one recovered syslog record verbatim as a UDP datagram.
   procedure Emit_Record (Rec : Syslog.Record_Bytes; Len : Syslog.Rec_Length) is
      SEA  : Stream_Element_Array (1 .. Stream_Element_Offset (Len));
      Last : Stream_Element_Offset;
   begin
      for I in 0 .. Len - 1 loop
         SEA (Stream_Element_Offset (I + 1)) := Stream_Element (Rec (I));
      end loop;
      Send_Socket (Out_Sock, SEA, Last, Out_Addr);
   exception
      when Socket_Error => null;
   end Emit_Record;

   --  A recovered (post-RS) message: open, unpack the batch, re-emit each line.
   procedure Consume (Msg : Relay.Msg_Bytes; Msg_Len : Relay.Msg_Byte_Count) is
      Plain : Secure.Plain_Buffer := (others => 0);
      PLen  : Natural := 0;
   begin
      if Use_Key then
         declare
            Blob : Secure.Blob_Buffer := (others => 0);
            Ok   : Boolean;
            CPL  : Secure.Plain_Len_T;
         begin
            if Msg_Len > Secure.Max_Blob then return; end if;
            for I in 1 .. Msg_Len loop Blob (I) := Msg (I); end loop;
            Secure.Open (Blob, Msg_Len, Key, Plain, CPL, Ok);
            if not Ok then return; end if;   --  bad tag: forged/tampered/replayed
            PLen := CPL;
         end;
      else
         if Msg_Len > Secure.Max_Plain then return; end if;
         for I in 1 .. Msg_Len loop Plain (I) := Msg (I); end loop;
         PLen := Msg_Len;
      end if;

      --  Walk the batch (proven: a malformed length stops the walk, no OOB).
      declare
         C    : Log_Batch.Batch_Len := 0;
         Rec  : Syslog.Record_Bytes;
         RLen : Syslog.Rec_Length;
         More : Boolean := True;
      begin
         while More loop
            Log_Batch.Next (Plain, Log_Batch.Batch_Len (PLen), C, Rec, RLen, More);
            if More and then RLen > 0 then
               Emit_Record (Rec, RLen);
            end if;
         end loop;
      end;
   end Consume;

   Coll : Relay.Collector;

begin
   Parse_Cli;
   Relay.Init (Coll);
   Open_Sockets;
   Put_Line (Standard_Error,
     "[ld_deamp] diode :" & Diode_Port'Image & " -> syslog/UDP "
     & To_String (Out_Ip) & ":" & Out_Port'Image
     & (if Use_Key then " (encrypted)" else " (cleartext)"));

   loop
      declare
         SEA  : Wire_SEA;
         Last : Stream_Element_Offset;
         From : Sock_Addr_Type;
      begin
         Receive_Socket (In_Sock, SEA, Last, From);
         if Last >= Stream_Element_Offset (Diode_Wire.Header_Len) then
            declare
               Produced : Boolean;
               Out_Msg  : Relay.Msg_Bytes;
               Out_Len  : Relay.Msg_Byte_Count;
            begin
               Relay.Offer (Coll, To_Pkt (SEA),
                            Diode_Wire.Pkt_Length (Last),
                            Produced, Out_Msg, Out_Len);
               if Produced then
                  Consume (Out_Msg, Out_Len);
               end if;
            end;
         end if;
      exception
         when Socket_Error => null;
      end;
   end loop;
end Ld_Deamp;
