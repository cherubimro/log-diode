--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later

pragma SPARK_Mode (Off);   --  trusted I/O shell over the proven codec core

with Ada.Command_Line;      use Ada.Command_Line;
with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Streams;           use Ada.Streams;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Unchecked_Conversion;
with Interfaces;            use Interfaces;
with GNAT.Sockets;         use GNAT.Sockets;
with GNAT.OS_Lib;

with Wire_Types;           use Wire_Types;
with Syslog;
with Log_Batch;
with Secure;
with Relay;
with Diode_Wire;
with Ld_Key;

--  AMPLIFIER (low-security side).  The Ada/SPARK reimplementation of the
--  encrypted syslog amplifier of Anton et al. (Sensors 2024), hardened:
--
--    ld_amp <listen_port> <diode_ip> <diode_port> [--key HEX64] [--batch N]
--           [--parity M] [--interleave D] [--min-severity S] [--pace-us N]
--           [--flush-ms T]
--
--  It receives syslog/UDP on <listen_port> (default 1514).  Each datagram's PRI
--  is parsed by the proven Syslog unit and severity-gated; surviving records are
--  packed --batch N to a message (default 1 = one record per message), which is
--  then AEAD-sealed (ChaCha20-Poly1305 -- authenticated, unlike the paper's
--  Speck-R) and Reed-Solomon-coded with M parity fragments.  --interleave D
--  spreads the fragments of D messages column-major so a burst can't take all
--  copies of one message (the paper repeated back-to-back).  A partial batch is
--  flushed after --flush-ms so a lone log line never waits forever.
procedure Ld_Amp is

   Max_Interleave : constant := Relay.Max_Inflight;   --  16

   subtype Wire_SEA is Stream_Element_Array (1 .. Diode_Wire.Max_Packet);
   function To_SEA is
     new Ada.Unchecked_Conversion (Diode_Wire.Packet, Wire_SEA);

   procedure Die (Msg : String) is
   begin
      Put_Line (Standard_Error, "[ld_amp] " & Msg);
      GNAT.OS_Lib.OS_Exit (1);
   end Die;

   ---------------------------------------------------------------------------
   --  CLI
   ---------------------------------------------------------------------------
   Listen_Port : Port_Type := 1514;
   Diode_Ip    : Unbounded_String := Null_Unbounded_String;
   Diode_Port  : Port_Type := 0;
   Use_Key     : Boolean := False;
   Key         : Secure.Key_Bytes := (others => 0);
   Batch_N     : Positive := 1;
   Parity      : Natural := 3;
   Interleave  : Natural := 1;
   Min_Sev     : Syslog.Severity_T := Syslog.Sev_Debug;   --  forward everything
   Pace_Us     : Natural := 0;
   Flush_Ms    : Natural := 500;

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
            elsif A = "--batch" and then I < Argument_Count then
               I := I + 1; Batch_N := Positive'Value (Argument (I));
            elsif A = "--parity" and then I < Argument_Count then
               I := I + 1; Parity := Natural'Value (Argument (I));
            elsif A = "--interleave" and then I < Argument_Count then
               I := I + 1; Interleave := Natural'Value (Argument (I));
            elsif A = "--min-severity" and then I < Argument_Count then
               I := I + 1; Min_Sev := Syslog.Severity_T'Value (Argument (I));
            elsif A = "--pace-us" and then I < Argument_Count then
               I := I + 1; Pace_Us := Natural'Value (Argument (I));
            elsif A = "--flush-ms" and then I < Argument_Count then
               I := I + 1; Flush_Ms := Natural'Value (Argument (I));
            elsif A'Length >= 2 and then A (A'First .. A'First + 1) = "--" then
               Die ("unknown option " & A);
            else
               Pos := Pos + 1;
               case Pos is
                  when 1 => Listen_Port := Port_Type'Value (A);
                  when 2 => Diode_Ip    := To_Unbounded_String (A);
                  when 3 => Diode_Port  := Port_Type'Value (A);
                  when others => Die ("too many arguments");
               end case;
            end if;
         end;
         I := I + 1;
      end loop;
      if Pos < 3 then
         Die ("usage: ld_amp <listen_port> <diode_ip> <diode_port> "
              & "[--key HEX64] [--batch N] [--parity M] [--interleave D] "
              & "[--min-severity 0..7] [--pace-us N] [--flush-ms T]");
      end if;
      if Parity > 40 then Die ("--parity too large"); end if;
      if Interleave < 1 then Interleave := 1; end if;
      if Interleave > Max_Interleave then Interleave := Max_Interleave; end if;
   end Parse_Cli;

   ---------------------------------------------------------------------------
   --  Sockets: bind the syslog listener, connect the diode sender.
   ---------------------------------------------------------------------------
   In_Sock  : Socket_Type;
   Out_Sock : Socket_Type;

   procedure Open_Sockets is
      In_Addr  : Sock_Addr_Type;
      Out_Addr : Sock_Addr_Type;
   begin
      Create_Socket (In_Sock, Family_Inet, Socket_Datagram);
      Set_Socket_Option (In_Sock, Socket_Level, (Reuse_Address, True));
      Set_Socket_Option (In_Sock, Socket_Level, (Receive_Buffer, 16#0080_0000#));
      In_Addr.Addr := Any_Inet_Addr;
      In_Addr.Port := Listen_Port;
      Bind_Socket (In_Sock, In_Addr);
      --  A receive timeout lets us flush a partial batch periodically.
      Set_Socket_Option
        (In_Sock, Socket_Level,
         (Receive_Timeout, Timeout => Duration (Flush_Ms) / 1000.0));

      Create_Socket (Out_Sock, Family_Inet, Socket_Datagram);
      Out_Addr.Addr := Addresses (Get_Host_By_Name (To_String (Diode_Ip)), 1);
      Out_Addr.Port := Diode_Port;
      Connect_Socket (Out_Sock, Out_Addr);
   end Open_Sockets;

   procedure Send_Pkt (P : Diode_Wire.Packet; Len : Diode_Wire.Pkt_Length) is
      Data : constant Wire_SEA := To_SEA (P);
      Last : Stream_Element_Offset;
   begin
      Send_Socket (Out_Sock, Data (1 .. Stream_Element_Offset (Len)), Last);
      if Pace_Us > 0 then
         delay Duration (Pace_Us) / 1_000_000.0;
      end if;
   exception
      when Socket_Error => null;
   end Send_Pkt;

   ---------------------------------------------------------------------------
   --  Message identity + AEAD nonce (fresh salt per run, monotonic counter).
   ---------------------------------------------------------------------------
   Salt      : constant U32 := Ld_Key.Random_Salt;
   Stream_Id : constant U64 := U64 (Salt) * (2 ** 32) + U64 (Ld_Key.Random_Salt);
   Msg_Ctr   : U32 := 0;   --  the paper's uint64 counter role; nonce-unique

   ---------------------------------------------------------------------------
   --  Fragment interleaving across messages (as in the sibling projects).
   ---------------------------------------------------------------------------
   type Job is record
      Pkts : Relay.Packet_Array;
      Lens : Relay.Length_Array;
      N    : Relay.Out_Count := 0;
   end record;
   type Job_Array is array (1 .. Max_Interleave) of Job;
   type Job_Ptr   is access Job_Array;
   Jobs  : constant Job_Ptr := new Job_Array;
   NJobs : Natural := 0;

   procedure Flush_Jobs is
      Max_N : Natural := 0;
   begin
      for J in 1 .. NJobs loop
         if Jobs (J).N > Max_N then Max_N := Jobs (J).N; end if;
      end loop;
      for Round in 1 .. Max_N loop
         for J in 1 .. NJobs loop
            if Round <= Jobs (J).N then
               Send_Pkt (Jobs (J).Pkts (Round), Jobs (J).Lens (Round));
            end if;
         end loop;
      end loop;
      NJobs := 0;
   end Flush_Jobs;

   ---------------------------------------------------------------------------
   --  The current batch being packed.
   ---------------------------------------------------------------------------
   Batch     : Secure.Plain_Buffer := (others => 0);
   Batch_Cur : Log_Batch.Batch_Len := 0;
   Batch_Cnt : Natural := 0;

   --  Seal + RS-protect the current batch into a Job; interleave-flush when the
   --  Job buffer is full.  Empty batch -> nothing.
   procedure Emit_Batch is
      Nonce : Secure.Nonce_Bytes := (others => 0);
      Blob  : Secure.Blob_Buffer;
      BLen  : Secure.Blob_Len_T;
      Msg   : Relay.Msg_Bytes := (others => 0);
      Ok    : Boolean;
   begin
      if Batch_Cnt = 0 then return; end if;

      if Use_Key then
         --  nonce = Salt | 0 | Msg_Ctr  (unique per sealed message)
         Nonce (1) := U8 (Salt / (2 ** 24) mod 256);
         Nonce (2) := U8 (Salt / (2 ** 16) mod 256);
         Nonce (3) := U8 (Salt / (2 ** 8) mod 256);
         Nonce (4) := U8 (Salt mod 256);
         Nonce (9)  := U8 (Msg_Ctr / (2 ** 24) mod 256);
         Nonce (10) := U8 (Msg_Ctr / (2 ** 16) mod 256);
         Nonce (11) := U8 (Msg_Ctr / (2 ** 8) mod 256);
         Nonce (12) := U8 (Msg_Ctr mod 256);
         Secure.Seal (Batch, Batch_Cur, Key, Nonce, Blob, BLen);
         for I in 1 .. BLen loop Msg (I) := Blob (I); end loop;
         NJobs := NJobs + 1;
         Relay.Protect (Msg, BLen, Stream_Id, Msg_Ctr, Parity,
                        Jobs (NJobs).Pkts, Jobs (NJobs).Lens,
                        Jobs (NJobs).N, Ok);
      else
         for I in 1 .. Batch_Cur loop Msg (I) := Batch (I); end loop;
         NJobs := NJobs + 1;
         Relay.Protect (Msg, Batch_Cur, Stream_Id, Msg_Ctr, Parity,
                        Jobs (NJobs).Pkts, Jobs (NJobs).Lens,
                        Jobs (NJobs).N, Ok);
      end if;
      if not Ok then NJobs := NJobs - 1; end if;

      Msg_Ctr := Msg_Ctr + 1;
      Batch_Cur := 0;
      Batch_Cnt := 0;

      if NJobs >= Interleave then Flush_Jobs; end if;
   end Emit_Batch;

begin
   Parse_Cli;
   Open_Sockets;
   Put_Line (Standard_Error,
     "[ld_amp] syslog/UDP :" & Listen_Port'Image & " -> diode "
     & To_String (Diode_Ip) & ":" & Diode_Port'Image
     & "  batch" & Batch_N'Image & " parity" & Parity'Image
     & " interleave" & Interleave'Image
     & " min-sev" & Min_Sev'Image
     & (if Use_Key then " (encrypted)" else " (cleartext)"));

   loop
      declare
         SEA  : Stream_Element_Array (1 .. Syslog.Max_Record);
         Last : Stream_Element_Offset;
         From : Sock_Addr_Type;
      begin
         Receive_Socket (In_Sock, SEA, Last, From);
         if Last >= SEA'First then
            declare
               Rec  : Syslog.Record_Bytes := (others => 0);
               RLen : constant Natural := Natural (Last);
               Info : Syslog.Pri_Info;
               Ok   : Boolean;
               Add  : Boolean;
            begin
               for I in SEA'First .. Last loop
                  Rec (Natural (I - SEA'First)) := U8 (SEA (I));
               end loop;

               --  Severity gate (proven parse).  A record without a valid PRI
               --  is forwarded by default (we do not silently drop unparseable
               --  logs -- they may be the most interesting ones).
               Syslog.Parse (Rec, RLen, Info, Ok);
               if (not Ok) or else Syslog.Passes_Gate (Info.Severity, Min_Sev)
               then
                  Log_Batch.Append (Batch, Batch_Cur, Rec, RLen, Add);
                  if not Add then          --  batch full: flush, then retry
                     Emit_Batch;
                     Log_Batch.Append (Batch, Batch_Cur, Rec, RLen, Add);
                  end if;
                  if Add then
                     Batch_Cnt := Batch_Cnt + 1;
                     if Batch_Cnt >= Batch_N then Emit_Batch; end if;
                  end if;
               end if;
            end;
         end if;
      exception
         --  Receive timeout: flush whatever is buffered so logs are not held.
         when Socket_Error =>
            Emit_Batch;
            if NJobs > 0 then Flush_Jobs; end if;
      end;
   end loop;
end Ld_Amp;
