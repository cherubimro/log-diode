--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later
--
--  Syslog -- proven parser of the syslog priority prefix (RFC 5424 6.2.1,
--  RFC 3164 4.1.1).
--
--  Every syslog message, in both the modern (RFC 5424) and the legacy BSD
--  (RFC 3164) format, begins with a PRI part:  "<" DIGITS ">".  The number is
--  PRIVAL = facility * 8 + severity, with facility in 0 .. 23 and severity in
--  0 .. 7, so PRIVAL is in 0 .. 191.  Everything after the ">" is the rest of
--  the message, which this project treats as an opaque, verbatim payload -- we
--  re-emit it byte-identical, exactly as the diode's low side received it.
--
--  WHY THIS IS PROVEN, AND WHY IT MATTERS FOR LOGS.  On the paper's topology
--  (Anton et al., Sensors 2024) logs flow low -> high: the amplifier ingests
--  syslog from the *less trusted* datacenter network and the aggregator sits on
--  the high-security side.  So the bytes parsed here are ATTACKER-INFLUENCED --
--  a compromised low-side device can inject any datagram, and log injection is
--  a real technique for hiding tracks or framing a peer.  Parse therefore
--  *proves* that any 0..65535-byte datagram, however malformed, yields a
--  verdict without a run-time error: a missing '<', a non-digit, a runaway
--  number, an empty record -- all give Valid => False, never an out-of-bounds
--  read.  The severity it extracts drives the optional severity gate (forward
--  only messages at or above a configured urgency), which the C original lacks.

with Wire_Types; use Wire_Types;

package Syslog with SPARK_Mode => On is

   --  A record is at most one u16 length field's worth of bytes (covers the
   --  full practical syslog range: RFC 3164 caps at 1024, RFC 5424 recommends
   --  >= 2048 and has no hard max; a UDP datagram tops out well under 65535).
   Max_Record : constant := 65535;

   subtype Rec_Index is Natural range 0 .. Max_Record - 1;
   subtype Rec_Length is Natural range 0 .. Max_Record;
   type Record_Bytes is array (Rec_Index) of U8;

   subtype Facility_T is Natural range 0 .. 23;
   subtype Severity_T is Natural range 0 .. 7;

   --  Severity names (RFC 5424 6.2.1), lowest value = most urgent.
   Sev_Emergency : constant := 0;
   Sev_Alert     : constant := 1;
   Sev_Critical  : constant := 2;
   Sev_Error     : constant := 3;
   Sev_Warning   : constant := 4;
   Sev_Notice    : constant := 5;
   Sev_Info      : constant := 6;
   Sev_Debug     : constant := 7;

   type Pri_Info is record
      Facility : Facility_T := 0;
      Severity : Severity_T := 7;      --  default = least urgent
      Body_At  : Rec_Length := 0;      --  index of the first byte after ">"
   end record;

   --  Parse the PRI prefix of Rec (0 .. Len-1).  Valid => False on any malformed
   --  prefix -- never a run-time error, whatever the Len bytes contain.  When
   --  Valid, Info.Body_At points just past the ">" and 0 <= Body_At <= Len, so
   --  the caller can re-emit Rec (Body_At .. Len-1) as the opaque message body.
   procedure Parse
     (Rec   : Record_Bytes;
      Len   : Rec_Length;
      Info  : out Pri_Info;
      Valid : out Boolean)
     with Post => (if Valid then Info.Body_At <= Len);

   --  True iff a message of this severity should cross the diode, given the
   --  configured minimum urgency Max_Sev (forward severities 0 .. Max_Sev;
   --  e.g. Max_Sev = Sev_Warning drops Notice/Info/Debug).  Total, no I/O.
   function Passes_Gate (Severity : Severity_T; Max_Sev : Severity_T)
      return Boolean
   is (Severity <= Max_Sev);

end Syslog;
