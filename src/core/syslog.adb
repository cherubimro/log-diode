--  log-diode -- a high-assurance Ada/SPARK syslog data-diode amplifier.
--  Copyright (C) 2026  Alin-Adrian Anton <alin.anton@upt.ro>
--  SPDX-License-Identifier: AGPL-3.0-or-later

package body Syslog with SPARK_Mode => On is

   Lt : constant U8 := Character'Pos ('<');   --  16#3C#
   Gt : constant U8 := Character'Pos ('>');   --  16#3E#
   D0 : constant U8 := Character'Pos ('0');   --  16#30#
   D9 : constant U8 := Character'Pos ('9');   --  16#39#

   procedure Parse
     (Rec   : Record_Bytes;
      Len   : Rec_Length;
      Info  : out Pri_Info;
      Valid : out Boolean)
   is
      Prival : Natural := 0;
      Digits_Seen : Natural := 0;
      Cur    : Rec_Length := 1;
   begin
      Info  := (Facility => 0, Severity => 7, Body_At => 0);
      Valid := False;

      --  Must start with '<'.
      if Len < 3 or else Rec (0) /= Lt then
         return;
      end if;

      --  1 .. 3 digits.  PRIVAL is at most 191, so it never exceeds three
      --  digits; capping the loop at 3 both matches the spec and keeps Prival
      --  provably small, so the * 10 accumulate and the * 8 / mod 8 below
      --  cannot overflow.  The invariant couples Prival's magnitude to the
      --  digit count (a k-digit number is < 10^k), which is what lets the
      --  prover bound Prival before the next multiply.
      while Cur < Len and then Digits_Seen < 3
        and then Rec (Cur) in D0 .. D9
      loop
         Prival := Prival * 10 + Natural (Rec (Cur) - D0);
         Digits_Seen := Digits_Seen + 1;
         Cur := Cur + 1;
         pragma Loop_Invariant (Cur <= Len);
         pragma Loop_Invariant (Digits_Seen in 1 .. 3);
         pragma Loop_Invariant
           (Prival <= (if Digits_Seen = 1 then 9
                       elsif Digits_Seen = 2 then 99
                       else 999));
      end loop;

      --  Need at least one digit, a closing '>', and a valid PRIVAL (<= 191).
      if Digits_Seen = 0 or else Cur >= Len or else Rec (Cur) /= Gt
        or else Prival > 191
      then
         return;
      end if;

      --  Cur points at '>', so the body begins at Cur + 1 (<= Len).
      Info.Facility := Prival / 8;
      Info.Severity := Prival mod 8;
      Info.Body_At  := Cur + 1;
      Valid := True;
   end Parse;

end Syslog;
