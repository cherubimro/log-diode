--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton

with Ada.Calendar;            use Ada.Calendar;
with Ada.Streams;
with Ada.Streams.Stream_IO;
with Interfaces.C;
with System;

package body Ld_Key with SPARK_Mode => Off is

   use type Interfaces.C.long;

   --  getrandom(2): fill a buffer with cryptographically secure random bytes.
   --  Returns the byte count, or -1 on error (old kernel / no wrapper).
   function C_Getrandom
     (Buf   : System.Address;
      Len   : Interfaces.C.size_t;
      Flags : Interfaces.C.unsigned) return Interfaces.C.long
     with Import, Convention => C, External_Name => "getrandom";

   function Nibble (C : Character; Ok : in out Boolean) return U8 is
   begin
      case C is
         when '0' .. '9' => return U8 (Character'Pos (C) - Character'Pos ('0'));
         when 'a' .. 'f' => return U8 (Character'Pos (C) - Character'Pos ('a') + 10);
         when 'A' .. 'F' => return U8 (Character'Pos (C) - Character'Pos ('A') + 10);
         when others     => Ok := False; return 0;
      end case;
   end Nibble;

   procedure Parse_Hex (S : String; Key : out Secure.Key_Bytes; Ok : out Boolean)
   is
      P : Natural := S'First;
   begin
      Key := (others => 0);
      Ok  := (S'Length = 2 * Secure.Key_Len);
      if not Ok then
         return;
      end if;
      for I in Key'Range loop
         declare
            Hi : constant U8 := Nibble (S (P), Ok);
            Lo : constant U8 := Nibble (S (P + 1), Ok);
         begin
            Key (I) := Hi * 16 + Lo;
         end;
         P := P + 2;
      end loop;
   end Parse_Hex;

   --  Last-resort salt if the OS CSPRNG is unreachable: a clock/mix value.
   --  Weaker than real entropy, but never worse than the old behaviour, and
   --  only reached on a kernel without getrandom AND without /dev/urandom.
   function Clock_Salt return U32 is
      Now : constant Duration := Seconds (Clock);
      S   : constant U64 := U64 (Long_Long_Integer (Now * 1_000_000.0));
      Z   : U64 := S * 16#2545F4914F6CDD1D# + 16#9E3779B97F4A7C15#;
   begin
      Z := (Z xor (Z / 2 ** 32));
      return U32 (Z mod 2 ** 32);
   end Clock_Salt;

   function Random_Salt return U32 is
      B : aliased array (1 .. 4) of Interfaces.Unsigned_8 := (others => 0);
      R : Interfaces.C.long;
   begin
      --  Primary: getrandom(2), the modern blocking CSPRNG.
      R := C_Getrandom (B'Address, 4, 0);
      if R = 4 then
         return U32 (B (1))
              + U32 (B (2)) * 2 ** 8
              + U32 (B (3)) * 2 ** 16
              + U32 (B (4)) * 2 ** 24;
      end if;

      --  Fallback: read 4 bytes from /dev/urandom.
      declare
         use Ada.Streams;
         use Ada.Streams.Stream_IO;
         F    : File_Type;
         Buf  : Stream_Element_Array (1 .. 4);
         Last : Stream_Element_Offset;
      begin
         Open (F, In_File, "/dev/urandom");
         Read (F, Buf, Last);
         Close (F);
         if Last = 4 then
            return U32 (Buf (1))
                 + U32 (Buf (2)) * 2 ** 8
                 + U32 (Buf (3)) * 2 ** 16
                 + U32 (Buf (4)) * 2 ** 24;
         end if;
      exception
         when others => null;
      end;

      --  Last resort.
      return Clock_Salt;
   end Random_Salt;

end Ld_Key;
