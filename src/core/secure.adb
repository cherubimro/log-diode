--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Secure body.  Marshals our U8 buffers to and from SPARKNaCl's Byte_Seq (a
--  0-based array of Interfaces.Unsigned_8), calls the proven AEAD, and lays out
--  the blob.  Every SPARKNaCl precondition (0-based, equal lengths, size < N32)
--  is met by construction; the rest of the proof is our own index bounds.
--
--  A fixed one-byte AAD (a protocol tag) is authenticated alongside: it also
--  sidesteps SPARKNaCl's zero-length-array corner, since a null Byte_Seq cannot
--  have 'First = 0.

with SPARKNaCl;             use SPARKNaCl;
with SPARKNaCl.Core;
with SPARKNaCl.Secretbox;

package body Secure with SPARK_Mode => On is

   use type SPARKNaCl.I32;

   AAD_Tag : constant SPARKNaCl.Byte := 16#4F#;   --  'O' for OPC-diode

   --  U8 <-> SPARKNaCl.Byte, both 8-bit modular; value-preserving via Integer.
   function To_SN (X : U8) return SPARKNaCl.Byte is
     (SPARKNaCl.Byte (Integer (X)));
   function To_U8 (B : SPARKNaCl.Byte) return U8 is
     (U8 (Integer (B)));

   --  Our 1-based 32-byte key -> a SPARKNaCl ChaCha20_Key.
   function Make_Key (K : Key_Bytes) return Core.ChaCha20_Key is
      B : Bytes_32 := (others => 0);
   begin
      for I in 1 .. Key_Len loop
         B (SPARKNaCl.N32 (I - 1)) := To_SN (K (I));
      end loop;
      return Core.Construct (B);
   end Make_Key;

   ----------
   -- Seal --
   ----------

   procedure Seal
     (Plain     : Plain_Buffer;
      Plain_Len : Plain_Len_T;
      Key       : Key_Bytes;
      Nonce     : Nonce_Bytes;
      Blob      : out Blob_Buffer;
      Blob_Len  : out Blob_Len_T)
   is
      N   : constant SPARKNaCl.N32 := SPARKNaCl.N32 (Plain_Len);
      M   : Byte_Seq (0 .. N - 1);
      C   : Byte_Seq (0 .. N - 1);
      Tag : Bytes_16 := (others => 0);
      Non : Core.ChaCha20_IETF_Nonce := (others => 0);
      Kc  : Core.ChaCha20_Key := Make_Key (Key);
      AAD : constant Byte_Seq (0 .. 0) := (0 => AAD_Tag);
   begin
      Blob := (others => 0);

      for I in 1 .. Nonce_Len loop
         Non (SPARKNaCl.N32 (I - 1)) := To_SN (Nonce (I));
      end loop;
      --  Iterate M's own index so SPARK sees every element initialised.
      for I in 0 .. N - 1 loop
         M (I) := To_SN (Plain (Natural (I) + 1));
      end loop;

      SPARKNaCl.Secretbox.Create (C, Tag, M, Non, Kc, AAD);

      --  Lay out [ nonce | tag | ciphertext ].
      for I in 1 .. Nonce_Len loop
         Blob (I) := Nonce (I);
      end loop;
      for I in 1 .. Tag_Len loop
         Blob (Nonce_Len + I) := To_U8 (Tag (SPARKNaCl.N32 (I - 1)));
      end loop;
      for I in 1 .. Plain_Len loop
         Blob (Overhead + I) := To_U8 (C (SPARKNaCl.N32 (I - 1)));
      end loop;

      Blob_Len := Plain_Len + Overhead;
   end Seal;

   ----------
   -- Open --
   ----------

   procedure Open
     (Blob      : Blob_Buffer;
      Blob_Len  : Blob_Len_T;
      Key       : Key_Bytes;
      Plain     : out Plain_Buffer;
      Plain_Len : out Plain_Len_T;
      Ok        : out Boolean)
   is
   begin
      Plain     := (others => 0);
      Plain_Len := 0;
      Ok        := False;

      if Blob_Len < Overhead + 1 then
         return;                       --  too short to hold nonce+tag+1 byte
      end if;

      declare
         PL  : constant Plain_Len_T := Blob_Len - Overhead;
         N   : constant SPARKNaCl.N32 := SPARKNaCl.N32 (PL);
         C   : Byte_Seq (0 .. N - 1);
         M   : Byte_Seq (0 .. N - 1);
         Tag : Bytes_16 := (others => 0);
         Non : Core.ChaCha20_IETF_Nonce := (others => 0);
         Kc  : Core.ChaCha20_Key := Make_Key (Key);
         AAD : constant Byte_Seq (0 .. 0) := (0 => AAD_Tag);
         Status : Boolean;
      begin
         for I in 1 .. Nonce_Len loop
            Non (SPARKNaCl.N32 (I - 1)) := To_SN (Blob (I));
         end loop;
         for I in 1 .. Tag_Len loop
            Tag (SPARKNaCl.N32 (I - 1)) := To_SN (Blob (Nonce_Len + I));
         end loop;
         --  Iterate C's own index so SPARK sees every element initialised.
         for I in 0 .. N - 1 loop
            C (I) := To_SN (Blob (Overhead + 1 + Natural (I)));
         end loop;

         SPARKNaCl.Secretbox.Open (M, Status, Tag, C, Non, Kc, AAD);

         if Status then
            for I in 1 .. PL loop
               Plain (I) := To_U8 (M (SPARKNaCl.N32 (I - 1)));
            end loop;
            Plain_Len := PL;
            Ok := True;
         end if;
      end;
   end Open;

end Secure;
