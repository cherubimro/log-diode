--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Secure -- authenticated encryption of a diode payload.
--
--  Wraps SPARKNaCl's AEAD (ChaCha20-Poly1305, RFC 8439) so the OPC UA bytes
--  are unreadable and tamper-evident on the wire.  Encryption sits ABOVE the
--  relay: Seal turns a NetworkMessage into a self-describing blob that the relay
--  then fragments and erasure-codes; Open reverses it after reassembly.  The
--  16-byte Poly1305 tag means a modified or forged payload is REJECTED, not
--  decoded -- integrity on a link with no feedback.
--
--  Blob layout (all bytes):
--     [ nonce : 12 ][ tag : 16 ][ ciphertext : plaintext_len ]
--  so a blob is exactly Overhead (28) bytes longer than its plaintext.
--
--  This is proven SPARK.  The cryptography itself is SPARKNaCl (BSD, separately
--  proven); this module only marshals bytes and discharges SPARKNaCl's
--  preconditions.

with Wire_Types; use Wire_Types;

package Secure with SPARK_Mode => On is

   Key_Len   : constant := 32;   --  ChaCha20 key
   Nonce_Len : constant := 12;   --  IETF nonce
   Tag_Len   : constant := 16;   --  Poly1305 tag
   Overhead  : constant := Nonce_Len + Tag_Len;   --  28

   Max_Plain : constant := 65536;   --  a full UADP NetworkMessage
   Max_Blob  : constant := Max_Plain + Overhead;

   type Key_Bytes    is array (1 .. Key_Len)   of U8;
   type Nonce_Bytes  is array (1 .. Nonce_Len) of U8;
   type Plain_Buffer is array (1 .. Max_Plain) of U8;
   type Blob_Buffer  is array (1 .. Max_Blob)  of U8;

   subtype Plain_Len_T is Natural range 0 .. Max_Plain;
   subtype Blob_Len_T  is Natural range 0 .. Max_Blob;

   --  Seal Plain (1 .. Plain_Len) under Key with the given 12-byte Nonce (which
   --  MUST be unique per key -- the caller derives it from stream + msg_seq +
   --  a per-run random).  The blob is Blob (1 .. Blob_Len).
   procedure Seal
     (Plain     : Plain_Buffer;
      Plain_Len : Plain_Len_T;
      Key       : Key_Bytes;
      Nonce     : Nonce_Bytes;
      Blob      : out Blob_Buffer;
      Blob_Len  : out Blob_Len_T)
     with Pre  => Plain_Len >= 1,
          Post => Blob_Len = Plain_Len + Overhead;

   --  Open a blob.  Ok is True only if the tag verifies -- a wrong key or any
   --  tampering yields Ok => False and no plaintext.
   procedure Open
     (Blob      : Blob_Buffer;
      Blob_Len  : Blob_Len_T;
      Key       : Key_Bytes;
      Plain     : out Plain_Buffer;
      Plain_Len : out Plain_Len_T;
      Ok        : out Boolean);

end Secure;
