--  SPDX-License-Identifier: AGPL-3.0-or-later
--  Copyright (C) 2026 Alin Anton
--
--  Reed-Solomon erasure code body.  Everything here is bounded: the matrices
--  are at most Max_K x 2*Max_K (72 x 144) bytes, every loop is bounded by K, M or
--  Len, and the only field operations are Gf256.Mul / Inv / xor -- all proved
--  free of run-time errors in gf256.adb.  So the entire proof obligation here
--  is index bounds, which follow from the K, M <= Max_* preconditions.

with Rs_Matrix;
with Wire_Types;

package body Rs with SPARK_Mode => On is

   use type Wire_Types.U8;

   --  Generator row of the fragment in slot S, for a code with K data columns
   --  and M parity rows.  Data slot (S <= K): the unit vector e_S -- data
   --  passes through verbatim.  Parity slot (S > K): row S-K of Cauchy, and
   --  1 <= S-K <= M <= Max_M makes that index provably valid.
   function Gen (S : Slot_Range; Col : K_Range; K : K_Range; M : M_Range)
      return Byte
     with Pre => Col <= K and then S <= K + M
   is
   begin
      if S <= K then
         return (if S = Col then 1 else 0);
      else
         --  S > K and S <= K+M, so 1 <= S-K <= M <= Max_M: a valid Cauchy row.
         return Rs_Matrix.Cauchy (S - K, Col);
      end if;
   end Gen;

   ------------
   -- Encode --
   ------------

   procedure Encode
     (K   : K_Range;
      M   : M_Range;
      Len : Frag_Len;
      Frags : in out Frag_Array)
   is
   begin
      --  parity_i(b) = sum_j Cauchy(i,j) * data_j(b)   over GF(2^8)
      for I in 1 .. M loop
         pragma Loop_Invariant (I <= M);
         for B in 1 .. Len loop
            declare
               Acc : Byte := 0;
            begin
               for J in 1 .. K loop
                  pragma Loop_Invariant (J <= K);
                  Acc := Acc xor Mul (Rs_Matrix.Cauchy (I, J), Frags (J) (B));
               end loop;
               Frags (K + I) (B) := Acc;
            end;
         end loop;
      end loop;
   end Encode;

   ------------
   -- Decode --
   ------------

   procedure Decode
     (K       : K_Range;
      M       : M_Range;
      Len     : Frag_Len;
      Present : Present_Array;
      Frags   : in out Frag_Array;
      Ok      : out Boolean)
   is
      --  Only slots 1 .. K+M are real fragments of this code.
      Last_Slot : constant Slot_Range := K + M;

      --  The K surviving fragments we solve from, in slot order.  Every entry
      --  is a valid slot of THIS code, i.e. in 1 .. K+M.
      Sel   : array (K_Range) of Slot_Range := (others => 1);
      N_Sel : Natural := 0;

      --  Augmented [A | I]: A is the KxK generator submatrix of the survivors,
      --  and Gauss-Jordan turns the left half into I and the right half into
      --  A^-1.  Width is 2*Max_K.
      subtype Aug_Col is Positive range 1 .. 2 * Max_K;
      Aug : array (K_Range, Aug_Col) of Byte := (others => (others => 0));

      Missing_Data : Boolean := False;
   begin
      Ok := False;

      --  Need at least K survivors; take the first K in slot order.  Iterate
      --  only real slots (1 .. K+M) so every Sel entry satisfies Sel <= K+M --
      --  which is what makes the Cauchy row index in Gen provably in range.
      for S in 1 .. Last_Slot loop
         pragma Loop_Invariant (N_Sel <= Max_K);
         pragma Loop_Invariant
           (for all R in 1 .. N_Sel => Sel (R) <= Last_Slot);
         if Present (S) and then N_Sel < K then
            N_Sel := N_Sel + 1;
            Sel (N_Sel) := S;
         end if;
         if S <= K and then not Present (S) then
            Missing_Data := True;
         end if;
      end loop;

      if N_Sel < K then
         return;                    --  fewer than K arrived: unrecoverable
      end if;

      --  Systematic shortcut: if every data fragment arrived, we are done.
      if not Missing_Data then
         Ok := True;
         return;
      end if;

      --  Build [A | I].  Sel (R) <= K+M (established above), so Gen's
      --  precondition holds and its Cauchy index is in range.
      for R in 1 .. K loop
         pragma Loop_Invariant (R <= Max_K);
         pragma Loop_Invariant
           (for all T in 1 .. N_Sel => Sel (T) <= Last_Slot);
         for C in 1 .. K loop
            pragma Loop_Invariant (C <= Max_K);
            Aug (R, C) := Gen (Sel (R), C, K, M);
         end loop;
         Aug (R, K + R) := 1;
      end loop;

      --  Gauss-Jordan elimination on the left half.
      for Col in 1 .. K loop
         pragma Loop_Invariant (Col <= Max_K);

         --  Find a pivot row >= Col with a non-zero entry in this column.
         declare
            Pivot : Natural := 0;
         begin
            for R in Col .. K loop
               pragma Loop_Invariant (Pivot <= Max_K);
               if Pivot = 0 and then Aug (R, Col) /= 0 then
                  Pivot := R;
               end if;
            end loop;

            --  A Cauchy submatrix is always invertible, so a pivot always
            --  exists.  SPARK cannot know that theorem, so we treat its
            --  absence as a decode failure rather than assume it away.
            if Pivot = 0 then
               return;
            end if;

            --  Swap Pivot into place.
            if Pivot /= Col then
               for C in Aug_Col loop
                  declare
                     T : constant Byte := Aug (Col, C);
                  begin
                     Aug (Col, C) := Aug (Pivot, C);
                     Aug (Pivot, C) := T;
                  end;
               end loop;
            end if;
         end;

         --  Normalise the pivot row so Aug (Col, Col) becomes 1.
         declare
            Piv : constant Byte := Aug (Col, Col);
         begin
            if Piv = 0 then
               return;              --  cannot happen after pivoting; guards Inv
            end if;
            declare
               IP : constant Byte := Inv (Piv);
            begin
               for C in Aug_Col loop
                  Aug (Col, C) := Mul (Aug (Col, C), IP);
               end loop;
            end;
         end;

         --  Eliminate this column from every other row.
         for R in 1 .. K loop
            pragma Loop_Invariant (R <= Max_K);
            if R /= Col and then Aug (R, Col) /= 0 then
               declare
                  F : constant Byte := Aug (R, Col);
               begin
                  for C in Aug_Col loop
                     Aug (R, C) := Aug (R, C) xor Mul (F, Aug (Col, C));
                  end loop;
               end;
            end if;
         end loop;
      end loop;

      --  The right half is now A^-1.  Reconstruct each MISSING data fragment:
      --    data_i(b) = sum_r A^-1(i,r) * survivor_r(b)
      --  Present data fragments are already correct and left untouched.
      for B in 1 .. Len loop
         pragma Loop_Invariant (B <= Max_Len);
         for I in 1 .. K loop
            pragma Loop_Invariant (I <= Max_K);
            if not Present (I) then
               declare
                  Acc : Byte := 0;
               begin
                  for R in 1 .. K loop
                     pragma Loop_Invariant (R <= Max_K);
                     Acc := Acc xor Mul (Aug (I, K + R), Frags (Sel (R)) (B));
                  end loop;
                  Frags (I) (B) := Acc;
               end;
            end if;
         end loop;
      end loop;

      Ok := True;
   end Decode;

end Rs;
