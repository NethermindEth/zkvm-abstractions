// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Runtime.InteropServices;

namespace Nethermind.Zkvm.Abstractions;

public static partial class Accelerators
{
    // Every routine here runs to completion on the guest's only thread and never calls back into managed code,
    // so the GC transition would only add a frame and callee-saved register spills around each call.

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_blake2f(
        uint rounds,
        Span<byte> h,
        ReadOnlySpan<byte> m,
        ReadOnlySpan<byte> t,
        byte f
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_g1_add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_g1_msm(
        ReadOnlySpan<byte> pairs,
        nuint num_pairs,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_g2_add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_g2_msm(
        ReadOnlySpan<byte> pairs,
        nuint num_pairs,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_map_fp_to_g1(
        ReadOnlySpan<byte> field_element,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_map_fp2_to_g2(
        ReadOnlySpan<byte> field_element,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bls12_pairing(
        ReadOnlySpan<byte> pairs,
        nuint num_pairs,
        [MarshalAs(UnmanagedType.U1)] out bool verified
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bn254_g1_add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bn254_g1_mul(
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> scalar,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_bn254_pairing(
        ReadOnlySpan<byte> pairs,
        nuint num_pairs,
        [MarshalAs(UnmanagedType.U1)] out bool verified
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_keccak256(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_kzg_point_eval(
        ReadOnlySpan<byte> commitment,
        ReadOnlySpan<byte> z,
        ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> proof,
        [MarshalAs(UnmanagedType.U1)] out bool verified
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_modexp(
        ReadOnlySpan<byte> @base,
        nuint base_len,
        ReadOnlySpan<byte> exp,
        nuint exp_len,
        ReadOnlySpan<byte> modulus,
        nuint mod_len,
        Span<byte> output
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_ripemd160(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_secp256k1_ecrecover(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        byte recid,
        Span<byte> output
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_secp256k1_verify(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        ReadOnlySpan<byte> pubkey,
        [MarshalAs(UnmanagedType.U1)] out bool verified
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_secp256r1_verify(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        ReadOnlySpan<byte> pubkey,
        [MarshalAs(UnmanagedType.U1)] out bool verified
    );

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial Status zkvm_sha256(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

#if ZISK
    // TODO: Remove when added to the zkVM standards: https://github.com/eth-act/zkvm-standards/issues/23
    // Two shapes of one import: behind the length check the Span stub costs fewer guest steps, and without it
    // the ref one does.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial void syscall_keccak_f(Span<ulong> state);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial void syscall_keccak_f(ref ulong state);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void syscall_sha256_f(Sha256FParameters* parameters);

    /// <summary>
    /// The operand block <c>syscall_sha256_f</c> reads through its single pointer argument.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    private unsafe struct Sha256FParameters
    {
        public ulong* State;
        public ulong* Block;
    }

    // ZisK's 256-bit arithmetic on its arith256 precompiles, which the zkVM standards do not cover.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void add_mod256_c(ulong* a, ulong* b, ulong* modulus, ulong* result);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void div_rem256_c(ulong* a, ulong* b, ulong* quotient, ulong* remainder);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void mul_mod256_c(ulong* a, ulong* b, ulong* modulus, ulong* result);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void reduce_mod256_c(ulong* a, ulong* modulus, ulong* result);

    // ZisK runs the C library's memmove as a precompile.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial void memmove(ref byte dest, ref readonly byte src, nuint n);
#endif
}
