// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

#pragma warning disable IDE1006 // Naming Styles

using System.Runtime.InteropServices;

namespace Nethermind.Zkvm.Abstractions;

public static partial class Accelerators
{
    private enum zkvm_status
    {
        ZKVM_EOK = 0,
        ZKVM_EFAIL = -1
    }

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_blake2f(
        uint rounds,
        Span<byte> h,
        ReadOnlySpan<byte> m,
        ReadOnlySpan<byte> t,
        byte f
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_bn254_g1_add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_bn254_g1_mul(
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> scalar,
        Span<byte> result
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_bn254_pairing(
        ReadOnlySpan<byte> pairs,
        nuint num_pairs,
        [MarshalAs(UnmanagedType.U1)] ref bool verified
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_keccak256(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_kzg_point_eval(
        ReadOnlySpan<byte> commitment,
        ReadOnlySpan<byte> z,
        ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> proof,
        [MarshalAs(UnmanagedType.U1)] ref bool verified
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_modexp(
        ReadOnlySpan<byte> @base,
        nuint base_len,
        ReadOnlySpan<byte> exp,
        nuint exp_len,
        ReadOnlySpan<byte> modulus,
        nuint mod_len,
        Span<byte> output
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_ripemd160(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_secp256k1_ecrecover(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        byte recid,
        Span<byte> output
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_secp256k1_verify(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        ReadOnlySpan<byte> pubkey,
        [MarshalAs(UnmanagedType.U1)] ref bool verified
    );

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_sha256(ReadOnlySpan<byte> data, nuint len, Span<byte> output);
}
