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

    //private unsafe struct zkvm_bytes_32
    //{
    //    public fixed byte data[32];
    //}

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_keccak256(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_ripemd160(ReadOnlySpan<byte> data, nuint len, Span<byte> output);

    [LibraryImport("__Internal")]
    private static partial zkvm_status zkvm_sha256(ReadOnlySpan<byte> data, nuint len, Span<byte> output);
}
