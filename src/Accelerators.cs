// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Security.Cryptography;

namespace Nethermind.Zkvm.Abstractions;

/// <summary>
/// Provides <see href="https://github.com/eth-act/zkvm-standards/tree/main/standards/c-interface-accelerators">
/// zkVM cryptographic accelerators.
/// </see>
/// </summary>
public static partial class Accelerators
{
    /// <summary>
    /// Computes the hash of data using the Keccak-256 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value.</param>
    /// <exception cref="ArgumentOutOfRangeException">Output buffer must be 32 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Keccak256(ReadOnlySpan<byte> data, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 32, nameof(output));

        zkvm_status status = zkvm_keccak256(data, (nuint)data.Length, output);

        ThrowIfFailed(status, nameof(zkvm_keccak256));
    }

    /// <summary>
    /// Computes the hash of data using the RIPEMD-160 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value.</param>
    /// <exception cref="ArgumentOutOfRangeException">Output buffer must be 32 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Ripemd160(ReadOnlySpan<byte> data, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 32, nameof(output));

        zkvm_status status = zkvm_ripemd160(data, (nuint)data.Length, output);

        ThrowIfFailed(status, nameof(zkvm_ripemd160));
    }

    /// <summary>
    /// Computes the hash of data using the SHA-256 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value.</param>
    /// <exception cref="ArgumentOutOfRangeException">Output buffer must be 32 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Sha256(ReadOnlySpan<byte> data, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 32, nameof(output));

        zkvm_status status = zkvm_sha256(data, (nuint)data.Length, output);

        ThrowIfFailed(status, nameof(zkvm_sha256));
    }

    private static void ThrowIfFailed(zkvm_status status, string methodName)
    {
        if (status != zkvm_status.ZKVM_EOK)
            throw new CryptographicException($"{methodName} failed. Status: {status}");
    }
}
