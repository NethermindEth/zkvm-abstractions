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
    /// Computes <c>(base^exp) % modulus</c> for arbitrary precision integers.
    /// </summary>
    /// <param name="base">The base, in bytes.</param>
    /// <param name="exp">The exponent value, in bytes.</param>
    /// <param name="modulus">The modulus, in bytes.</param>
    /// <param name="output">The buffer to receive the result value.</param>
    /// <exception cref="ArgumentOutOfRangeException">Output buffer length must be equal to <c>modulus</c> length.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void ModExp(
        ReadOnlySpan<byte> @base,
        ReadOnlySpan<byte> exp,
        ReadOnlySpan<byte> modulus,
        Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, modulus.Length, nameof(output));

        zkvm_status status = zkvm_modexp(
            @base,
            (nuint)@base.Length,
            exp,
            (nuint)exp.Length,
            modulus,
            (nuint)modulus.Length,
            output
        );

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
    /// Recovers public key from signature.
    /// </summary>
    /// <param name="msg">The message hash.</param>
    /// <param name="sig">The signature <c>(r || s)</c>.</param>
    /// <param name="recid">The recovery id.</param>
    /// <param name="output">The buffer to receive the public key.</param>
    /// <exception cref="ArgumentOutOfRangeException"><c>msg</c> must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><c>sig</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><c>output</c> must be 64 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void SecP256k1ECRecover(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        byte recid,
        Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(msg.Length, 32, nameof(msg));
        ArgumentOutOfRangeException.ThrowIfNotEqual(sig.Length, 64, nameof(sig));
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 64, nameof(output));

        zkvm_status status = zkvm_secp256k1_ecrecover(msg, sig, recid, output);

        ThrowIfFailed(status, nameof(zkvm_secp256k1_ecrecover));
    }

    /// <summary>
    /// Verifies an ECDSA signature on the SecP256k1 curve.
    /// </summary>
    /// <param name="msg">The message hash.</param>
    /// <param name="sig">The signature <c>(r || s)</c>.</param>
    /// <param name="pubkey">The uncompressed public key <c>(x || y)</c>.</param>
    /// <returns><c>true</c> if signature is valid; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException"><c>msg</c> must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><c>sig</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException"><c>pubkey</c> must be 64 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static bool SecP256k1Verify(ReadOnlySpan<byte> msg, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> pubkey)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(msg.Length, 32, nameof(msg));
        ArgumentOutOfRangeException.ThrowIfNotEqual(sig.Length, 64, nameof(sig));
        ArgumentOutOfRangeException.ThrowIfNotEqual(pubkey.Length, 64, nameof(pubkey));

        var verified = false;

        zkvm_status status = zkvm_secp256k1_verify(msg, sig, pubkey, ref verified);

        ThrowIfFailed(status, nameof(zkvm_secp256k1_verify));

        return verified;
    }

    /// <summary>
    /// Computes the hash of data using the SHA-256 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value:
    /// first 20 bytes contain the hash; remaining 12 bytes are zero-filled.
    /// </param>
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
