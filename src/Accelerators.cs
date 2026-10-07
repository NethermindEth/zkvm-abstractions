// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

namespace Nethermind.Zkvm.Abstractions;

/// <summary>
/// Provides <see href="https://github.com/eth-act/zkvm-standards/tree/main/standards/c-interface-accelerators">
/// zkVM cryptographic accelerators</see>.
/// </summary>
public static partial class Accelerators
{
    /// <summary>
    /// Performs BLAKE2f compression.
    /// </summary>
    /// <param name="rounds">The number of rounds.</param>
    /// <param name="state">The state vector.</param>
    /// <param name="message">The message block.</param>
    /// <param name="offset">The offset counters.</param>
    /// <param name="finalBlock">The final block indicator.</param>
    /// <exception cref="ArgumentOutOfRangeException">The <c>state</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>message</c> must be 128 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>offset</c> must be 16 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Blake2F(
        uint rounds,
        Span<byte> state,
        ReadOnlySpan<byte> message,
        ReadOnlySpan<byte> offset,
        byte finalBlock)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(state.Length, 64, nameof(state));
        ArgumentOutOfRangeException.ThrowIfNotEqual(message.Length, 128, nameof(message));
        ArgumentOutOfRangeException.ThrowIfNotEqual(offset.Length, 16, nameof(offset));

        Status status = zkvm_blake2f(rounds, state, message, offset, finalBlock);

        ThrowIfFailed(status, nameof(zkvm_blake2f));
    }

    /// <summary>
    /// Performs BLS12-381 G1 point addition.
    /// </summary>
    /// <param name="p1">The first point <c>(x || y)</c>.</param>
    /// <param name="p2">The second point <c>(x || y)</c>.</param>
    /// <param name="result">The resulting point <c>(x || y)</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>p1</c> must be 96 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>p2</c> must be 96 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 96 bytes long.</exception>
    public static Status Bls12381G1Add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(p1.Length, 96, nameof(p1));
        ArgumentOutOfRangeException.ThrowIfNotEqual(p2.Length, 96, nameof(p2));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 96, nameof(result));

        return zkvm_bls12_g1_add(p1, p2, result);
    }

    /// <summary>
    /// Performs BLS12-381 G1 multi-scalar multiplication.
    /// </summary>
    /// <param name="pairs">The array of point-scalar pairs.</param>
    /// <param name="numPairs">The number of point-scalar pairs.</param>
    /// <param name="result">The resulting point.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>pairs</c> must be <c>128 * numPairs</c> bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 96 bytes long.</exception>
    public static Status Bls12381G1Msm(ReadOnlySpan<byte> pairs, nuint numPairs, Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual((uint)pairs.Length, 128 * numPairs, nameof(pairs));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 96, nameof(result));

        return zkvm_bls12_g1_msm(pairs, numPairs, result);
    }

    /// <summary>
    /// Performs BLS12-381 G2 point addition.
    /// </summary>
    /// <param name="p1">The first point <c>(x || y)</c>.</param>
    /// <param name="p2">The second point <c>(x || y)</c>.</param>
    /// <param name="result">The resulting point <c>(x || y)</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>p1</c> must be 192 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>p2</c> must be 192 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 192 bytes long.</exception>
    public static Status Bls12381G2Add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(p1.Length, 192, nameof(p1));
        ArgumentOutOfRangeException.ThrowIfNotEqual(p2.Length, 192, nameof(p2));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 192, nameof(result));

        return zkvm_bls12_g2_add(p1, p2, result);
    }

    /// <summary>
    /// Performs BLS12-381 G2 multi-scalar multiplication.
    /// </summary>
    /// <param name="pairs">The array of point-scalar pairs.</param>
    /// <param name="numPairs">The number of point-scalar pairs.</param>
    /// <param name="result">The resulting point.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>pairs</c> must be <c>224 * numPairs</c> bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 192 bytes long.</exception>
    public static Status Bls12381G2Msm(ReadOnlySpan<byte> pairs, nuint numPairs, Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual((uint)pairs.Length, 224 * numPairs, nameof(pairs));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 192, nameof(result));

        return zkvm_bls12_g2_msm(pairs, numPairs, result);
    }

    /// <summary>
    /// Checks if the BLS12-381 pairing equation holds for the given points.
    /// </summary>
    /// <param name="pairs">The array of G1-G2 point pairs.</param>
    /// <param name="numPairs">The number of point pairs.</param>
    /// <param name="verified"><c>true</c> if the pairing equation holds; otherwise, <c>false</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>pairs</c> must be <c>288 * numPairs</c> bytes long.</exception>
    public static Status Bls12381Pairing(ReadOnlySpan<byte> pairs, nuint numPairs, out bool verified)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual((uint)pairs.Length, 288 * numPairs, nameof(pairs));

        return zkvm_bls12_pairing(pairs, numPairs, out verified);
    }

    /// <summary>
    /// Maps a field element to a BLS12-381 G1 point.
    /// </summary>
    /// <param name="fieldElement">The Fp element.</param>
    /// <param name="result">The resulting point <c>(x || y)</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>fieldElement</c> must be 48 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 96 bytes long.</exception>
    public static Status Bls12381MapFpToG1(ReadOnlySpan<byte> fieldElement, Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(fieldElement.Length, 48, nameof(fieldElement));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 96, nameof(result));

        return zkvm_bls12_map_fp_to_g1(fieldElement, result);
    }

    /// <summary>
    /// Maps a field element to a BLS12-381 G2 point.
    /// </summary>
    /// <param name="fieldElement">The Fp2 element.</param>
    /// <param name="result">The resulting point <c>(x || y)</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>fieldElement</c> must be 96 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 192 bytes long.</exception>
    public static Status Bls12381MapFp2ToG2(ReadOnlySpan<byte> fieldElement, Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(fieldElement.Length, 96, nameof(fieldElement));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 192, nameof(result));

        return zkvm_bls12_map_fp2_to_g2(fieldElement, result);
    }

    /// <summary>
    /// Performs BN254 G1 point addition.
    /// </summary>
    /// <param name="p1">The first point <c>(x || y)</c>.</param>
    /// <param name="p2">The second point <c>(x || y)</c>.</param>
    /// <param name="result">The resulting point <c>(x || y)</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>p1</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>p2</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 64 bytes long.</exception>
    public static Status BN254G1Add(
        ReadOnlySpan<byte> p1,
        ReadOnlySpan<byte> p2,
        Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(p1.Length, 64, nameof(p1));
        ArgumentOutOfRangeException.ThrowIfNotEqual(p2.Length, 64, nameof(p2));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 64, nameof(result));

        return zkvm_bn254_g1_add(p1, p2, result);
    }

    /// <summary>
    /// Performs BN254 G1 scalar multiplication.
    /// </summary>
    /// <param name="point">The input point <c>(x || y)</c>.</param>
    /// <param name="scalar">The scalar.</param>
    /// <param name="result">The resulting point <c>(x || y)</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>point</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>scalar</c> must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>result</c> must be 64 bytes long.</exception>
    public static Status BN254G1Mul(
        ReadOnlySpan<byte> point,
        ReadOnlySpan<byte> scalar,
        Span<byte> result)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(point.Length, 64, nameof(point));
        ArgumentOutOfRangeException.ThrowIfNotEqual(scalar.Length, 32, nameof(scalar));
        ArgumentOutOfRangeException.ThrowIfNotEqual(result.Length, 64, nameof(result));

        return zkvm_bn254_g1_mul(point, scalar, result);
    }

    /// <summary>
    /// Checks if the BN254 pairing equation holds for the given points.
    /// </summary>
    /// <param name="pairs">The array of G1-G2 point pairs.</param>
    /// <param name="numPairs">The number of point pairs.</param>
    /// <param name="verified"><c>true</c> if the pairing equation holds; otherwise, <c>false</c>.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>pairs</c> buffer must be <c>192 * numPairs</c> bytes long.</exception>
    public static Status BN254Pairing(ReadOnlySpan<byte> pairs, nuint numPairs, out bool verified)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual((uint)pairs.Length, 192 * numPairs, nameof(pairs));

        return zkvm_bn254_pairing(pairs, numPairs, out verified);
    }

    /// <summary>
    /// Computes the hash of data using the Keccak-256 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value.</param>
    /// <exception cref="ArgumentOutOfRangeException">The <c>output</c> must be 32 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Keccak256(ReadOnlySpan<byte> data, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 32, nameof(output));

        Status status = zkvm_keccak256(data, (nuint)data.Length, output);

        ThrowIfFailed(status, nameof(zkvm_keccak256));
    }

    /// <summary>
    /// Verifies a KZG proof for point evaluation.
    /// </summary>
    /// <param name="commitment">The KZG commitment.</param>
    /// <param name="z">The evaluation point.</param>
    /// <param name="y">The claimed evaluation.</param>
    /// <param name="proof">The KZG proof.</param>
    /// <returns><c>true</c> if the proof is valid; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>commitment</c> buffer must be 48 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>z</c> buffer must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>y</c> buffer must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>proof</c> buffer must be 48 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static bool KzgPointEval(
        ReadOnlySpan<byte> commitment,
        ReadOnlySpan<byte> z,
        ReadOnlySpan<byte> y,
        ReadOnlySpan<byte> proof)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(commitment.Length, 48, nameof(commitment));
        ArgumentOutOfRangeException.ThrowIfNotEqual(z.Length, 32, nameof(z));
        ArgumentOutOfRangeException.ThrowIfNotEqual(y.Length, 32, nameof(y));
        ArgumentOutOfRangeException.ThrowIfNotEqual(proof.Length, 48, nameof(proof));

        Status status = zkvm_kzg_point_eval(commitment, z, y, proof, out bool verified);

        ThrowIfFailed(status, nameof(zkvm_kzg_point_eval));

        return verified;
    }

    /// <summary>
    /// Computes <c>(base^exp) % modulus</c> for arbitrary precision integers.
    /// </summary>
    /// <param name="base">The base, in bytes.</param>
    /// <param name="exp">The exponent value, in bytes.</param>
    /// <param name="modulus">The modulus, in bytes.</param>
    /// <param name="output">The buffer to receive the result value.</param>
    /// <exception cref="ArgumentOutOfRangeException">The <c>output</c> length must be equal to the <c>modulus</c> length.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void ModExp(
        ReadOnlySpan<byte> @base,
        ReadOnlySpan<byte> exp,
        ReadOnlySpan<byte> modulus,
        Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, modulus.Length, nameof(output));

        Status status = zkvm_modexp(
            @base,
            (nuint)@base.Length,
            exp,
            (nuint)exp.Length,
            modulus,
            (nuint)modulus.Length,
            output
        );

        ThrowIfFailed(status, nameof(zkvm_modexp));
    }

    /// <summary>
    /// Computes the hash of data using the RIPEMD-160 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value (20-byte hash, right-aligned in a 32-byte buffer).</param>
    /// <exception cref="ArgumentOutOfRangeException">The <c>output</c> must be 32 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Ripemd160(ReadOnlySpan<byte> data, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 32, nameof(output));

        Status status = zkvm_ripemd160(data, (nuint)data.Length, output);

        ThrowIfFailed(status, nameof(zkvm_ripemd160));
    }

    /// <summary>
    /// Recovers public key from signature.
    /// </summary>
    /// <param name="msg">The message hash.</param>
    /// <param name="sig">The signature <c>(r || s)</c>.</param>
    /// <param name="recid">The recovery id.</param>
    /// <param name="output">The buffer to receive the public key.</param>
    /// <returns>The status of the operation.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>msg</c> must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>sig</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>output</c> must be 64 bytes long.</exception>
    public static Status SecP256k1Recover(
        ReadOnlySpan<byte> msg,
        ReadOnlySpan<byte> sig,
        byte recid,
        Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(msg.Length, 32, nameof(msg));
        ArgumentOutOfRangeException.ThrowIfNotEqual(sig.Length, 64, nameof(sig));
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 64, nameof(output));

        return zkvm_secp256k1_ecrecover(msg, sig, recid, output);
    }

    /// <summary>
    /// Verifies an ECDSA signature on the SecP256k1 curve.
    /// </summary>
    /// <param name="msg">The message hash.</param>
    /// <param name="sig">The signature <c>(r || s)</c>.</param>
    /// <param name="pubkey">The uncompressed public key <c>(x || y)</c>.</param>
    /// <returns><c>true</c> if signature is valid; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>msg</c> must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>sig</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>pubkey</c> must be 64 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static bool SecP256k1Verify(ReadOnlySpan<byte> msg, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> pubkey)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(msg.Length, 32, nameof(msg));
        ArgumentOutOfRangeException.ThrowIfNotEqual(sig.Length, 64, nameof(sig));
        ArgumentOutOfRangeException.ThrowIfNotEqual(pubkey.Length, 64, nameof(pubkey));

        Status status = zkvm_secp256k1_verify(msg, sig, pubkey, out bool verified);

        ThrowIfFailed(status, nameof(zkvm_secp256k1_verify));

        return verified;
    }

    /// <summary>
    /// Verifies an ECDSA signature on the SecP256r1 curve.
    /// </summary>
    /// <param name="msg">The message hash.</param>
    /// <param name="sig">The signature <c>(r || s)</c>.</param>
    /// <param name="pubkey">The uncompressed public key <c>(x || y)</c>.</param>
    /// <returns><c>true</c> if signature is valid; otherwise, <c>false</c>.</returns>
    /// <exception cref="ArgumentOutOfRangeException">The <c>msg</c> must be 32 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>sig</c> must be 64 bytes long.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The <c>pubkey</c> must be 64 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static bool SecP256r1Verify(ReadOnlySpan<byte> msg, ReadOnlySpan<byte> sig, ReadOnlySpan<byte> pubkey)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(msg.Length, 32, nameof(msg));
        ArgumentOutOfRangeException.ThrowIfNotEqual(sig.Length, 64, nameof(sig));
        ArgumentOutOfRangeException.ThrowIfNotEqual(pubkey.Length, 64, nameof(pubkey));

        Status status = zkvm_secp256r1_verify(msg, sig, pubkey, out bool verified);

        ThrowIfFailed(status, nameof(zkvm_secp256r1_verify));

        return verified;
    }

    /// <summary>
    /// Computes the hash of data using the SHA-256 algorithm.
    /// </summary>
    /// <param name="data">The data to hash.</param>
    /// <param name="output">The buffer to receive the hash value.</param>
    /// <exception cref="ArgumentOutOfRangeException">The <c>output</c> must be 32 bytes long.</exception>
    /// <exception cref="CryptographicException">Operation failed.</exception>
    public static void Sha256(ReadOnlySpan<byte> data, Span<byte> output)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(output.Length, 32, nameof(output));

        Status status = zkvm_sha256(data, (nuint)data.Length, output);

        ThrowIfFailed(status, nameof(zkvm_sha256));
    }

#if ZISK
    /// <summary>
    /// Computes <c>(a + b) mod modulus</c> for 256-bit integers, with the sum taken over 257 bits.
    /// </summary>
    /// <param name="a">The first addend.</param>
    /// <param name="b">The second addend.</param>
    /// <param name="modulus">The modulus. A zero modulus gives zero.</param>
    /// <param name="result">The buffer to receive the result.</param>
    /// <remarks><inheritdoc cref="MulMod256" path="/remarks"/></remarks>
    public static unsafe void AddMod256(ulong* a, ulong* b, ulong* modulus, ulong* result) =>
        add_mod256_c(a, b, modulus, result);

    /// <summary>
    /// Computes <c>a / b</c> and <c>a mod b</c> for 256-bit integers.
    /// </summary>
    /// <param name="a">The dividend.</param>
    /// <param name="b">The divisor. It must not be zero: with a zero divisor the routine never returns.</param>
    /// <param name="quotient">The buffer to receive the quotient.</param>
    /// <param name="remainder">The buffer to receive the remainder.</param>
    /// <remarks>
    /// The quotient and remainder are hinted, then checked with one <c>arith256</c> precompile call:
    /// <c>quotient * b + remainder</c> must equal <paramref name="a"/> with a zero high word, and the
    /// remainder must be less than <paramref name="b"/>, so a prover cannot substitute another pair.
    /// <inheritdoc cref="MulMod256" path="/remarks"/>
    /// </remarks>
    public static unsafe void DivRem256(ulong* a, ulong* b, ulong* quotient, ulong* remainder) =>
        div_rem256_c(a, b, quotient, remainder);

    /// <summary>
    /// Performs the Keccak-f[1600] permutation on the given state.
    /// </summary>
    /// <param name="state">The state buffer.</param>
    /// <exception cref="ArgumentOutOfRangeException">The <c>state</c> must be 25 elements long.</exception>
    public static void KeccakF(Span<ulong> state)
    {
        ArgumentOutOfRangeException.ThrowIfNotEqual(state.Length, 25, nameof(state));

        syscall_keccak_f(state);
    }

    /// <summary>
    /// Performs the Keccak-f[1600] permutation in place on the 25 lanes starting at <paramref name="state"/>.
    /// </summary>
    /// <param name="state">The first of 25 contiguous state lanes.</param>
    /// <remarks>
    /// Unchecked counterpart of <see cref="KeccakF(Span{ulong})"/> for absorb loops that already hold the state:
    /// the caller guarantees 25 lanes are addressable from <paramref name="state"/>.
    /// </remarks>
    public static void KeccakF(ref ulong state) => syscall_keccak_f(ref state);

    /// <summary>
    /// Copies <paramref name="source"/> to the start of <paramref name="destination"/>; the two may overlap.
    /// </summary>
    /// <param name="source">The bytes to copy.</param>
    /// <param name="destination">The buffer to receive them.</param>
    /// <remarks>
    /// Calls ZisK's <c>memmove</c> precompile directly. Corelib's span copy reaches the same routine for longer runs,
    /// but through a wrapper that spills every callee-saved register. The spans are not pinned: the import suppresses
    /// the GC transition, so no GC can run between taking their addresses and the call returning.
    /// </remarks>
    /// <exception cref="ArgumentOutOfRangeException">The <c>destination</c> must be at least as long as <c>source</c>.</exception>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static void Memmove(ReadOnlySpan<byte> source, Span<byte> destination)
    {
        ArgumentOutOfRangeException.ThrowIfGreaterThan(source.Length, destination.Length, nameof(source));

        unsafe
        {
            memmove(
                Unsafe.AsPointer(ref MemoryMarshal.GetReference(destination)),
                Unsafe.AsPointer(ref MemoryMarshal.GetReference(source)),
                (nuint)source.Length);
        }
    }

    /// <summary>
    /// Copies <paramref name="length"/> bytes from <paramref name="source"/> to <paramref name="destination"/>;
    /// the two may overlap.
    /// </summary>
    /// <param name="destination">The buffer to receive the bytes.</param>
    /// <param name="source">The bytes to copy.</param>
    /// <param name="length">The number of bytes to copy.</param>
    /// <remarks>
    /// Unchecked counterpart of <see cref="Memmove(ReadOnlySpan{byte}, Span{byte})"/> for hot paths: the caller
    /// guarantees both buffers hold <paramref name="length"/> bytes, and that pointers into managed memory stay
    /// valid until the call returns. Raw pointers skip the stub that pins <c>ref</c> arguments in a stack frame.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Memmove(void* destination, void* source, nuint length) =>
        memmove(destination, source, length);

    /// <summary>
    /// Sets <paramref name="length"/> bytes at <paramref name="destination"/> to <paramref name="value"/>.
    /// </summary>
    /// <param name="destination">The buffer to fill.</param>
    /// <param name="value">The byte to fill it with.</param>
    /// <param name="length">The number of bytes to fill.</param>
    /// <remarks>
    /// Calls ZisK's <c>memset</c> precompile directly. Unchecked, with the caller's contract of
    /// <see cref="Memmove(void*, void*, nuint)"/>.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Memset(void* destination, byte value, nuint length) =>
        memset(destination, value, length);

    /// <summary>
    /// Computes <c>(a * b) mod modulus</c> for 256-bit integers, with the product taken over 512 bits.
    /// </summary>
    /// <param name="a">The multiplicand.</param>
    /// <param name="b">The multiplier.</param>
    /// <param name="modulus">The modulus. A zero modulus gives zero.</param>
    /// <param name="result">The buffer to receive the result.</param>
    /// <remarks>
    /// Every argument points to a 256-bit integer stored as four 64-bit limbs, least significant first. An
    /// output must not alias an input: ZisK takes them as Rust references, which it may assume never
    /// overlap. These take pointers rather than spans so that hot callers skip the length checks and pinning,
    /// and so that a caller shared with other zkVMs can hold them in <c>delegate*&lt;ulong*, ...&gt;</c> slots
    /// and use them only where ZisK installs them.
    /// </remarks>
    public static unsafe void MulMod256(ulong* a, ulong* b, ulong* modulus, ulong* result) =>
        mul_mod256_c(a, b, modulus, result);

    /// <summary>
    /// Computes <c>a mod modulus</c> for 256-bit integers.
    /// </summary>
    /// <param name="a">The value to reduce.</param>
    /// <param name="modulus">The modulus. A zero modulus gives zero.</param>
    /// <param name="result">The buffer to receive the result.</param>
    /// <remarks><inheritdoc cref="MulMod256" path="/remarks"/></remarks>
    public static unsafe void ReduceMod256(ulong* a, ulong* modulus, ulong* result) =>
        reduce_mod256_c(a, modulus, result);

    /// <summary>
    /// Performs the SHA-256 compression function on a state and one 64-byte block.
    /// </summary>
    /// <param name="state">The eight 32-bit state words, as four 64-bit lanes with the lower-indexed word in the low half.</param>
    /// <param name="block">The message block, as its 64 bytes in order.</param>
    /// <remarks>
    /// Both pointers must be 8-byte aligned, and <paramref name="block"/> may not overlap <paramref name="state"/>.
    /// Padding the message is up to the caller. Unchecked, like <see cref="KeccakF(ref ulong)"/>, as merkleization
    /// runs it twice per node.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Sha256F(ulong* state, ulong* block)
    {
        Sha256FParameters parameters = new() { State = state, Block = block };

        syscall_sha256_f(&parameters);
    }

    /// <summary>
    /// Performs the SHA-256 compression function on the state and block a parameter block points to.
    /// </summary>
    /// <param name="parameters">The parameter block. It is only read, so a caller may reuse it across calls.</param>
    /// <remarks>
    /// The contract of <see cref="Sha256F(ulong*, ulong*)"/> applies to the pointers in <paramref name="parameters"/>.
    /// For callers that compress several blocks into one state: they keep one parameter block and rewrite only
    /// <see cref="Sha256FParameters.Block"/> between calls, rather than have each call fill a fresh one.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Sha256F(Sha256FParameters* parameters) => syscall_sha256_f(parameters);

    /// <summary>
    /// The operand block ZisK's SHA-256 compression precompile reads through its single pointer argument.
    /// </summary>
    [StructLayout(LayoutKind.Sequential)]
    public unsafe struct Sha256FParameters
    {
        /// <summary>The state, as described on <see cref="Sha256F(ulong*, ulong*)"/>.</summary>
        public ulong* State;

        /// <summary>The message block, as described on <see cref="Sha256F(ulong*, ulong*)"/>.</summary>
        public ulong* Block;
    }
#endif

#if SP1
    /// <summary>
    /// Extends a SHA-256 message schedule: fills words 16 to 63 from the first sixteen.
    /// </summary>
    /// <param name="w">The 64-word schedule.</param>
    /// <remarks>
    /// Calls SP1's <c>sha256_extend</c> precompile. The schedule holds each 32-bit word, as SHA-256 reads it
    /// big-endian, in the low half of a 64-bit slot. Unchecked for hot paths: the caller guarantees 64 slots,
    /// 8-byte aligned.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Sha256Extend(ulong* w) => zkvm_sha256_extend(w);

    /// <summary>
    /// Performs the SHA-256 compression function on a state and one extended message schedule.
    /// </summary>
    /// <param name="w">The 64-word schedule, extended by <see cref="Sha256Extend"/>.</param>
    /// <param name="state">The eight 32-bit state words, updated in place.</param>
    /// <remarks>
    /// Calls SP1's <c>sha256_compress</c> precompile. Both buffers hold one word per 64-bit slot as described on
    /// <see cref="Sha256Extend"/>, 8-byte aligned and not overlapping. Padding the message is up to the caller.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void Sp1Sha256Compress(ulong* w, ulong* state) => zkvm_sha256_compress(w, state);

    /// <summary>
    /// Computes <c>x = (x * y) mod m</c> for 256-bit integers in place, with <c>m</c> the 256-bit integer that
    /// follows <paramref name="y"/>.
    /// </summary>
    /// <param name="x">The multiplicand, overwritten with the result.</param>
    /// <param name="y">The multiplier, immediately followed by the modulus. A zero modulus means 2^256.</param>
    /// <remarks>
    /// Calls SP1's <c>uint256_mulmod</c> precompile. Every integer is stored as four 64-bit limbs, least
    /// significant first, 8-byte aligned. Unchecked for hot paths: the caller guarantees 32 bytes at
    /// <paramref name="x"/> and 64 at <paramref name="y"/>, not overlapping.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void UInt256MulMod(ulong* x, ulong* y) => zkvm_uint256_mulmod(x, y);
#endif

#if OPENVM
    /// <summary>
    /// Computes <c>(a * b) mod 2^256</c>.
    /// </summary>
    /// <param name="result">The buffer to receive the result.</param>
    /// <param name="a">The multiplicand.</param>
    /// <param name="b">The multiplier.</param>
    /// <remarks>
    /// One instruction of OpenVM's bigint extension. Every argument points to a 256-bit integer stored as four
    /// 64-bit limbs, least significant first. Unchecked for hot paths: the caller guarantees 32 bytes at each
    /// pointer, 8-byte aligned. Both operands are read before the result is written, so
    /// <paramref name="result"/> may alias either.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void UInt256Mul(ulong* result, ulong* a, ulong* b) => zkvm_u256_mul(result, a, b);

    /// <summary>
    /// XORs <paramref name="len"/> bytes of <paramref name="input"/> into the Keccak-f[1600] state <paramref name="buffer"/>.
    /// </summary>
    /// <param name="buffer">The 25-lane state.</param>
    /// <param name="input">The bytes to absorb.</param>
    /// <param name="len">The number of bytes, at most the 136-byte rate: a longer run executes but fails to prove.</param>
    /// <remarks>
    /// One instruction of OpenVM's Keccak extension, the absorb step of a sponge without the permutation.
    /// Unchecked for hot paths: the caller guarantees both pointers are 8-byte aligned and hold
    /// <paramref name="len"/> bytes.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void KeccakXorin(ulong* buffer, byte* input, nuint len) => zkvm_keccak_xorin(buffer, input, len);

    /// <summary>
    /// Performs the SHA-256 compression function on a state and one 64-byte block.
    /// </summary>
    /// <param name="state">The eight 32-bit state words, as four 64-bit lanes with the lower-indexed word in the low half.</param>
    /// <param name="input">The message block, as its 64 bytes in order.</param>
    /// <param name="output">The buffer to receive the new state, in the layout of <paramref name="state"/>; it may alias <paramref name="state"/>.</param>
    /// <remarks>
    /// One instruction of OpenVM's SHA-2 extension. Every pointer must be 8-byte aligned. Padding the message is
    /// up to the caller.
    /// </remarks>
    [MethodImpl(MethodImplOptions.AggressiveInlining)]
    public static unsafe void OpenVmSha256Compress(ulong* state, ulong* input, ulong* output) => zkvm_sha256_compress(state, input, output);
#endif

    private static void ThrowIfFailed(Status status, string methodName)
    {
        if (status != Status.OK)
            throw new CryptographicException($"{methodName} failed. Status: {status}");
    }

    /// <summary>
    /// Represents the status of an accelerator operation.
    /// </summary>
    public enum Status // zkvm_status
    {
        /// <summary>
        /// The operation completed successfully.
        /// </summary>
        OK = 0, // ZKVM_EOK
        /// <summary>
        /// The operation failed.
        /// </summary>
        Fail = -1 // ZKVM_EFAIL
    }
}
