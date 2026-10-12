// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

#if ZISK
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

namespace Nethermind.Zkvm.Abstractions;

public static partial class Accelerators
{
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
}
#endif
