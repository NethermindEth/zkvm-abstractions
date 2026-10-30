// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

#if ZISK
using System.Runtime.InteropServices;

namespace Nethermind.Zkvm.Abstractions;

public static partial class Accelerators
{
    // TODO: Remove when added to the zkVM standards: https://github.com/eth-act/zkvm-standards/issues/23
    // Two shapes of one import: behind the length check the Span stub costs fewer guest steps, and without it
    // the ref one does.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial void syscall_keccak_f(Span<ulong> state);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static partial void syscall_keccak_f(ref ulong state);

    // Since ZisK v1.4.0 the precompile takes the state and the input directly, with no parameter block.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void syscall_sha256_f(ulong* state, ulong* input);

    // ZisK's 256-bit arithmetic precompiles themselves. Each takes the address of its operand block, which a JIT
    // that lists the import in JitZkCsrPInvokes emits as the CSR write rather than a call.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void syscall_arith256(Arith256Parameters* parameters);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void syscall_arith256_mod(Arith256ModParameters* parameters);

    // ZisK's EVM JUMPDEST bitmap precompile, a csrs/add pair the transpiler fuses only while they are adjacent.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void zkvm_jump_dest_bitmap(ulong* bitmap, byte* code, nuint length);

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

    // ZisK runs the C library's memmove, memset and memcmp as DMA precompiles. Pointers rather than refs:
    // ref arguments make the stub pin them in a stack frame.
    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void* memmove(void* dest, void* src, nuint n);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial void* memset(void* s, int c, nuint n);

    [LibraryImport("__Internal")]
    [SuppressGCTransition]
    private static unsafe partial int memcmp(void* s1, void* s2, nuint n);
}
#endif
