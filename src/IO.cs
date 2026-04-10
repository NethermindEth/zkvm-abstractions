// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

namespace Nethermind.Zkvm.Abstractions;

/// <summary>
/// Provides <see href="https://github.com/eth-act/zkvm-standards/tree/main/standards/io-interface">zkVM I/O</see>.
/// </summary>
public static partial class IO
{
    /// <summary>
    /// Reads raw bytes from the input stream.
    /// </summary>
    /// <returns>The data read.</returns>
    public static unsafe ReadOnlySpan<byte> ReadInput()
    {
        byte* ptr = null;
        nuint size = nuint.Zero;

        read_input(&ptr, ref size);

        return size == nuint.Zero ? [] : new ReadOnlySpan<byte>(ptr, checked((int)size));
    }

    /// <summary>
    /// Writes raw bytes to public outputs.
    /// </summary>
    /// <param name="output">The data buffer.</param>
    public static void WriteOutput(ReadOnlySpan<byte> output) => write_output(output, (nuint)output.Length);
}
