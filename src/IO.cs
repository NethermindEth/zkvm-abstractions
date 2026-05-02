// SPDX-FileCopyrightText: 2026 Demerzel Solutions Limited
// SPDX-License-Identifier: MIT

using System.Buffers.Binary;
using System.Runtime.InteropServices;
using System.Text;

namespace Nethermind.Zkvm.Abstractions;

/// <summary>
/// Provides <see href="https://github.com/eth-act/zkvm-standards/tree/main/standards/io-interface">zkVM I/O</see>.
/// </summary>
public static unsafe partial class IO
{
    // TODO: Remove when Zisk implements the zkVM standards
#if ZISK
    private static readonly byte* Input = (byte*)0x4000_0000ul; // INPUT_ADDR
    private static readonly uint* Output = (uint*)0xa001_0000ul; // OUTPUT_ADDR

    private static ulong _inputPosition = sizeof(ulong); // zkVM offset
#endif
    /// <summary>
    /// Prints the given string followed by a newline to the standard output.
    /// </summary>
    /// <param name="value">The string to print.</param>
    public static void PrintLine(ReadOnlySpan<char> value)
    {
        // TODO: Remove when added to the zkVM standards
#if ZISK
        int len = Encoding.UTF8.GetByteCount(value) + 1;

        Span<byte> buffer = len <= 512 ? stackalloc byte[len] : new byte[len];

        Encoding.UTF8.GetBytes(value, buffer);

        buffer[len - 1] = (byte)'\n';

        fixed (byte* ptr = &MemoryMarshal.GetReference(buffer))
            sys_write(1u, ptr, (nuint)len);
#else
        throw new NotImplementedException();
#endif
    }

    /// <summary>
    /// Reads raw bytes from the input stream.
    /// </summary>
    /// <returns>The data read.</returns>
    public static ReadOnlySpan<byte> ReadInput()
    {
        // TODO: Remove when Zisk implements the zkVM standards
#if ZISK
        byte* data = Input + checked((nint)_inputPosition); // len: u64 | data | padding
        ulong len = *(ulong*)data;

        if (len > int.MaxValue)
            Environment.FailFast("Input size exceeds the maximum supported length");

        ulong alignedLen = (len + 7ul) & ~7ul;

        // Advance by padded length
        _inputPosition = checked(_inputPosition + sizeof(ulong) + alignedLen);

        // Return the length of actual data, not including the padding
        return new ReadOnlySpan<byte>(data + sizeof(ulong), (int)len);
#else
        byte* ptr = null;

        read_input(&ptr, out nuint size);

        return size == nuint.Zero ? [] : new ReadOnlySpan<byte>(ptr, checked((int)size));
#endif
    }

    /// <summary>
    /// Writes raw bytes to public outputs.
    /// </summary>
    /// <param name="output">The data buffer.</param>
    public static void WriteOutput(ReadOnlySpan<byte> output)
    {
        // TODO: Remove when Zisk implements the zkVM standards
#if ZISK
        int count = output.Length / sizeof(uint);

        if ((uint)count >= 64u)
            Environment.FailFast("Output id must be between 0 and 63");

        int remaining = output.Length % sizeof(uint);

        for (int i = 0; i < count; i++)
            Output[(uint)i] = BinaryPrimitives.ReadUInt32LittleEndian(output.Slice(i * sizeof(uint), sizeof(uint)));

        if (remaining != 0)
        {
            uint value = 0u;
            int start = count * sizeof(uint);

            for (int i = 0; i < remaining; i++)
                value |= (uint)(output[start + i] << (8 * i));

            Output[(uint)count] = value;
        }
#else
        write_output(output, (nuint)output.Length);
#endif
    }
}
