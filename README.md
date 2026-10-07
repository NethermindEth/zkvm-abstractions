# Nethermind zkVM abstractions

[![Build](https://github.com/nethermindeth/zkvm-abstractions/actions/workflows/build.yml/badge.svg)](https://github.com/nethermindeth/zkvm-abstractions/actions/workflows/build.yml)
[![Nethermind.Zkvm.Abstractions](https://img.shields.io/nuget/v/Nethermind.Zkvm.Abstractions)](https://www.nuget.org/packages/Nethermind.Zkvm.Abstractions)

C# bindings for the [zkVM Standards for Ethereum](https://github.com/eth-act/zkvm-standards).

The library targets guest programs compiled with Native AOT and statically linked against a zkVM that implements the standard C interfaces. All native functions resolve at link time.

## API

- `Accelerators`: [cryptographic accelerators](https://github.com/eth-act/zkvm-standards/tree/main/standards/c-interface-accelerators), such as Keccak-256, SHA-256, RIPEMD-160, BLAKE2f, BLS12-381, BN254, secp256k1, secp256r1, KZG point evaluation and ModExp.
- `IO`: [input and output](https://github.com/eth-act/zkvm-standards/tree/main/standards/io-interface) of the guest program.

Span-based methods validate buffer lengths before the native call and throw `ArgumentOutOfRangeException` on mismatch. Methods that return `Accelerators.Status` leave failure handling to the caller, since invalid input is an expected outcome for curve operations and signature recovery. The remaining standard accelerators throw `CryptographicException` on failure.

## ZisK

Building with `-p:Zisk=true` adds APIs not covered by the standards, backed by [ZisK](https://github.com/0xPolygonHermez/zisk)-specific functions:

- `Accelerators.KeccakF`: Keccak-f[1600] permutation ([eth-act/zkvm-standards#23](https://github.com/eth-act/zkvm-standards/issues/23)).
- `Accelerators.Sha256F`: SHA-256 compression of one block, also through a reusable `Sha256FParameters` block.
- `Accelerators.Memmove` and `Memset`: direct calls to the `memmove` and `memset` precompiles, skipping corelib's wrapper.
- `Accelerators.AddMod256`, `MulMod256`, `ReduceMod256` and `DivRem256`: 256-bit modular arithmetic and division.
- `IO.PrintLine`: writes to the standard output ([eth-act/zkvm-standards#21](https://github.com/eth-act/zkvm-standards/issues/21)). Without ZisK, it throws `NotImplementedException`.

The pointer- and `ref`-based methods are unchecked for hot paths; the caller guarantees the buffer sizes, alignment and non-aliasing described in their docs. `DivRem256` never returns if the divisor is zero.

## SP1

Building with `-p:Sp1=true` adds unchecked APIs backed by [SP1](https://github.com/succinctlabs/sp1) precompiles:

- `Accelerators.Sha256Extend` and `Sp1Sha256Compress`: SHA-256 message schedule extension and compression of one block.
- `Accelerators.UInt256MulMod`: in-place 256-bit modular multiplication.

## OpenVM

Building with `-p:OpenVm=true` adds unchecked APIs backed by [OpenVM](https://github.com/openvm-org/openvm) extensions:

- `Accelerators.UInt256Mul`: 256-bit wrapping multiplication on the bigint extension.
- `Accelerators.KeccakXorin`: XORs up to one rate of input into a Keccak state.
- `Accelerators.OpenVmSha256Compress`: SHA-256 compression of one block.

SP1 and OpenVM both export `zkvm_sha256_compress`, with different arguments: `Sp1Sha256Compress` and `OpenVmSha256Compress` each link on both zkVMs but work only on their own.

## Packaging

The published package is built with ZisK, SP1 and OpenVM support, so these APIs are visible to every consumer but work only on their zkVM. A guest links only the imports its code reaches, so one that never calls another zkVM's API links fine.

## License

This project is licensed under the [MIT](https://github.com/nethermindeth/zkvm-abstractions/blob/main/LICENSE) license.
