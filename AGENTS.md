# AGENTS instructions

C# bindings for the [zkVM Standards for Ethereum](https://github.com/eth-act/zkvm-standards). See [global.json](./global.json) and [src](./src/) directory for the project requirements and configuration.

## Project structure

- [src](./src/): The main codebase, a single project.
  - `*.bindings.cs`: `LibraryImport` declarations of the native C interface, imported from `__Internal` (statically linked into Native AOT guest programs).
  - `Accelerators.cs`, `IO.cs`: The public API wrapping the bindings.
- [build.yml](./.github/workflows/build.yml): Builds with and without ZisK, SP1 and OpenVM support, treating warnings as errors.
- [publish.yml](./.github/workflows/publish.yml): Publishes on NuGet with ZisK, SP1 and OpenVM support. Uses NuGet trusted publishing, so do not rename it.

## Coding guidelines

- Follow [.editorconfig](./.editorconfig).
- Do not assume; measure, research, ask if unsure.
- Keep comments short and to the point.
- Use conventional commits; keep scoped and imperative.
- Match native signatures to the [zkVM standards](https://github.com/eth-act/zkvm-standards) headers exactly; keep native names and parameter names as in the headers.
- Validate span lengths in the public API before calling native code, and document them with `<exception>` tags. Unchecked pointer or `ref` overloads are for hot paths only and must document the caller's contract (sizes, alignment, aliasing).
- Mark accelerator imports with `[SuppressGCTransition]`; guest programs are single-threaded and native routines never call back into managed code.
- Document all public API with XML comments, linking to the relevant standard.
- Guard non-standard APIs with `#if ZISK`, `#if SP1` or `#if OPENVM`, with a `TODO` linking the upstream standards issue where one exists; remove them once standardized.
- Build with each of `-p:Zisk=true`, `-p:Sp1=true` and `-p:OpenVm=true` alone, none, and all together before committing; each must be free of warnings.
- Keep the public API Native AOT compatible.
- Prefer the latest versions of GitHub Actions and runners.
- Keep [AGENTS.md](./AGENTS.md) and [README.md](./README.md) in sync with the ongoing development.
