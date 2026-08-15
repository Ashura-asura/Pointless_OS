@echo off
REM Rebuild the Phase J linux-hello.elf from its LLVM IR source.
REM Uses the LLVM toolchain bundled with the pinned Rust toolchains on this
REM host (llc compiles the IR, ld.lld links it static). On a host with GNU
REM binutils, an equivalent .S file can be assembled with `as --64` +
REM `ld -static --nostdlib -T link-hello.ld`; the committed .elf is the
REM byte-identical single-PT_LOAD R+E binary either path produces.
set LLC=%USERPROFILE%\.rustup\toolchains\stable-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\bin\llc.exe
set LDLD=%USERPROFILE%\.rustup\toolchains\1.97.1-x86_64-pc-windows-msvc\lib\rustlib\x86_64-pc-windows-msvc\bin\gcc-ld\ld.lld.exe
cd /d "%~dp0"
"%LLC%" -filetype=obj -relocation-model=static -o linux-hello.o linux-hello.ll
"%LDLD%" -m elf_x86_64 -static --nostdlib -T link-hello.ld -o linux-hello.elf linux-hello.o
del linux-hello.o
echo linux-hello.elf rebuilt
