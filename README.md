# Minimal ELF Loader

This project is a custom, minimal loader for 64-bit ELF executables on Linux, written in C. It is capable of parsing an ELF file, mapping its segments into memory, setting up a stack, and transferring control to the new program.

It was developed as a university assignment to understand virtual memory, memory protection, and the process stack layout.

## Features

This loader successfully implements the following:

* **ELF Header Validation**: Checks the ELF magic number and class (64-bit) to ensure it's a valid file.
* **Syscall-Only Binary Support**: Loads and executes minimal binaries that make direct Linux syscalls without `libc`.
* **Correct Memory Permissions**: Maps program segments (`PT_LOAD`) into memory with the correct permissions (Read, Write, Execute) as specified in the program headers.
* **Static Non-PIE Binary Support**:
    * Fully loads and runs statically linked C programs (e.g., compiled with `gcc -static`).
    * Builds a valid process stack, including `argc`, `argv`, and environment variables (`envp`).
    * Sets up the **Auxiliary Vector (AUXV)** with necessary entries like `AT_PHDR`, `AT_PHENT`, `AT_PHNUM`, `AT_RANDOM`, and `AT_NULL`.

## How to Use

### Setup

The project includes a `src/` directory for the loader and a `test/` directory with a test suite.

### Compile and Run

1.  **Build the loader:**
    ```bash
    make
    ```
    (This should create the `elf_loader` executable in the `src/` directory or root).

2.  **Compile the test binaries:**
    ```bash
    cd test/
    make
    cd ..
    ```

3.  **Run the loader:**
    Pass the path to a test binary as an argument to the loader.
    ```bash
    # Example for a syscall-only binary
    ./elf_loader ./test/snippets/syscall

    # Example for a non-PIE binary with arguments
    ./elf_loader ./test/snippets/no_pie arg1 arg2 "hello world"
    ```

### Run the Checker

To run the automated checker (including linters):

```bash
./local.sh checker
