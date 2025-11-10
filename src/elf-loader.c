// SPDX-License-Identifier: BSD-3-Clause

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#include <stdint.h>

// standard ELF types, structures, and macros
#include <elf.h>



void *map_elf(const char *filename)
{
	// This part helps you store the content of the ELF file inside the buffer.
	struct stat st;
	void *file;
	int fd;

	fd = open(filename, O_RDONLY);
	if (fd < 0) {
		perror("open");
		exit(1);
	}

	fstat(fd, &st);

	file = mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
	if (file == MAP_FAILED) {
		perror("mmap");
		close(fd);
		exit(1);
	}

	return file;
}

void load_and_run(const char *filename, int argc, char **argv, char **envp)
{
	// ############################################
	//	Validate ELFMAG and ELFCLASS64
	// ############################################
	void *elf_contents = map_elf(filename);

	unsigned char *elf_header = (unsigned char *)elf_contents;

	if (
		elf_header[0] != ELFMAG0 ||
		elf_header[1] != ELFMAG1 ||
		elf_header[2] != ELFMAG2 ||
		elf_header[3] != ELFMAG3
	) {
		fprintf(stderr, "Not a valid ELF file\n");
		exit(3);
	}

	if (elf_header[4] != ELFCLASS64) {
		fprintf(stderr, "Not a 64-bit ELF\n");
		exit(4);
	}

	// ############################################
	// Minimal loader
	// ############################################
	Elf64_Ehdr *header = (Elf64_Ehdr *)elf_contents;
	Elf64_Off e_phoff = header->e_phoff;			// Program header table file offset
	Elf64_Half e_phnum = header->e_phnum;			// Program header table entry count
	Elf64_Half e_phentsize = header->e_phentsize;	// Program header table entry size

	size_t mask = sysconf(_SC_PAGESIZE) - 1;

	Elf64_Addr min_vaddr = -1;
	Elf64_Addr max_vaddr =  0;

	Elf64_Addr aligned_min = min_vaddr & ~(mask);
	size_t total_size = max_vaddr - aligned_min;
	total_size = (total_size + mask) & ~mask;

	uintptr_t load_base = 0;
	void *reserved = NULL;

	for (Elf64_Half i = 0; i < e_phnum; i++) {
		Elf64_Off program_header_offset = e_phoff + (i * e_phentsize);
		Elf64_Phdr *phdr = (Elf64_Phdr *)(elf_header + program_header_offset);

		if (phdr->p_type != PT_LOAD) continue;

		Elf64_Addr seg_page_vaddr = (Elf64_Addr)(phdr->p_vaddr & ~(mask));
		size_t seg_page_offset = phdr->p_vaddr - seg_page_vaddr;
		size_t map_size = seg_page_offset + phdr->p_memsz;
		map_size = (map_size + mask) & ~mask;

		void *target = (void *)(load_base + seg_page_vaddr);

		void *seg = mmap(
					target, map_size,
					PROT_READ | PROT_WRITE | PROT_EXEC,
					MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
					-1, 0);

		if (phdr->p_filesz > 0) {
			memcpy((uint8_t *)seg + seg_page_offset, (uint8_t *)elf_contents + phdr->p_offset, phdr->p_filesz);
		}
		// ############################################
		// Load memory regions with correct permissions
		// ############################################
		int mem_protect = 0;
		if (phdr->p_flags & PF_R) mem_protect = mem_protect | PROT_READ;
		if (phdr->p_flags & PF_W) mem_protect = mem_protect | PROT_WRITE;
		if (phdr->p_flags & PF_X) mem_protect = mem_protect | PROT_EXEC;
		mprotect(seg, map_size, mem_protect);
	}

	/**
	 * TODO: Support Static Non-PIE Binaries with libc
	 * Must set up a valid process stack, including:
	 *	- argc, argv, envp
	 *	- auxv vector (with entries like AT_PHDR, AT_PHENT, AT_PHNUM, etc.)
	 * Note: Beware of the AT_RANDOM, AT_PHDR entries, the application will crash if you do not set them up properly.
	 */
	void *sp = NULL;

	/**
	 * TODO: Support Static PIE Executables
	 * Map PT_LOAD segments at a random load base.
	 * Adjust virtual addresses of segments and entry point by load_base.
	 * Stack setup (argc, argv, envp, auxv) same as above.
	 */

	void (*entry)() = (void (*)(void))header->e_entry;

	// Transfer control
	__asm__ __volatile__(
			"mov %0, %%rsp\n"
			"xor %%rbp, %%rbp\n"
			"jmp *%1\n"
			:
			: "r"(sp), "r"(entry)
			: "memory"
			);
}

int main(int argc, char **argv, char **envp)
{
	if (argc < 2) {
		fprintf(stderr, "Usage: %s <static-elf-binary>\n", argv[0]);
		exit(1);
	}

	load_and_run(argv[1], argc - 1, &argv[1], envp);
	return 0;
}
