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
#include <sys/random.h>
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

		if (phdr->p_type != PT_LOAD)
			continue;

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

		if (phdr->p_filesz > 0)
			memcpy((uint8_t *)seg + seg_page_offset, (uint8_t *)elf_contents + phdr->p_offset, phdr->p_filesz);

		// ############################################
		// Load memory regions with correct permissions
		// ############################################
		int mem_protect = 0;

		if (phdr->p_flags & PF_R)
			mem_protect = mem_protect | PROT_READ;
		if (phdr->p_flags & PF_W)
			mem_protect = mem_protect | PROT_WRITE;
		if (phdr->p_flags & PF_X)
			mem_protect = mem_protect | PROT_EXEC;

		mprotect(seg, map_size, mem_protect);
	}

	// ############################################
	// Support Static Non-PIE Bins with LIBC
	// ############################################
	size_t STACK_SIZE = 2*1024*1024;

	uint8_t *stack = mmap(NULL, STACK_SIZE, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);

	uintptr_t sp = (uintptr_t)(stack + STACK_SIZE);

	uintptr_t argv_ptrs[argc+1];

	for (int i = argc-1; i >= 0; i--) {
		size_t len = strlen(argv[i])+1;

		sp -= len;

		memcpy((void *)sp, argv[i], len);
		argv_ptrs[i] = sp;
	}
	argv_ptrs[argc] = 0;

	// copy envp strings
	int envc = 0;

	while (envp && envp[envc])
		envc++;

	uintptr_t envp_ptrs[envc+1];

	for (int i = envc-1; i >= 0; i--) {
		size_t len = strlen(envp[i]) + 1;

		sp -= len;

		memcpy((void *)sp, envp[i], len);
		envp_ptrs[i] = sp;
	}
	envp_ptrs[envc] = 0;


	uintptr_t phdr = 0;

	Elf64_Phdr *phdrs = (Elf64_Phdr *)(elf_contents + header->e_phoff);

	for (Elf64_Half i = 0; i < header->e_phnum; i++) {
		if (phdrs[i].p_type == PT_PHDR) {
			phdr = phdrs[i].p_vaddr;
			break;
		}
	}

	uint64_t auxv[16];

	int i = 0;

	auxv[i++] = AT_EXECFD;
	auxv[i++] = -1; // fd

	auxv[i++] = AT_PHDR;
	auxv[i++] = (uint64_t)(phdr + load_base);

	auxv[i++] = AT_PHENT;
	auxv[i++] = (uint64_t)header->e_phentsize;

	auxv[i++] = AT_PHNUM;
	auxv[i++] = (uint64_t)header->e_phnum;

	auxv[i++] = AT_PAGESZ;
	auxv[i++] = (uint64_t)sysconf(_SC_PAGESIZE);

	auxv[i++] = AT_ENTRY;
	auxv[i++] = (uint64_t)(header->e_entry + load_base);

	auxv[i++] = AT_RANDOM;
	sp -= 16;
	getrandom((void *)sp, 16, 0);
	auxv[i++] = (uint64_t)sp;

	auxv[i++] = AT_NULL;
	auxv[i++] = 0;

	// push auxv
	for (int j = i - 1; j >= 0; j--) {
		sp -= sizeof(uint64_t);
		*(uint64_t *)sp = auxv[j];
	}

	// push envp
	for (int i = envc; i >= 0; i--) {
		sp -= sizeof(uintptr_t);
		*(uintptr_t *)sp = envp_ptrs[i];
	}

	// push argv
	for (int i = argc; i >= 0; i--) {
		sp -= sizeof(uintptr_t);

		*(uintptr_t *)sp = argv_ptrs[i];
	}

	// push argc
	sp -= sizeof(uintptr_t);

	*(uintptr_t *)sp = argc;

	// set entry point
	//void (*entry)() = (void (*)(void)header->e_entry + load_base);
	uintptr_t entry_addr = (uintptr_t)(load_base + header->e_entry);

	void (*entry)(void) = (void (*)(void))entry_addr;

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
