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
#include <elf.h>

#include "key.h"
#include "payload_data.h"

static void die(const char *msg) {
    perror(msg);
    _exit(1);
}

void validate_elf(void *p, size_t sz) {
    if (sz < sizeof(Elf64_Ehdr)) {
        die("file too small to be ELF");
    }

    Elf64_Ehdr *eh = (Elf64_Ehdr *)p;

    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) {
        die("invalid ELF magic");
    }

    if (eh->e_ident[EI_CLASS] != ELFCLASS64) {
        die("not a 64-bit ELF");
    }

    if (eh->e_ident[EI_DATA] != ELFDATA2LSB) {
        die("unsupported endianness");
    }

    if (eh->e_type != ET_EXEC) {
        die("not a static executable (ET_EXEC required)");
    }

    if (eh->e_machine != EM_X86_64) {
        die("invalid architecture");
    }
}

static void *get_decrypted_elf(size_t *sz) {
    *sz = sizeof(encrypted_payload);

    void *p = mmap(NULL, *sz, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (p == MAP_FAILED) die("mmap anonymous");
    uint8_t *dest = (uint8_t *)p;

    for (size_t i = 0; i < *sz; i++) {
        dest[i] = encrypted_payload[i] ^ xor_key[i % XOR_KEY_LEN];
    }

    return p;
}

void load_and_run(int argc, char **argv, char **envp) {
    size_t elf_sz;

    uint8_t *elf_contents = get_decrypted_elf(&elf_sz);

    Elf64_Ehdr *eh = (Elf64_Ehdr *)elf_contents;

    validate_elf(eh, elf_sz);

    // https://man7.org/linux/man-pages/man5/elf.5.html
    Elf64_Off e_phoff = eh->e_phoff;
    Elf64_Half e_phnum = eh->e_phnum;
    Elf64_Half e_phentsize = eh->e_phentsize;

    Elf64_Phdr *phdrs = (Elf64_Phdr *)(elf_contents + e_phoff);

	size_t mask = sysconf(_SC_PAGESIZE) - 1;

	Elf64_Addr min_vaddr = -1;
	Elf64_Addr max_vaddr =  0;

    for (int i = 0; i < e_phnum; i++) {
       Elf64_Phdr *ph = &phdrs[i];

       if (ph->p_type != PT_LOAD)
           continue;

       if (ph->p_vaddr < min_vaddr)
           min_vaddr = ph->p_vaddr;

       if (ph->p_vaddr + ph->p_memsz > max_vaddr)
           max_vaddr = ph->p_vaddr + ph->p_memsz;
   }

	Elf64_Addr aligned_min = min_vaddr & ~(mask);
	size_t total_size = max_vaddr - aligned_min;

	total_size = (total_size + mask) & ~mask;

	uintptr_t load_base = 0;
	void *reserved = NULL;

	for (Elf64_Half i = 0; i < e_phnum; i++) {
	    Elf64_Phdr *ph = &phdrs[i];

		if (ph->p_type != PT_LOAD)
			continue;

        Elf64_Addr seg_page_vaddr = ph->p_vaddr & ~mask;
        size_t seg_page_offset = ph->p_vaddr - seg_page_vaddr;
        size_t map_size = (seg_page_offset + ph->p_memsz + mask) & ~mask;

        void *target = (void *)seg_page_vaddr;
        void *seg = mmap(target, map_size,
                 PROT_READ | PROT_WRITE | PROT_EXEC,
                 MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED,
                 -1, 0);

        if (seg == MAP_FAILED)
            die("mmap failed");

        if (ph->p_filesz > 0) {
            memcpy((uint8_t *)seg + seg_page_offset,
                   (uint8_t *)elf_contents + ph->p_offset,
                   ph->p_filesz);
        }
		// ############################################
		// Load memory regions with correct permissions
		// ############################################
		int mem_protect = 0;

		if (ph->p_flags & PF_R)
			mem_protect = mem_protect | PROT_READ;
		if (ph->p_flags & PF_W)
			mem_protect = mem_protect | PROT_WRITE;
		if (ph->p_flags & PF_X)
			mem_protect = mem_protect | PROT_EXEC;

		mprotect(seg, map_size, mem_protect);
	}

	// ############################################
	// Support Static Non-PIE Bins with LIBC
	// ############################################
	size_t STACK_SIZE = 8*1024*1024;

    uint8_t *stack = mmap(NULL, STACK_SIZE,
                    PROT_READ | PROT_WRITE,
                    MAP_PRIVATE | MAP_ANONYMOUS,
                    -1, 0);

    if (stack == MAP_FAILED)
        die("mmap stack");

	uintptr_t sp = (uintptr_t)(stack + STACK_SIZE);

    uintptr_t argv_ptrs[argc + 1];
    for (int i = argc - 1; i >= 0; i--) {
       size_t len = strlen(argv[i]) + 1;
       sp -= len;
       memcpy((void *)sp, argv[i], len);
       argv_ptrs[i] = sp;
    }
    argv_ptrs[argc] = 0;

    int envc = 0;
    while (envp && envp[envc]) envc++;

    uintptr_t envp_ptrs[envc + 1];
    for (int i = envc - 1; i >= 0; i--) {
       size_t len = strlen(envp[i]) + 1;
       sp -= len;
       memcpy((void *)sp, envp[i], len);
       envp_ptrs[i] = sp;
    }
    envp_ptrs[envc] = 0;

    sp &= ~0xF;
    sp -= 16;

    getrandom((void *)sp, 16, 0);
    uintptr_t random_data_addr = sp;

    uintptr_t phdr_addr = 0;
    for (Elf64_Half i = 0; i < eh->e_phnum; i++) {
       if (phdrs[i].p_type == PT_PHDR) {
          phdr_addr = phdrs[i].p_vaddr;
          break;
       }
    }
    if (!phdr_addr)
        phdr_addr = phdrs[0].p_vaddr + eh->e_phoff;


	Elf64_auxv_t auxv[64];
	int i = 0;

    // https://refspecs.linuxfoundation.org/LSB_2.1.0/LSB-Core-IA64/LSB-Core-IA64/auxiliaryvector.html
    auxv[i].a_type = AT_EXECFD; auxv[i++].a_un.a_val = -1;
    auxv[i].a_type = AT_PHDR;   auxv[i++].a_un.a_val = phdr_addr;
    auxv[i].a_type = AT_PHENT;  auxv[i++].a_un.a_val = eh->e_phentsize;
    auxv[i].a_type = AT_PHNUM;  auxv[i++].a_un.a_val = eh->e_phnum;
    auxv[i].a_type = AT_PAGESZ; auxv[i++].a_un.a_val = sysconf(_SC_PAGESIZE);
    auxv[i].a_type = AT_ENTRY;  auxv[i++].a_un.a_val = eh->e_entry;
    auxv[i].a_type = AT_RANDOM; auxv[i++].a_un.a_val = random_data_addr;
    auxv[i].a_type = AT_UID;    auxv[i++].a_un.a_val = getuid();
    auxv[i].a_type = AT_EUID;   auxv[i++].a_un.a_val = geteuid();
    auxv[i].a_type = AT_GID;    auxv[i++].a_un.a_val = getgid();
    auxv[i].a_type = AT_EGID;   auxv[i++].a_un.a_val = getegid();
    auxv[i].a_type = AT_NULL;   auxv[i++].a_un.a_val = 0;

    // align stack 16 bytes
    sp &= ~0xF;

    // push auxv (last entry first)
    for (int j = i - 1; j >= 0; j--) {
        sp -= sizeof(Elf64_auxv_t);
        memcpy((void *)sp, &auxv[j], sizeof(Elf64_auxv_t));
    }

    // push envp NULL
    sp -= sizeof(uintptr_t);
    *(uintptr_t *)sp = 0;

    // push envp ptrs
    for (int j = envc - 1; j >= 0; j--) {
        sp -= sizeof(uintptr_t);
        *(uintptr_t *)sp = envp_ptrs[j];
    }

    // push argv NULL
    sp -= sizeof(uintptr_t);
    *(uintptr_t *)sp = 0;

    // push argv pointers
    for (int j = argc - 1; j >= 0; j--) {
        sp -= sizeof(uintptr_t);
        *(uintptr_t *)sp = argv_ptrs[j];
    }

    // push argc
    sp -= sizeof(uintptr_t);
    *(uintptr_t *)sp = argc;

	// set entry point
    void (*entry)(void) = (void (*)(void))eh->e_entry;

	// transfer control
    __asm__ __volatile__(
          "mov %0, %%rsp\n"      // set Stack Pointer
          "xor %%rbp, %%rbp\n"
          "xor %%rdx, %%rdx\n"
          "jmp *%1\n"            // jmp to entry
          :
          : "D"(sp), "a"(entry)
          : "memory", "cc", "rdx", "rsi", "rcx", "rbx" // for clobbering
          );
}


int main(int argc, char **argv, char **envp) {
    load_and_run(1, argv, envp);
    return 0;
}