#include <sys/sysmacros.h>
/* #include <sys/exechdr.h> */
#include <sys/elf.h>
#include <sys/elf_notes.h>
#include <asm/sunddi.h>
#include "dbg2.h"

#ifdef DEBUG
static int      debug = 1;
#else /* DEBUG */
extern int      debug;
#endif /* DEBUG */
#define dprintf if (debug) dbg2_printf

typedef int	(*func_t)();

#define	FAIL	((func_t)-1)
#define FAIL_READELF64  ((uint64_t)0)

char impl_arch_name[] = "ARM,sbsa";
char filename[1024];
extern int verbosemode;
int	npagesize = 0;
int     use_align = 0;

extern int get_progmemory(caddr_t vaddr, size_t size, int align);

void
mod_path_uname_m(char *mod_path, char *ia_name)
{
}

int cons_gets(char *buf, int sz)
{
	return (-1);
}

void
setup_aux(void)
{
}

void
prom_enter_mon(void)
{
	dbg2_printf("prom_enter_mon: unimplemented for this platform\n");
	for (;;) ;
}


static uint64_t
read_elf64(caddr_t payload, size_t payload_size, int print, Elf64_Ehdr *elfhdrp)
{
	Elf64_Phdr *phdr;
	Elf64_Nhdr *nhdr;
	caddr_t allphdrs;
	int nphdrs, phdrsize;
	caddr_t namep, descp;
	Elf64_Addr entrypt;			/* entry point of standalone */
	int i;
	uintptr_t       off;
	size_t offset = 0;
	int bss_seen = 0;
	Elf64_Addr loadaddr, base;
	Elf64_Phdr *thdr;                       /* "text" program header */
	Elf64_Phdr *dhdr;                       /* "data" program header */
	size_t size;

	allphdrs = NULL;
	nhdr = NULL;

	if (verbosemode)
		dprintf("Elf64 client\n");

	if (elfhdrp->e_phnum == 0 || elfhdrp->e_phoff == 0)
		goto elf64error;

	entrypt = elfhdrp->e_entry;
	if (verbosemode)
		dprintf("Entry point: 0x%llx\n", (u_longlong_t)entrypt);

	/*
	 * Allocate and read in all the program headers.
	 */
	nphdrs = elfhdrp->e_phnum;
	phdrsize = nphdrs * elfhdrp->e_phentsize;
	allphdrs = (caddr_t)kmem_alloc(phdrsize, 0);
	if (allphdrs == NULL)
		goto elf64error;
	memcpy(allphdrs, payload + elfhdrp->e_phoff, phdrsize);

	/*
	 * First look for PT_NOTE headers that tell us what pagesize to
	 * use in allocating program memory.
	 */
	npagesize = 0;
	for (i = 0; i < nphdrs; i++) {
		void *note_buf;

		phdr = (Elf64_Phdr *)(allphdrs + elfhdrp->e_phentsize * i);
		if (phdr->p_type != PT_NOTE)
			continue;
		if (verbosemode) {
			dprintf("allocating 0x%llx bytes for note hdr\n",
			    (u_longlong_t)phdr->p_filesz);
		}
		if ((note_buf = kmem_alloc(phdr->p_filesz, 0)) == NULL)
			goto elf64error;
		nhdr = (Elf64_Nhdr *)note_buf;
		memcpy(nhdr, payload + phdr->p_offset, phdr->p_filesz);
		if (verbosemode) {
			dprintf("p_note namesz %x descsz %x type %x\n",
			    nhdr->n_namesz, nhdr->n_descsz, nhdr->n_type);
		}

		/*
		 * Iterate through all ELF PT_NOTE elements looking for
		 * ELF_NOTE_SOLARIS which, if present, will specify the
		 * executable's preferred pagesize.
		 */
		do {
			namep = (caddr_t)(nhdr + 1);

			if (nhdr->n_namesz == strlen(ELF_NOTE_SOLARIS) + 1 &&
			    strcmp(namep, ELF_NOTE_SOLARIS) == 0 &&
			    nhdr->n_type == ELF_NOTE_PAGESIZE_HINT) {
				descp = namep + roundup(nhdr->n_namesz, 4);
				npagesize = *(int *)descp;
				if (verbosemode)
					dprintf("pagesize is %x\n", npagesize);
			}

			offset += sizeof (Elf64_Nhdr) + roundup(nhdr->n_namesz,
			    4) + roundup(nhdr->n_descsz, 4);

			nhdr = (Elf64_Nhdr *)((char *)note_buf + offset);
		} while (offset < phdr->p_filesz);

		kmem_free(note_buf, phdr->p_filesz);
		nhdr = NULL;
	}

	/*
	 * Next look for PT_LOAD headers to read in.
	 */
	if (print)
		dbg2_puts("Size: ");
	for (i = 0; i < nphdrs; i++) {
		phdr = (Elf64_Phdr *)(allphdrs + elfhdrp->e_phentsize * i);
		if (verbosemode) {
			dprintf("Doing header 0x%x\n", i);
			dprintf("phdr\n");
			dprintf("\tp_offset = %llx, p_vaddr = %llx\n",
			    (u_longlong_t)phdr->p_offset,
			    (u_longlong_t)phdr->p_vaddr);
			dprintf("\tp_memsz = %llx, p_filesz = %llx\n",
			    (u_longlong_t)phdr->p_memsz,
			    (u_longlong_t)phdr->p_filesz);
			dprintf("\tp_type = %x, p_flags = %x\n",
			    phdr->p_type, phdr->p_flags);
		}

		if (phdr->p_type == PT_LOAD) {
			if (phdr->p_flags == (PF_R | PF_W) &&
			    phdr->p_vaddr == 0) {
				/*
				 * It's a PT_LOAD segment that is RW but
				 * not executable and has a vaddr
				 * of zero.  This is relocation info that
				 * doesn't need to stick around after
				 * krtld is done with it.  We allocate boot
				 * memory for this segment, since we don't want
				 * it mapped in permanently as part of
				 * the kernel image.
				 */
				if ((loadaddr = (Elf64_Addr)(uintptr_t)
				    kmem_alloc(phdr->p_memsz, 0)) == 0)
					goto elf64error;

				/*
				 * Save this to pass on
				 * to the interpreter.
				 */
				phdr->p_vaddr = loadaddr;
			} else {
				if (print)
					printf("0x%llx+",
					    (u_longlong_t)phdr->p_filesz);
				/*
				 * If we found a new pagesize above, use it
				 * to adjust the memory allocation.
				 */
				loadaddr = phdr->p_vaddr;
				if (use_align && npagesize != 0) {
					off = loadaddr & (npagesize - 1);
					size = roundup(phdr->p_memsz + off,
					    npagesize);
					base = loadaddr - off;
				} else {
					npagesize = 0;
					size = phdr->p_memsz;
					base = loadaddr;
				}
				/*
				 * Check if it's text or data.
				 */
				if (phdr->p_flags & PF_W)
					dhdr = phdr;
				else
					thdr = phdr;

				if (verbosemode)
					dprintf(
					    "allocating memory: %llx %lx %x\n",
					    (u_longlong_t)base,
					    size, npagesize);

				/*
				 * If memory size is zero just ignore this
				 * header.
				 */
				if (size == 0)
					continue;

				/*
				 * We're all set up to read.
				 * Now let's allocate some memory.
				 */
				if (get_progmemory((caddr_t)(uintptr_t)base,
				    size, npagesize))
					goto elf64error;
			}
			dbg2_printf("thdr: 0x%p, dhdr: 0x%p\n", thdr, dhdr);

			if (verbosemode) {
				dprintf("reading 0x%llx bytes into 0x%llx\n",
				    (u_longlong_t)phdr->p_filesz,
				    (u_longlong_t)loadaddr);
			}

			memcpy((void *)loadaddr, payload + phdr->p_offset, phdr->p_filesz);

			/* zero out BSS */
			if (phdr->p_memsz > phdr->p_filesz) {
				loadaddr += phdr->p_filesz;
				if (verbosemode) {
					dprintf("bss from 0x%llx size 0x%llx\n",
					    (u_longlong_t)loadaddr,
					    (u_longlong_t)(phdr->p_memsz -
					    phdr->p_filesz));
				}

				bzero((caddr_t)(uintptr_t)loadaddr,
				    phdr->p_memsz - phdr->p_filesz);
				bss_seen++;
				if (print)
					dbg2_printf("0x%llx Bytes\n",
					    (u_longlong_t)(phdr->p_memsz -
					    phdr->p_filesz));
			}

			/* force instructions to be visible to icache */
			if (phdr->p_flags & PF_X)
				sync_instruction_memory((caddr_t)(uintptr_t)
				    phdr->p_vaddr, phdr->p_memsz);

		} else if (phdr->p_type == PT_INTERP) {
			dbg2_panic("UNIX has an interpreter set - a kernel "
			    "interpreter is unsupported on aarch64/SBSA.\n");
		}
	}

	if (!bss_seen && print)
		printf("0 Bytes\n");

	kmem_free(allphdrs, phdrsize);
	return ((uint64_t)entrypt);

elf64error:
	if (allphdrs != NULL)
		kmem_free(allphdrs, phdrsize);
	if (nhdr != NULL)
		kmem_free(nhdr, phdr->p_filesz);
	dbg2_puts("Elf64 read error.\n");
	return (FAIL_READELF64);
}

func_t
load_elf_payload(caddr_t payload, size_t payload_size, int print)
{
	uint64_t elf64_go2;
	Elf64_Ehdr elfhdr;

	memcpy(&elfhdr, payload, sizeof (Elf64_Ehdr));

	if (*(int *)&elfhdr.e_ident != *(int *)(ELFMAG)) {
		dbg2_printf("load_elf_payload: payload is not ELF\n");
		return (FAIL);
	}

	if (elfhdr.e_ident[EI_CLASS] != ELFCLASS64) {
		dbg2_printf("load_elf_payload: only ELF64 is supported\n");
		return (FAIL);
	}

	if (verbosemode) {
		dprintf("calling readelf, elfheader is:\n");
		dprintf("e_ident\t0x%x, 0x%x, 0x%x, 0x%x\n",
		    *(int *)&elfhdr.e_ident[0],
		    *(int *)&elfhdr.e_ident[4],
		    *(int *)&elfhdr.e_ident[8],
		    *(int *)&elfhdr.e_ident[12]);
		dprintf("e_machine\t0x%x\n", elfhdr.e_machine);

		dprintf("e_entry\t\t0x%llx\n", elfhdr.e_entry);
		dprintf("e_shoff\t\t0x%llx\n", elfhdr.e_shoff);
		dprintf("e_shnentsize\t%d\n", elfhdr.e_shentsize);
		dprintf("e_shnum\t\t%d\n", elfhdr.e_shnum);
		dprintf("e_shstrndx\t%d\n", elfhdr.e_shstrndx);
	}

	dprintf("ELF file CLASS 0x%x 32 is %x 64 is %x\n",
	    elfhdr.e_ident[EI_CLASS], ELFCLASS32, ELFCLASS64);

	elf64_go2 = read_elf64(payload, payload_size, print, (Elf64_Ehdr *)&elfhdr);
	dbg2_printf("Kernel entry point is 0x%p\n", elf64_go2);
	return ((elf64_go2 == FAIL_READELF64) ? FAIL : (func_t)elf64_go2);
}
