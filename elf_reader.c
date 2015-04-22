/* zso1 jk320790 */
/* based on http://stackoverflow.com/questions/13908276/loading-elf-file-in-c-in-user-space */

#include <stdio.h>
#include <string.h>
#include <elf.h>
#include <sys/mman.h>
#include <dlfcn.h>
#include <stdlib.h>

#include "elf_reader.h"

void printk(const char* msg)
{
  fputs(msg, stderr);
}

int is_image_valid(Elf32_Ehdr *hdr)
{
  /* i386 */
  if (hdr->e_machine != EM_386)
    return 0;
  /* ELF type */
  if (hdr->e_type != ET_DYN)
    return 0;
  return 1;
}

void *resolve(const char* sym)
{
  static void *handle = NULL;
  if (handle == NULL) {
    //    handle = dlopen("libc.so", RTLD_NOW);
  }
  //  return dlsym(handle, sym);
  return 0;
}

void relocate(Elf32_Shdr* shdr, const Elf32_Sym* syms, const char* strings, const char* src,
    char* dst, void *(*getsym)(const char *name))
{
  //  printf ("relocate::\n");
  Elf32_Rel* rel = (Elf32_Rel*)(src + shdr->sh_offset);
  int j;
  for(j = 0; j < shdr->sh_size / sizeof(Elf32_Rel); j += 1) {
    const char* sym = strings + syms[ELF32_R_SYM(rel[j].r_info)].st_name;
    printf ("nanme: %s (%d)\n", sym, ELF32_R_TYPE(rel[j].r_info));
    printf ("addrs: [dst](%d) [off](0x%x) \n", (int)dst, rel[j].r_offset);
    switch(ELF32_R_TYPE(rel[j].r_info)) {
      case R_386_PC32:
      case R_386_JMP_SLOT:
      case R_386_GLOB_DAT:
        printf ("<<< addr in rel: %d >>>\n", (int)getsym(sym));
        *(Elf32_Word*)(dst + rel[j].r_offset) = (Elf32_Word)getsym(sym);
        //        *(Elf32_Word*)(dst + rel[j].r_offset) = (Elf32_Word)resolve(sym);
        break;
    }
  }
}

void* find_sym(const char* name, Elf32_Shdr* shdr, const char* strings, const char* src, char* dst)
{
  printf ("find sym::\n");
  printf ("dst %d\n", (int)dst);
  Elf32_Sym* syms = (Elf32_Sym*)(src + shdr->sh_offset);
  int i;
  for(i = 0; i < shdr->sh_size / sizeof(Elf32_Sym); i += 1) {
    if (strcmp(name, strings + syms[i].st_name) == 0) {
      printf ("%s\n", name);
      char tmp[10];
      strncpy(tmp, strings + syms[i].st_name, 9);
      tmp[9] = 0;
      printf("name: %s under (%d)\n", tmp, syms[i].st_value);
      return dst + syms[i].st_value;
    }
  }
  return NULL;
}

void *image_load (char *elf_start, unsigned int size)
{
  Elf32_Ehdr      *hdr     = NULL;
  Elf32_Phdr      *phdr    = NULL;
  Elf32_Shdr      *shdr    = NULL;
  Elf32_Sym       *syms    = NULL;
  char            *strings = NULL;
  char            *start   = NULL;
  char            *taddr   = NULL;
  void            *entry   = NULL;
  int i = 0;
  char *exec = NULL;

  /* TODO dynamic change to e_phnum/e_shnum */
  const int max_load_sections = 100;
  const int max_dynamic_sections = 100;
  Elf32_Phdr load_sections[max_load_sections];
  Elf32_Phdr dynamic_sections[max_dynamic_sections];
  int num_load_sections = 0;
  int num_dynamic_sections = 0;

  hdr = (Elf32_Ehdr *) elf_start;

  if(!is_image_valid(hdr)) {
    printk("image_load:: invalid ELF image\n");
    return 0;
  }

  exec = mmap(NULL, size, PROT_READ | PROT_WRITE | PROT_EXEC,
      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  printf ("%d\n", (int)exec);

  if(!exec) {
    printk("image_load:: error allocating memory\n");
    return 0;
  }

  // Start with clean memory.
  memset(exec, 0x0, size);

  phdr = (Elf32_Phdr *)(elf_start + hdr->e_phoff);

  for(i=0, num_load_sections=0, num_dynamic_sections=0; i < hdr->e_phnum; ++i) {
    printf ("%dth segment: %d\n", i, phdr[i].p_type);

    if(phdr[i].p_type == PT_LOAD) {
      load_sections[num_load_sections++] = phdr[i];
    }
    if(phdr[i].p_type == PT_DYNAMIC) {
      dynamic_sections[num_dynamic_sections++] = phdr[i];
    }

    if(phdr[i].p_type != PT_LOAD) {
      continue;
    }
    if(phdr[i].p_filesz > phdr[i].p_memsz) {
      printk("image_load:: p_filesz > p_memsz\n");
      munmap(exec, size);
      return 0;
    }
    if(!phdr[i].p_filesz) {
      continue;
    }

    // p_filesz can be smaller than p_memsz,
    // the difference is zeroe'd out.
    start = elf_start + phdr[i].p_offset;
    taddr = phdr[i].p_vaddr + exec;
    memmove(taddr,start,phdr[i].p_filesz);

    if(!(phdr[i].p_flags & PF_W)) {
      // Read-only.
      mprotect((unsigned char *) taddr,
          phdr[i].p_memsz,
          PROT_READ);
    }

    if(phdr[i].p_flags & PF_X) {
      // Executable.
      mprotect((unsigned char *) taddr,
          phdr[i].p_memsz,
          PROT_EXEC);
    }
  }

  shdr = (Elf32_Shdr *)(elf_start + hdr->e_shoff);

  for(i=0; i < hdr->e_shnum; ++i) {
    printf("section: %d\n", shdr[i].sh_type);
    if (shdr[i].sh_type == SHT_DYNSYM) {
      syms = (Elf32_Sym*)(elf_start + shdr[i].sh_offset);
      strings = elf_start + shdr[shdr[i].sh_link].sh_offset;
      entry = find_sym("main", shdr + i, strings, elf_start, exec);
      break;
    }
  }

  for(i=0; i < hdr->e_shnum; ++i) {
    if (shdr[i].sh_type == SHT_REL) {
      //      relocate(shdr + i, syms, strings, elf_start, exec);
    }
  }

  return entry;

} /* image_load */

int allocate(char *elf, Elf32_Shdr **dynsym)
{

  printf("alloca\n");
  Elf32_Ehdr *hdr = (Elf32_Ehdr*) elf;
  Elf32_Phdr *phdr = (Elf32_Phdr *)(elf + hdr->e_phoff);

  Elf32_Phdr *tmp;

  int i;
  for(i=0; i < hdr->e_phnum; ++i) {
    printf ("%dth segment: %d\n", i, phdr[i].p_type);

    if(phdr[i].p_type == PT_LOAD) {
    }
    if(phdr[i].p_type == PT_DYNAMIC) {
      tmp = phdr + i;
      printf("here\n");
    }
  }

  return 42;
}

#define ElfW(type) Elf32_ ## type
#define MAX_PHNUM 100
#define NONSFI_PAGE_SIZE 0x1000
#define NONSFI_PAGE_MASK (NONSFI_PAGE_SIZE - 1)

static uintptr_t PageSizeRoundDown(uintptr_t addr) {
    return addr & ~NONSFI_PAGE_MASK;
}
static uintptr_t PageSizeRoundUp(uintptr_t addr) {
    return PageSizeRoundDown(addr + NONSFI_PAGE_SIZE - 1);
}
static int ElfFlagsToMmapFlags(int pflags) {
  return ((pflags & PF_X) != 0 ? PROT_EXEC : 0) |
         ((pflags & PF_R) != 0 ? PROT_READ : 0) |
         ((pflags & PF_W) != 0 ? PROT_WRITE : 0);
}

uintptr_t NaClLoadElfFile(int fd) {
  /* Read ELF file headers. */
  Elf32_Ehdr ehdr;
  ssize_t bytes_read = pread(fd, &ehdr, sizeof(ehdr), 0);
  if (bytes_read != sizeof(ehdr)) {
    return -1;
    //    NaClLog(LOG_FATAL, "Failed to read ELF file headers\n");
  }
  /* TODO check it ! */
  //  CheckElfHeaders(&ehdr);
  /* Read ELF program headers. */
  if (ehdr.e_phnum > MAX_PHNUM) {
    return -1;
    //    NaClLog(LOG_FATAL, "ELF file has too many program headers\n");
  }
  Elf32_Phdr phdr[MAX_PHNUM];
  ssize_t phdrs_size = sizeof(phdr[0]) * ehdr.e_phnum;
  bytes_read = pread(fd, phdr, phdrs_size, ehdr.e_phoff);
  if (bytes_read != phdrs_size) {
    //    NaClLog(LOG_FATAL, "Failed to read ELF program headers\n");
  }
  /* Find the first PT_LOAD segment. */
  size_t phdr_index = 0;
  while (phdr_index < ehdr.e_phnum && phdr[phdr_index].p_type != PT_LOAD)
    ++phdr_index;
  if (phdr_index == ehdr.e_phnum) {
    return -1;
//    NaClLog(LOG_FATAL, "ELF file has no PT_LOAD header\n");
  }
  /*
   * ELF requires that PT_LOAD segments be in ascending order of p_vaddr.
   * Find the last one to calculate the whole address span of the image.
   */
  Elf32_Phdr *first_load = &phdr[phdr_index];
  Elf32_Phdr *last_load = &phdr[ehdr.e_phnum - 1];
  while (last_load > first_load && last_load->p_type != PT_LOAD)
    --last_load;
  if (first_load->p_vaddr != 0) {
    return -1;
//    NaClLog(LOG_FATAL, "First PT_LOAD segment's load address is not 0\n");
  }
  size_t span = last_load->p_vaddr + last_load->p_memsz;
  /* Reserve address space. */
  void *mapping = mmap(NULL, span, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (mapping == MAP_FAILED) {
    return -1;
//    NaClLog(LOG_FATAL, "Failed to reserve address space for executable\n");
  }
  uintptr_t load_bias = (uintptr_t) mapping;
  /* Map the PT_LOAD segments. */
  uintptr_t prev_segment_end = 0;
  int entry_point_is_valid = 0;
  Elf32_Phdr *ph;
  for (ph = first_load; ph <= last_load; ++ph) {
    if (ph->p_type != PT_LOAD)
      continue;
    int prot = ElfFlagsToMmapFlags(ph->p_flags);
    uintptr_t segment_start = PageSizeRoundDown(ph->p_vaddr);
    uintptr_t segment_end = PageSizeRoundUp(ph->p_vaddr + ph->p_memsz);
    if (segment_start < prev_segment_end) {
      return -1;
//      NaClLog(LOG_FATAL, "PT_LOAD segments overlap or are not sorted\n");
    }
    prev_segment_end = segment_end;
    void *segment_addr = (void *) (load_bias + segment_start);
    void *map_result = mmap((void *) segment_addr,
        segment_end - segment_start,
        prot, MAP_PRIVATE | MAP_FIXED, fd,
        PageSizeRoundDown(ph->p_offset));
    if (map_result != segment_addr) {
      return -1;
//      NaClLog(LOG_FATAL, "Failed to map ELF segment\n");
    }
    if ((ph->p_flags & PF_X) != 0 &&
        ph->p_vaddr <= ehdr.e_entry &&
        ehdr.e_entry < ph->p_vaddr + ph->p_filesz) {
      entry_point_is_valid = 1;
    }
  }
  if (close(fd) != 0) {
    return -1;
//    NaClLog(LOG_FATAL, "close() failed\n");
  }

  return load_bias;
}


int get_symbols(char *elf, void *(*getsym)(const char *name))
{
  Elf32_Ehdr *hdr = (Elf32_Ehdr*) elf;
  Elf32_Shdr *shdr = (Elf32_Shdr *)(elf + hdr->e_shoff);
  Elf32_Sym *syms = NULL;
  char *strings = NULL;
  int i;
  printf ("shdr 0x%x and off 0x%x\n", shdr, hdr->e_shoff);
  for(i=0; i < hdr->e_shnum; ++i) {
    //    printf("section: %d\n", shdr[i].sh_type);
    if (shdr[i].sh_type == SHT_DYNSYM) {
      syms = (Elf32_Sym*)(elf + shdr[i].sh_offset);
      strings = elf + shdr[shdr[i].sh_link].sh_offset;
      //      entry = find_sym("main", shdr + i, strings, elf, exec);
      break;
    }
  }

  for(i=0; i < hdr->e_shnum; ++i) {
    if (shdr[i].sh_type == SHT_RELA) {
      printf("ERROR!!!!!!!!!!!!!!!!!!!!!!!!!!!11\n");
    }
    if (shdr[i].sh_type == SHT_REL) {
      relocate(shdr + i, syms, strings, elf, elf, getsym);
    }
  }


  return 2;
}

int f2()
{
  int (*ptr)();
  static char buf[10485760];
  FILE* elf = fopen("elf", "rb");
  fread(buf, sizeof buf, 1, elf);
  ptr = image_load(buf, sizeof buf);
  return ptr();
}
