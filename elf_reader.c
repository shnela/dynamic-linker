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
        break;
    }
  }
}

void* get_dyn_segment(char *elf)
{
  Elf32_Ehdr *hdr = (Elf32_Ehdr*) elf;
  Elf32_Phdr *phdr = (Elf32_Phdr *)(elf + hdr->e_phoff);

  int i;
  for(i=0; i < hdr->e_phnum; ++i) {
    if(phdr[i].p_type == PT_DYNAMIC) {
      return elf + phdr[i].p_vaddr;
    }
  }
  return (void*)NULL;
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

size_t map_elf(const char* name, void **mapped_load) {
  FILE* elf = fopen(name, "rb");
  int fd = fileno(elf);

  size_t span;

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
  if (!is_image_valid(&ehdr))
    return -1;
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
  span = last_load->p_vaddr + last_load->p_memsz;
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

  *mapped_load = (void*)load_bias;
  return span;
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
      printf("JEA!!!!!!!!!!!!!!!!!!!!!!!!!!!11\n");
      relocate(shdr + i, syms, strings, elf, elf, getsym);
    }
    if (shdr[i].sh_type == SHT_REL) {
      printf("normal!!!!!!!!!!!!!!!!!!!!!!!!11\n");
      relocate(shdr + i, syms, strings, elf, elf, getsym);
    }
  }


  return 2;
}
