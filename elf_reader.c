/* zso1 jk320790 */

#include <assert.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <sys/mman.h>
#include <stdlib.h>
#include <string.h>

#include "elf_reader.h"

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
//  return (PROT_EXEC | PROT_READ | PROT_WRITE);
  return ((pflags & PF_X) != 0 ? PROT_EXEC : 0) |
    ((pflags & PF_R) != 0 ? PROT_READ : 0) |
    ((pflags & PF_W) != 0 ? PROT_WRITE : 0);
}

int is_image_valid(Elf32_Ehdr *hdr)
{
  unsigned int ok = 1;
  /* i386 */
  if (hdr->e_machine != EM_386)
    ok = 0;
  /* ELF type */
  if (hdr->e_type != ET_DYN)
    ok = 0;

  if (!ok)
    errno = EINVAL;
  return ok;
}

size_t map_elf(const char* name, void **mapped_load)
{
  FILE* elf = fopen(name, "rb");
  if (!elf)
    return -1;
  int fd = fileno(elf);

  size_t span;

  /* Read ELF file headers. */
  Elf32_Ehdr ehdr;
  ssize_t bytes_read = pread(fd, &ehdr, sizeof(ehdr), 0);
  if (bytes_read != sizeof(ehdr)) {
    errno = EINVAL;
    return -1;
  }

  if (!is_image_valid(&ehdr))
    return -1;
  if (ehdr.e_phnum > MAX_PHNUM) {
    errno = EINVAL;
    return -1;
  }
  Elf32_Phdr phdr[MAX_PHNUM];
  ssize_t phdrs_size = sizeof(phdr[0]) * ehdr.e_phnum;
  bytes_read = pread(fd, phdr, phdrs_size, ehdr.e_phoff);
  if (bytes_read != phdrs_size) {
    errno = EINVAL;
  }
  /* Find the first PT_LOAD segment. */
  size_t phdr_index = 0;
  while (phdr_index < ehdr.e_phnum && phdr[phdr_index].p_type != PT_LOAD)
    ++phdr_index;
  if (phdr_index == ehdr.e_phnum) {
    errno = EINVAL;
    return -1;
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
    errno = EINVAL;
    return -1;
  }
  span = last_load->p_vaddr + last_load->p_memsz;
  /* Reserve address space. */
  void *mapping = mmap(NULL, span, PROT_NONE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
  if (mapping == MAP_FAILED) {
    return -1;
  }
  uintptr_t load_bias = (uintptr_t) mapping;
  /* Map the PT_LOAD segments. */
  uintptr_t prev_segment_end = 0;
  int entry_point_is_valid = 0;
  Elf32_Phdr *ph;
  for (ph = first_load; ph <= last_load; ++ph) {
    if (ph->p_type != PT_LOAD)
      continue;
//    int prot = ElfFlagsToMmapFlags(ph->p_flags);
    int prot = (PROT_EXEC | PROT_READ | PROT_WRITE);
    uintptr_t segment_start = PageSizeRoundDown(ph->p_vaddr);
    uintptr_t segment_end = PageSizeRoundUp(ph->p_vaddr + ph->p_memsz);
    if (segment_start < prev_segment_end) {
      errno = EINVAL;
      munmap(mapping, span);
      return -1;
    }
    prev_segment_end = segment_end;
    void *segment_addr = (void *) (load_bias + segment_start);
    void *map_result = mmap((void *) segment_addr,
        segment_end - segment_start,
        prot, MAP_PRIVATE | MAP_FIXED, fd,
        PageSizeRoundDown(ph->p_offset));
    if (map_result != segment_addr) {
      errno = EINVAL;
      munmap(mapping, span);
      return -1;
    }
    if ((ph->p_flags & PF_X) != 0 &&
        ph->p_vaddr <= ehdr.e_entry &&
        ehdr.e_entry < ph->p_vaddr + ph->p_filesz) {
      entry_point_is_valid = 1;
    }
  }

  uintptr_t bss_start = ph->p_vaddr + ph->p_filesz;
  uintptr_t bss_map_start = PageSizeRoundUp(bss_start);
  memset((void *) (load_bias + bss_start), 0, bss_map_start - bss_start);

  if (close(fd) != 0) {
    errno = EIO;
    munmap(mapping, span);
    return -1;
  }

  *mapped_load = (void*)load_bias;
  return span;
}


void* get_dyn_segment( char *elf)
{
  Elf32_Ehdr *hdr = (Elf32_Ehdr*) elf;
  Elf32_Phdr *phdr = (Elf32_Phdr *)(elf + hdr->e_phoff);

  int i;
  for(i=0; i < hdr->e_phnum; ++i) {
    if(phdr[i].p_type == PT_DYNAMIC) {
      return elf + phdr[i].p_vaddr;
    }
  }
  errno = EINVAL;
  return (void*)NULL;
}


int get_symbols(char* elf_start, Elf32_Dyn *dyn, Elf32_Sym **symbols, char **strtab)
{
  *symbols = NULL;
  *strtab = NULL;

  Elf32_Word *hash;
  Elf32_Word number_of_symbols;
  while(dyn->d_tag != DT_NULL)
  {
    if (dyn->d_tag == DT_HASH)
    {
      hash = (Elf32_Word*)(elf_start + dyn->d_un.d_ptr);
      number_of_symbols = hash[1];
    }
    else if (dyn->d_tag == DT_STRTAB)
    {
      *strtab = elf_start + dyn->d_un.d_ptr;
    }
    else if (dyn->d_tag == DT_SYMTAB)
    {
      *symbols = (Elf32_Sym*)(elf_start + dyn->d_un.d_ptr);
    }
    dyn++;
  }
  if (symbols && strtab)
    return number_of_symbols;
  return -1;
}


int32_t get_offset_of_declared_symbol(const int number_of_symbols, Elf32_Sym *sym, char *strtab, const char *name)
{
  Elf32_Word sym_index;
  for (sym_index = 0; sym_index < number_of_symbols; sym_index++)
  {
    unsigned char sym_type = ELF32_ST_TYPE(sym[sym_index].st_info);
    if (sym_type != STT_OBJECT
        && sym_type != STT_FUNC
        && sym_type != STT_NOTYPE)
      continue;

    char* sym_name = &strtab[sym[sym_index].st_name];
    if (!strcmp(name, sym_name)) {
      if (sym_type == STT_NOTYPE) return -1;
      return sym[sym_index].st_value;
    }
  }
  return -1;
}


int do_relocation(char *elf_start, Elf32_Rel *rel, int32_t addr)
{
  Elf32_Rela *rela = (Elf32_Rela*)rel;
  Elf32_Word rel_type = ELF32_R_TYPE(rel->r_info);

  int32_t *rel_point = (int32_t*)(elf_start + rel->r_offset);
  switch (ELF32_R_TYPE(rel->r_info)) {
    case R_386_32:
      *rel_point += addr;
      break;
    case R_386_PC32:
      *rel_point = *rel_point + addr - (int32_t)rel_point;
      break;
    case R_386_JMP_SLOT:
      *rel_point = addr;
      break;
    case R_386_GLOB_DAT:
      *rel_point = addr;
      break;
    case R_386_RELATIVE:
      *rel_point += (int32_t)elf_start;
      break;
    default:
      /* TODO */
      printf("Error\n");
      return 0;
  }
}

int32_t resolve_relocation(char *elf_start, int number_of_symbols, Elf32_Sym *symbols, char *strtab,
    const char* sym_name, void *(*getsym)(const char *name))
{
  int32_t offset = get_offset_of_declared_symbol(number_of_symbols, symbols, strtab, sym_name);
  if (offset < 0)
    return (int32_t)getsym(sym_name);
  return (int32_t)(elf_start + offset);
}

int do_relocations(char *elf_start, Elf32_Dyn *dyn_start, void *(*getsym)(const char *name))
{
  size_t number_of_rel_relocs = 0;
  size_t number_of_jmp_relocs = 0;
  size_t relent_size = 8; /* assuming 8 according to task description */
  Elf32_Rel *rel_rel = NULL;
  Elf32_Rel *plt_rel = NULL;

  Elf32_Dyn *dyn = dyn_start;
  while(dyn->d_tag != DT_NULL)
  {
    switch (dyn->d_tag) {
      case DT_RELENT:
        relent_size = dyn->d_un.d_val;
        assert(relent_size == 8);
        break;
      case DT_RELSZ:
        number_of_rel_relocs = dyn->d_un.d_val;
        break;
      case DT_PLTRELSZ:
        number_of_jmp_relocs = dyn->d_un.d_val;
        break;
      case DT_REL:
        rel_rel = (Elf32_Rel*)(elf_start + dyn->d_un.d_ptr);
        break;
      case DT_JMPREL:
        plt_rel = (Elf32_Rel*)(elf_start + dyn->d_un.d_ptr);
        break;
    }
    dyn++;
  }

  Elf32_Sym *sym;
  char* strtab;
  int number_of_symbols = get_symbols(elf_start, dyn_start, &sym, &strtab);
  if (number_of_symbols < 0)
    return -1;

  Elf32_Rel *rel;
  const char *sym_name;
  int32_t addr;
  int i;
  for (i=0; i < number_of_rel_relocs / relent_size; i++) {
    rel = rel_rel + i;
    sym_name = strtab + sym[ELF32_R_SYM(rel->r_info)].st_name;
    addr = resolve_relocation(elf_start, number_of_rel_relocs, sym, strtab, sym_name, getsym);
    do_relocation(elf_start, rel, addr);
  }
  for (i=0; i < number_of_jmp_relocs / relent_size; i++) {
    rel = plt_rel + i;
    sym_name = strtab + sym[ELF32_R_SYM(rel->r_info)].st_name;
    addr = resolve_relocation(elf_start, number_of_rel_relocs, sym, strtab, sym_name, getsym);
    do_relocation(elf_start, rel, addr);
  }
  return 42;
}
