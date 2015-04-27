/* zso1 jk320790 */
#ifndef ELF_READER_H
#define ELF_READER_H

#include <elf.h>

struct elf_ptrs {
  void (*r)();
  void *elf_start;
  Elf32_Dyn *dyn_section;
  Elf32_Rel *plt_relocations;
  Elf32_Sym *symbols;
  char *strtab;
  void *(*getsym)();
};

/* set proper protection lvl to loaded segments */
struct protect {
  int prot;
  void *addr;
  int size;
};

/* maps elf LOAD segments file and sets pointer to them, returns mapped bytes or -1*/
size_t map_elf(const char* name, void **mapped_load, struct protect **protections, int *number_of_protections);

/* returns pointer to dynamic segment of mapped elf file */
void* get_dyn_segment(char *elf);

/* sets symbols to symol table and strtab, returns number of symbols or -1 */
int get_symbols(char *elf_start, Elf32_Dyn *dyn, Elf32_Sym **symbols, char **strtab);

/* returns offset of symbol defined in library or -1 */
int32_t get_offset_of_declared_symbol(const int number_of_symbols, Elf32_Sym *sym, char *strtab, const char *name);

int do_relocations(char *elf_start, Elf32_Dyn *dyn, void *(*getsym)(const char *name));

#endif
