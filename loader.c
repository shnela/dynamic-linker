/* zso1 jk320790 */
#include <stdlib.h>

#include "loader.h"
#include "elf_reader.h"

#include <sys/mman.h>

struct library {
  /* mapped LOAD segments */
  void *lib;
  /* begin of DYNAMIC segment */
  void *dyn_segment;
};

struct library *library_load(const char *name, void *(*getsym)(const char *name))
{
  struct library *lib = malloc(sizeof(struct library));
  if (!lib)
    return NULL;

  void *mapped_lib;
  size_t mapped_size;
  mapped_size = map_elf(name, &mapped_lib);
  if (mapped_size < 0)
    return NULL;
  lib->lib = mapped_lib;

  void *dyn_segment;
  dyn_segment = get_dyn_segment(mapped_lib);
  if (!dyn_segment) {
    munmap(mapped_lib, mapped_size);
    return NULL;
  }
  lib->dyn_segment = dyn_segment;

  int reloc_status;
  reloc_status = do_relocations((char*)mapped_lib, (Elf32_Dyn*)dyn_segment, getsym);
  if (reloc_status < 0) {
    munmap(mapped_lib, mapped_size);
    return NULL;
  }

  return lib;
}


void *library_getsym(struct library *lib, const char *name)
{
  char* elf_start = lib->lib;
  Elf32_Dyn *dyn = (Elf32_Dyn*)lib->dyn_segment;

  Elf32_Sym *sym;
  char *strtab;
  Elf32_Word number_of_symbols;
  number_of_symbols = get_symbols(elf_start, dyn, &sym, &strtab);
  if (number_of_symbols < 0)
    return NULL;

  int32_t off = get_offset_of_declared_symbol(number_of_symbols, sym, strtab, name);
  if (off < 0)
    return NULL;
  return elf_start + off;
}
