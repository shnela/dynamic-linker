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

void free_allocated(void *lib, void *mapped_lib, int mapped_size, void *protections)
{
  free(lib);
  munmap(mapped_lib, mapped_size);
  free(protections);
}

struct library *library_load(const char *name, void *(*getsym)(const char *name))
{
  struct library *lib = malloc(sizeof(struct library));
  if (!lib)
    return NULL;

  void *mapped_lib;
  size_t mapped_size;
  struct protect *protections;
  int number_of_protections;
  mapped_size = map_elf(name, &mapped_lib, &protections, &number_of_protections);
  if (mapped_size < 0) {
    free(lib);
    return NULL;
  }
  lib->lib = mapped_lib;

  void *dyn_segment;
  dyn_segment = get_dyn_segment(mapped_lib);
  if (!dyn_segment) {
    free_allocated(lib, mapped_lib, mapped_size, protections);
    return NULL;
  }
  lib->dyn_segment = dyn_segment;

  if (do_relocations((char*)mapped_lib, (Elf32_Dyn*)dyn_segment, getsym) < 0) {
    free_allocated(lib, mapped_lib, mapped_size, protections);
    return NULL;
  }

  /* change protection lvl of segments */
  int i;
  for (i = 0; i < number_of_protections; i++)
  {
    if (mprotect(protections + i, protections[i].size, protections[i].prot) < 0) {
      free_allocated(lib, mapped_lib, mapped_size, protections);
      return NULL;
    }
  }
  free(protections);

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
