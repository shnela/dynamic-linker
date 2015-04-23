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
      return elf_start + sym[sym_index].st_value;
    }
  }
  return NULL;
}
/*
   DT_PLTRELSZ
   DT_JMPREL
   DT_PLTGOT
   DT_STRTAB
   DT_SYMTAB
   DT_REL
   DT_RELSZ
   DT_HASH
   */
