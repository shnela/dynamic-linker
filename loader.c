/* zso1 jk320790 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

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
  if (!dyn_segment)
    return NULL;
  lib->dyn_segment = dyn_segment;

  /*
  int numsym = get_symbols(mapped_lib, getsym);
  if (numsym < 0)
    return NULL;
    */

  return lib;
}


void *library_getsym(struct library *lib, const char *name)
{
  char* elf_start = lib->lib;
  Elf32_Dyn *dyn;

  Elf32_Word *hash;
  char* strtab;
  Elf32_Word number_of_symbols;


  /* Iterate over all entries of the dynamic section until the
   * end of the symbol table is reached. This is indicated by
   * an entry with d_tag == DT_NULL.
   *
   * Only the following entries need to be processed to find the
   * symbol names:
   *  - DT_HASH   -> second word of the hash is the number of symbols
   *  - DT_STRTAB -> pointer to the beginning of a string table that
   *                 contains the symbol names
   *  - DT_SYMTAB -> pointer to the beginning of the symbols table
   */
  dyn = (Elf32_Dyn*)lib->dyn_segment;
  while(dyn->d_tag != DT_NULL)
  {
    if (dyn->d_tag == DT_HASH)
    {
      hash = (Elf32_Word*)(elf_start + dyn->d_un.d_ptr);
      number_of_symbols = hash[1];
    }
    else if (dyn->d_tag == DT_STRTAB)
    {
      strtab = elf_start + dyn->d_un.d_ptr;
    }
    else if (dyn->d_tag == DT_SYMTAB)
    {
      Elf32_Sym *sym;
      sym = (Elf32_Sym*)(elf_start + dyn->d_un.d_ptr);

      char* sym_name;
      Elf32_Word sym_index;
      for (sym_index = 0; sym_index < number_of_symbols; sym_index++)
      {
        sym_name = &strtab[sym[sym_index].st_name];
        if (!strcmp(name, sym_name))
          return elf_start + sym[sym_index].st_value;
      }
    }
    dyn++;
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
