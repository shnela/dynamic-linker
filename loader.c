/* zso1 jk320790 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "loader.h"
#include "elf_reader.h"

#include <sys/mman.h>

char* get_elf(const char *name, int *fd)
{
  /* TODO max elf size */
  static char buf[104857600];
  //  char *buf = mmap(NULL, 1048560, PROT_READ | PROT_WRITE | PROT_EXEC,
  //      MAP_PRIVATE | MAP_ANONYMOUS, 0, 0);
  FILE* elf = fopen(name, "rb");
  fread(buf, sizeof buf, 1, elf);
  *fd = fileno(elf);
  return buf;
}

struct library *library_load(const char *name, void *(*getsym)(const char *name))
{
  int fd;
  char* elf_start = get_elf(name, &fd);

  struct library *lib = malloc(sizeof(struct library));
  if (!lib)
    return NULL;

  char* shared_lib;
  Elf32_Shdr **dynsym = malloc(0x100000);
  //  int libsz = allocate(elf_start, dynsym);
  shared_lib = NaClLoadElfFile(fd);
  if (shared_lib < 0)
    return NULL;
  lib->lib = shared_lib;
  lib->dynsym = *dynsym;

     int numsym = get_symbols(shared_lib, getsym);
     if (numsym < 0)
     return NULL;

  return lib;
}


void *library_getsym(struct library *lib, const char *name)
{
  char* elf_start = lib->lib;
  Elf32_Ehdr *hdr = (Elf32_Ehdr*)elf_start;
  Elf32_Phdr *phdr = (Elf32_Phdr *)(elf_start + hdr->e_phoff);

  int i;
  for(i=0; i < hdr->e_phnum; ++i) {
    Elf32_Dyn *dyn;
    Elf32_Sym *sym;
    Elf32_Word *hash;
    char* strtab;
    char* sym_name;
    Elf32_Word sym_cnt;

    if(phdr[i].p_type == PT_DYNAMIC) {
      dyn = (Elf32_Dyn*)(elf_start +  phdr[i].p_vaddr);

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
      while(dyn->d_tag != DT_NULL)
      {
        if (dyn->d_tag == DT_HASH)
        {
          /* Get a pointer to the hash */
          /* TODO OK? */
          hash = (Elf32_Word*)(elf_start + dyn->d_un.d_ptr);

          /* The 2nd word is the number of symbols */
          sym_cnt = hash[1];

        }
        else if (dyn->d_tag == DT_STRTAB)
        {
          /* Get the pointer to the string table */
          /* TODO ok? */
          strtab = elf_start + dyn->d_un.d_ptr;
        }
        else if (dyn->d_tag == DT_SYMTAB)
        {
          /* Get the pointer to the first entry of the symbol table */
          /* TODO ok ? */
          sym = (Elf32_Sym*)(elf_start + dyn->d_un.d_ptr);

          /* Iterate over the symbol table */
          Elf32_Word sym_index;
          for (sym_index = 0; sym_index < sym_cnt; sym_index++)
          {
            /* get the name of the i-th symbol.
             * This is located at the address of st_name
             * relative to the beginning of the string table. */
            sym_name = &strtab[sym[sym_index].st_name];
            //            sym_name[5] = 0;
//            printf ("%s|0x%x\n", sym_name, sym[sym_index].st_value);
            if (!strcmp(name, sym_name))
              return elf_start + sym[sym_index].st_value;

            /* TODO important! */
            //            symbol_names->push_back(string(sym_name));
          }
        }

        /* move pointer to the next entry */
        dyn++;
      }
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
