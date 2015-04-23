/* zso1 jk320790 */
#ifndef ELF_READER_H
#define ELF_READER_H

#include <elf.h>

/* maps elf LOAD segments file and sets pointer to them, returns mapped bytes or -1*/
size_t map_elf(char* name, void **mapped_load);

/* returns pointer to dynamic segment of mapped elf file */
void* get_dyn_segment(char *elf);

/* sets symbols to symol table and strtab, returns number of symbols or -1 */
int get_symbols(char *elf_start, Elf32_Dyn *dyn, Elf32_Sym **symbols, char **strtab);

int do_relocations(char *elf_start, Elf32_Dyn *dyn, void *(*getsym)(const char *name));

#endif
