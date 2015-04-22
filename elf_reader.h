/* zso1 jk320790 */
#include <elf.h>

/* allocates library in memeory with all premisiosns */
int allocate(char* hdr, Elf32_Shdr **dynsym);

/* gets symbols from elf and returns number of pairs sym:addr allocated in symbols */
int get_symbols(char *elf, void *(*getsym)(const char *name));

void* find_sym(const char* name, Elf32_Shdr* shdr, const char* strings, const char* src, char* dst);
