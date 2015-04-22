/* zso1 jk320790 */
#include <elf.h>

/* maps elf LOAD segments file and sets pointer to them, returns mapped bytes or -1*/
size_t map_elf(const char* name, void **mapped_load);

/* returns pointer to dynamic segment of mapped elf file */
void* get_dyn_segment(char *elf);
