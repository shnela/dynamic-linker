#ifndef LOADER_H
#define LOADER_H
#include <elf.h>

#ifdef __cplusplus
extern "C" {
#endif

struct library {
  void *lib;
  Elf32_Shdr *dynsym;
};



struct library *library_load(const char *name, void *(*getsym)(const char *name));
void *library_getsym(struct library *lib, const char *name);

#ifdef __cplusplus
}
#endif

#endif
