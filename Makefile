libloader.so: libloader.o elf_reader.o
	gcc -m32 --shared libloader.o elf_reader.o -o libloader.so

libloader.o: loader.c loader.h
	gcc -m32 -c -o libloader.o loader.c

elf_reader.o: elf_reader.h elf_reader.c
	gcc -m32 -c -o elf_reader.o elf_reader.c

clean:
	rm -f *.so *.o
