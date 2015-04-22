# %.so: %.c hello.h
# 	gcc -m32 -shared -fPIC -o $@ $< -nostdlib -Wl,--hash-style=sysv
# 
# textrel.so: textrel.c hello.h
# 	gcc -m32 -shared -o $@ $< -nostdlib -Wl,--hash-style=sysv
# 
# test%: test%.c %.so
# 	gcc -m32 -o $@ $< libloader.so -Wl,-rpath,.


test: test.c libloader.so
	gcc -m32 -o test test.c libloader.so -g

libloader.so: libloader.o elf_reader.o
	ld -melf_i386 -r libloader.o elf_reader.o -o libloader.so

libloader.o: loader.c loader.h
	gcc -m32 -c -o libloader.o loader.c -g

elf_reader.o: elf_reader.h elf_reader.c
	gcc -m32 -c -o elf_reader.o elf_reader.c -g

clean:
	rm -f *.so *.o ./test
