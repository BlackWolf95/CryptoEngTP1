all: AES

#ByteSubSR: main2.o
#	gcc -o ByteSubSR main2.o

AES: impl1.o
	gcc -o AES impl1.o
impl1.o: impl1.c
	gcc -c -O0 impl1.c -Wall -pedantic -std=c99

clean:
	rm -f *.o AES
