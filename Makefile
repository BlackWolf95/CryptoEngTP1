all: AES2 AES3 AES4

AES4: q21.o
	gcc -o AES4 q21.o
q21.o: q21.c
	gcc -c -O0 q21.c -Wall -pedantic -std=c99


AES3: q13_F.o
	gcc -o AES3 q13_F.o
q13_F: q13_F.c
	gcc -c -O0 q13_F.c -Wall -pedantic -std=c99


AES2: prev_key12.o
	gcc -o AES2 prev_key12.o
prev_key12.o: prev_key12.c
	gcc -c -O0 prev_key12.c -Wall -pedantic -std=c99


clean:
	rm -f *.o AES2 AES3 AES4
