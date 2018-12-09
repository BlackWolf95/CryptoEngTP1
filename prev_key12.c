#include "aes-128_enc.h"
#include <stdlib.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>

//
static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

//printing any uint8_t array
int print_array_uint8(uint8_t *array, int length)
{
  //printf("\nPrinting array val:");
  for (int i = 0; i < length;i++){
    printf("%x ",array[i]);
  }
  printf("\n");
  return 0;
}
//printing finished
void copyArr(uint8_t l[], uint8_t r[],int length){
  for(int i = 0; i<length; i++)
    l[i] = r[i];
}


void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round)//will be needed for decryption
{
	/* WRITE ME */


		int i;
		for (i = 15; i > 3; i--)
		{
			prev_key[i] = next_key[i] ^ prev_key[i - 4];
		}

		prev_key[3] = next_key[3] ^ S[next_key[12]];
		prev_key[2] = next_key[2] ^ S[next_key[15]];
		prev_key[1] = next_key[1] ^ S[next_key[14]];
		prev_key[0] = next_key[0] ^ S[next_key[13]] ^ RC[round];

}


int main()
{
	//uint8_t prev_key[16];

	int pk,nk;
	int i;
	uint8_t next_key[16]={
  0x13,0x11,0x1d,0x7f,
  0xe3,0x94,0x4a,0x17,
  0xf3,0x07,0xa7,0x8b,
  0x4d,0x2b,0x30,0xc5
};

  for (i = 9; i >= 0; i--) {
    prev_aes128_round_key(next_key, next_key, i);
    printf("i=%d, decryption key\n",i+1 );
    print_array_uint8(next_key, 16);
    //copyArr(next_key,prev_key, 16);
  }
/*uint8_t next_key[16]={
	0x13,0xe3,0xf3,0x4d,
	0x11,0x94,0x07,0x07,
	0x1d,0x4a,0xa7,0xa7,
	0x7f,0x17,0x8b,0xc5
};*/
/*for (i = 0; i < 16; i++)
{
	//block[i] ^= key[i];
	ekey2[i]   = next_key[i];
}


printf("ROUND %d\n", 10);
printf("next_key:\n");
print_array_uint8(ekey2, 16);
prev_aes128_round_key(ekey2 , ekey2+16, 0);
//printf("prev_key:\n");
//print_array_uint8(ekey2, 32);

pk = 0;//what is it???
nk = 16;
//copyArr(next_key, prev_key,16);
  for (i = 8; i >= 0 ; i--) {
		printf("ROUND %d\n", i+1);
		printf("next_key:\n");
		print_array_uint8(ekey2, 16);
		pk = (pk + 16) & 0x10;//for prev
		nk = (nk + 16) & 0x10;//for next
			printf("In round PK=%d NK=%d\n",pk,nk);
    //copyArr(next_key, prev_key,16);
    prev_aes128_round_key(ekey2 + nk, ekey2 + pk, i);
		printf("prev_key:\n");
    print_array_uint8(ekey2, 16);
    //copyArr(next_key, prev_key,16);
  }
	printf("In last round PK=%d NK=%d\n",pk,nk);*/



}
