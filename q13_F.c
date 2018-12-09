#include "aes-128_enc.h"
#include <time.h>

static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

uint8_t xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x1B;//calculates the modulus of the multiplication, by the irreducible polynomial of 0x1B, change to 0x7B

	return ((p << 1) ^ m);
}

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
//copying an array done

void xor(uint8_t l[], uint8_t r[], uint8_t XORed[], int length){
  for(int i = 0; i < 16; i++) {
      XORed[i] = l[i] ^ r[i];
  }



}

/*CODE FROM TAR BALL*/
void aes_round(uint8_t block[AES_BLOCK_SIZE], uint8_t round_key[AES_BLOCK_SIZE], int lastround)
{
	int i;
	uint8_t tmp;

	/*
	 * SubBytes + ShiftRow
	 */
	/* Row 0 */
	block[ 0] = S[block[ 0]];
	block[ 4] = S[block[ 4]];
	block[ 8] = S[block[ 8]];
	block[12] = S[block[12]];
	/* Row 1 */
	tmp = block[1];
	block[ 1] = S[block[ 5]];
	block[ 5] = S[block[ 9]];
	block[ 9] = S[block[13]];
	block[13] = S[tmp];
	/* Row 2 */
	tmp = block[2];
	block[ 2] = S[block[10]];
	block[10] = S[tmp];
	tmp = block[6];
	block[ 6] = S[block[14]];
	block[14] = S[tmp];
	/* Row 3 */
	tmp = block[15];
	block[15] = S[block[11]];
	block[11] = S[block[ 7]];
	block[ 7] = S[block[ 3]];
	block[ 3] = S[tmp];

	/*
	 * MixColumns
	 */
	for (i = lastround; i < 16; i += 4) /* lastround = 16 if it is the last round, 0 otherwise */
	{
		uint8_t *column = block + i;
		uint8_t tmp2 = column[0];
		tmp = column[0] ^ column[1] ^ column[2] ^ column[3];

		column[0] ^= tmp ^ xtime(column[0] ^ column[1]);
		column[1] ^= tmp ^ xtime(column[1] ^ column[2]);
		column[2] ^= tmp ^ xtime(column[2] ^ column[3]);
		column[3] ^= tmp ^ xtime(column[3] ^ tmp2);
	}

	/*
	 * AddRoundKey
	 */
	for (i = 0; i < 16; i++)
	{
		block[i] ^= round_key[i];
	}
}

void next_aes128_round_key(const uint8_t prev_key[16], uint8_t next_key[16], int round)
{
	int i;

	next_key[0] = prev_key[0] ^ S[prev_key[13]] ^ RC[round];
	next_key[1] = prev_key[1] ^ S[prev_key[14]];
	next_key[2] = prev_key[2] ^ S[prev_key[15]];
	next_key[3] = prev_key[3] ^ S[prev_key[12]];

	for (i = 4; i < 16; i++)
	{
		next_key[i] = prev_key[i] ^ next_key[i - 4];
	}
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

void aes128_enc(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull)
{
	uint8_t ekey[32];// why 32 instead of 16 size??
	int i, pk, nk;//what is the role of pk, nk??

	for (i = 0; i < 16; i++)
	{
		block[i] ^= key[i];
		ekey[i]   = key[i];
	}
next_aes128_round_key(ekey, ekey+16 , 0); //why is this one needed??
pk = 0;
nk = 16;
for (i = 1; i < nrounds; i++)
{
  aes_round(block, ekey + nk, 0);
  pk = (pk + 16) & 0x10;
  nk = (nk + 16) & 0x10;
  next_aes128_round_key(ekey + pk, ekey + nk, i);// what's the job of ekey + pk, ekey + nk??
}
if (lastfull)
{
  aes_round(block, ekey + nk, 0);
}
else
{
  aes_round(block, ekey + nk, 16);
}
}

int aes_enc3(uint8_t next_key[16],uint8_t pt[16],uint8_t ct[16]){
  //pass pt and copy encrypted pt to ct
  //aes128_enc(pt, next_key, 3, 1);
  aes128_enc(pt, next_key, 3, 0);
  printf("In aes_enc3\n" );
  print_array_uint8(pt, 16);
  copyArr(ct, pt, 16);
  return 0;
}


int main(){
  uint8_t next_key1[16]={
  	0x00,0x01,0x02,0x03,
  	0x04,0x05,0x06,0x07,
  	0x08,0x09,0x0a,0x0b,
  	0x0c,0x0d,0x0e,0x0f
  };
  /*uint8_t next_key2[16]={
  	0x20,0x31,0x42,0x53,
  	0x24,0x35,0x46,0x57,
  	0x28,0x39,0x4a,0x5b,
  	0x2c,0x3d,0x4e,0x5f
  };*/
  uint8_t next_key2[16]={
  	0x00,0x01,0x02,0x03,
  	0x04,0x05,0x06,0x07,
  	0x08,0x09,0x0a,0x0b,
  	0x0c,0x0d,0x0e,0x0f
  };
  /* pt1 always same as pt2*/
  uint8_t pt1[16]=
  {
   0x00,0x11,0x22,0x33,
   0x44,0x55,0x66,0x77,
   0x88,0x99,0xaa,0xbb,
   0xcc,0xdd,0xee,0xff
  };
  uint8_t pt2[16]=
  {
   0x00,0x11,0x22,0x33,
   0x44,0x55,0x66,0x77,
   0x88,0x99,0xaa,0xbb,
   0xcc,0xdd,0xee,0xff
  };
  /* pt1 always same as pt2*/
  uint8_t ct1[16];
  uint8_t ct2[16];
  uint8_t XORed[16];
  //calling Encryption for E(next_key1,pt), E(next_key2,pt)
  aes_enc3(next_key1, pt1, ct1);
  aes_enc3(next_key2, pt2, ct2);
  //XOR next_key1,ct1 & next_key2,ct2
  xor(next_key1, ct1, ct1, 16);
  xor(next_key2, ct2, ct2, 16);
//XOR the final ciphertexts ct1, ct2

  xor(ct1, ct2, XORed, 16);
  //print the result of ct2
  print_array_uint8(ct2, 16);
  //print the result of ct1
  print_array_uint8(ct1, 16);
  printf("FINAL XOR\n");
  print_array_uint8(XORed, 16);
  return 0;
}
//For F(k1||k2,x) when we have k1!=k2, F!=0 but if k1==k2
//then F results to 0, without using the distinguiser property
