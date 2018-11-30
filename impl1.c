/*
 * AES-128 Encryption
 * Byte-Oriented
 * On-the-fly key schedule
 * Constant-time XTIME
 */

#include "aes-128_enc.h"
#include <time.h>

/*
 * Constant-time ``broadcast-based'' multiplication by $a$ in $F_2[X]/X^8 + X^4 + X^3 + X + 1$
 */
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
//copying finished
/*
 * The round constants
 */
static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};

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

/*
 * Compute the @(round + 1)-th round key in @next_key, given the @round-th key in @prev_key
 * @round in {0...9}
 * The ``master key'' is the 0-th round key
 */
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

/*
 * Compute the @round-th round key in @prev_key, given the @(round + 1)-th key in @next_key
 * @round in {0...9}
 * The ``master decryption key'' is the 10-th round key (for a full AES-128)
 */
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


/*
 * Encrypt @block with @key over @nrounds. If @lastfull is true, the last round includes MixColumn, otherwise it doesn't.$
 * @nrounds <= 10
 */
void aes128_enc(uint8_t block[AES_BLOCK_SIZE], const uint8_t key[AES_128_KEY_SIZE], unsigned nrounds, int lastfull)
{
	uint8_t ekey[32];// why 32 instead of 16 size??
	int i, pk, nk;//what is the role of pk, nk??

	for (i = 0; i < 16; i++)
	{
		block[i] ^= key[i];
		ekey[i]   = key[i];
	}

	//printf("Print block after round 0:\n");
	//print_array_uint8(block, 16);

	next_aes128_round_key(ekey, ekey+16 , 0); //why is this one needed??
//why is this one needed
/*	for(i = 0; i <= 16; i++)
		ekey[i] = ekey[i+16];*/
//why do we need to shift?

	//printf("Key used next_key:\n");
	//print_array_uint8(ekey+16,16);
	/*prev_aes128_round_key(ekey, ekey , 0);
	printf("Key used prev_key:\n");
	print_array_uint8(ekey,16);*/
	pk = 0;
	nk = 16;
	for (i = 1; i < nrounds; i++)
	{
		aes_round(block, ekey + nk, 0);
		//printf("show encrypted block:");
		//print_array_uint8(block, 16);
		pk = (pk + 16) & 0x10;
		nk = (nk + 16) & 0x10;
		next_aes128_round_key(ekey + pk, ekey + nk, i);// what's the job of ekey + pk, ekey + nk??
		//why is this one needed
		/*	for(int i1 = 0; i1 < 16; i1++)
				ekey[i1] = ekey[i1+16];*/
		//why do we need to shift?
		//printf("Key used next_key i=%d:\n", i+1);
		//print_array_uint8(ekey+nk, 16);
		//printf("show entire block:");
		//print_array_uint8(ekey, 32);//show entire block
		///*if(i == nrounds-1)
		//	lastfull = 0;
 	}//, changed for experimenting, report if it doesn't work

	if (lastfull)
	{
		aes_round(block, ekey + nk, 0);
		//printf("show encrypted block:");
		//print_array_uint8(block, 16);
	}
	else
	{
		aes_round(block, ekey + nk, 16);
		//printf("show encrypted block:");
		//print_array_uint8(block, 16);
	}
/*for (i = 0; i < 16; i++)
	{
		block[i] ^= ekey[nk+i];
	}*/
}

int main() {
uint8_t next_key[16]={
	0x00,0x01,0x02,0x03,
	0x04,0x05,0x06,0x07,
	0x08,0x09,0x0a,0x0b,
	0x0c,0x0d,0x0e,0x0f
};
uint8_t pt[16]=
{
 0x00,0x11,0x22,0x33,
 0x44,0x55,0x66,0x77,
 0x88,0x99,0xaa,0xbb,
 0xcc,0xdd,0xee,0xff
};
uint8_t pt2[256][16];
uint8_t ct2[256][16];
//aes128_enc(pt,next_key,10,0);
	//aes128_enc(pt,next_key,3,0);
	//last round after generating last key
	//printf("ENCODED Message:\n");
	//print_array_uint8(pt,16);

//now we will start to apply the prev_key function, by creating the plaintext of 256 * 16 blocks
uint8_t temp = (uint8_t)rand();
for (uint8_t i = 0x00; i < 0xff; i = i+0x01) {
	pt2[i][0] = i;
	//
	for(int j = 1; j < 16; j++){
		pt2[i][j] = temp;
	}
	//printf("\ntemp =%x\n",temp );
}
//for last row, weirdly not workinguint8_t temp = (uint8_t)rand();
//uint8_t temp = (uint8_t)rand();
for(int j = 1; j < 16; j++){
	pt2[255][j] = temp;
}
pt2[255][0] = 0xff;
//printing pt2
printf("pt2\n");
for (int i = 0; i < 256; i++) {
	for(int j = 0; j < 16; j++) {
		printf("%x ",pt2[i][j]);
	}
	printf("\n");
}

//now we are encrypting pt2

for (int i = 0; i < 256; i++) {
	uint8_t pblock[16];
	uint8_t cblock[16];
	//copy pt2[i][0]-pt2[i][15] to pblock, encrypt it
	for(int j = 0; j < 16; j++) {
		pblock[j] = pt2[i][j];
	}
	aes128_enc(pblock,next_key,3,1);//pblock stores the encrypted block
	for(int j = 0; j < 16; j++) {
		ct2[i][j] = pblock[j];//copy pblock into ct2
	}
}
// now printing c2
printf("ct2\n");
for (int i = 0; i < 256; i++) {
	for(int j = 0; j < 16; j++) {
		printf("%x ",ct2[i][j]);
	}
	printf("\n");
}
// now XOR all of those ct2 values
uint8_t XORed[16];//let's do for the first and second rows
for(int j = 0; j < 16; j++) {
	XORed[j] = ct2[0][j] ^ ct2[1][j];
}
//now for the next 253 rows of ct2
for (int i = 2; i < 256; i++) {
	for(int j = 0; j < 16; j++) {
		XORed[j] = XORed[j] ^ ct2[i][j];
	}
}
//let's print XORed now
printf("XORed:\n");
print_array_uint8(XORed, 16);
	/*printf("Key used:\n");
	print_array_uint8(next_key,16);*/
	return 0;
}
