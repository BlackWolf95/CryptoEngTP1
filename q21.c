#include "aes-128_enc.h"
#include <sys/time.h>
#include <stdlib.h>
#include <pthread.h>
static const uint8_t RC[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
/*might be needed*/
uint8_t ct[16] = {
  0xc8, 0x71, 0xbe, 0x5a,
  0xbc, 0x35, 0xeb, 0x92,
  0x10, 0x9a, 0x60, 0x7f,
  0x6e, 0xba, 0x92, 0xad
 };

uint8_t pt[16] = {
  0xff, 0x67, 0x67, 0x67,
  0x67, 0x67, 0x67, 0x67,
  0x67, 0x67, 0x67, 0x67,
  0x67, 0x67, 0x67, 0x67
};

uint8_t master_key[16]={
 0x00,0x01,0x02,0x03,
 0x04,0x05,0x06,0x07,
 0x08,0x09,0x0a,0x0b,
 0x0c,0x0d,0x0e,0x0f
};
/* will be changed as necessary*/
uint8_t xtime(uint8_t p)
{
	uint8_t m = p >> 7;

	m ^= 1;
	m -= 1;
	m &= 0x1B;//calculates the modulus of the multiplication, by the irreducible polynomial of 0x1B, change to 0x7B

	return ((p << 1) ^ m);
}

//print any array
int print_array2_uint8(uint8_t array[][16], int r, int c)
{
  //printf("\nPrinting array val:");
  for (int i = 0; i < r; i++){
    for (int j = 0; j < c; j++) {
      printf("%x ",array[i][j]);
    }
    printf("\n ");
  }
  printf("\n");
  printf("printing finished\n");
  return 0;
}

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
void xor(uint8_t l[], uint8_t r[], uint8_t XORed[], int length){
  for(int i = 0; i < 16; i++) {
      XORed[i] = l[i] ^ r[i];
  }
}

 void aes_round(uint8_t block[AES_BLOCK_SIZE], uint8_t round_key[AES_BLOCK_SIZE], int lastround)
 {
 	int i;
 	uint8_t tmp;

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

 void prev_aes128_round_key(const uint8_t next_key[16], uint8_t prev_key[16], int round)
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
 	uint8_t ekey[32];
 	int i, pk, nk;

 	for (i = 0; i < 16; i++)
 	{
 		block[i] ^= key[i];
 		ekey[i]   = key[i];
 	}

 	next_aes128_round_key(ekey, ekey+16 , 0);
 	pk = 0;
 	nk = 16;
 	for (i = 1; i < nrounds; i++)
 	{
 		aes_round(block, ekey + nk, 0);
 		pk = (pk + 16) & 0x10;
 		nk = (nk + 16) & 0x10;
 		next_aes128_round_key(ekey + pk, ekey + nk, i);
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



 int distinguisher(uint8_t pt2[256][16],uint8_t ct2[256][16],uint8_t next_key[]){
   uint8_t temp = 0x67;
   for (uint8_t i = 0x00; i < 0xff; i = i+0x01) {
   	pt2[i][0] = i;
   	for(int j = 1; j < 16; j++){
   		pt2[i][j] = temp;
   	}
   }
   for(int j = 1; j < 16; j++){
   	pt2[255][j] = temp;
   }
   pt2[255][0] = 0xff;
   //printing pt2
   //printf("pt2-FROM distinguisher\n");
   //print_array2_uint8(pt2, 256, 16);

   for (int i = 0; i < 256; i++) {
   	uint8_t pblock[16];
   	uint8_t cblock[16];
   	for(int j = 0; j < 16; j++) {
   		pblock[j] = pt2[i][j];
   	}
   	aes128_enc(pblock,next_key,3,1);//pblock stores the encrypted block
   	for(int j = 0; j < 16; j++) {
   		ct2[i][j] = pblock[j];//copy pblock into ct2
   	}
   }
   //printf("ct2-FROM distinguisher\n");
   //print_array2_uint8(ct2, 256, 16);
   printf("MASTER KEY for distinguisher test:\n");
   print_array_uint8(next_key, 16);

   uint8_t XORed[16];
   for(int j = 0; j < 16; j++) {
   	XORed[j] = ct2[0][j] ^ ct2[1][j];
   }
   for (int i = 2; i < 256; i++) {
   	for(int j = 0; j < 16; j++) {
   		XORed[j] = XORed[j] ^ ct2[i][j];
   	}
   }
   printf("XOR RESULT FROM distinguisher:\n");
   print_array_uint8(XORed, 16);
   return 0;
 }

 int encrypter(uint8_t pt2[256][16],uint8_t ct2[256][16],uint8_t next_key[]){
   //uint8_t temp = 0x67;

   uint8_t temp;
   struct timeval tm;
   gettimeofday(&tm, NULL);
   srandom(tm.tv_sec + tm.tv_usec * 1000000ul);
   temp = (uint8_t)random();
   //printf("temp=%x\n",temp );
   for (uint8_t i = 0x00; i < 0xff; i = i+0x01) {
    pt2[i][0] = i;
    for(int j = 1; j < 16; j++){
      pt2[i][j] = temp;
    }
   }
   for(int j = 1; j < 16; j++){
    pt2[255][j] = temp;
   }
   pt2[255][0] = 0xff;
   //printing pt2
   //printf("pt2-FROM encrypter\n");
  //print_array2_uint8(pt2, 256, 16);
   for (int i = 0; i < 256; i++) {
    uint8_t pblock[16];
    uint8_t cblock[16];
    for(int j = 0; j < 16; j++) {
      pblock[j] = pt2[i][j];
    }
    aes128_enc(pblock,next_key,4,0);//pblock stores the encrypted block of 3.5 rounds encryption
    for(int j = 0; j < 16; j++) {
      ct2[i][j] = pblock[j];//copy pblock into ct2
    }
   }
   //printf("ct2-FROM encrypter\n");
  //print_array2_uint8(ct2, 256, 16);
   uint8_t XORed[16];
   for(int j = 0; j < 16; j++) {
    XORed[j] = ct2[0][j] ^ ct2[1][j];
   }
   for (int i = 2; i < 256; i++) {
    for(int j = 0; j < 16; j++) {
      XORed[j] = XORed[j] ^ ct2[i][j];
    }
   }
   return 0;
 }



int part_decrypt_half(uint8_t ct3[][16], uint8_t key[], uint8_t decrypted_ct3[][16]){

  for (int i = 0; i < 256; i++ ){

    uint8_t state_arr[16];
    for(int j = 0; j < 16; j++){
      state_arr[j] = ct3[i][j];
    }
    for ( int k = 0; k<16; k++){
      state_arr[k] ^= key[k];
      state_arr[k] = Sinv[state_arr[k]];
    }
    for(int j = 0; j < 16; j++){
      ct3[i][j] = state_arr[j];
    }
  }
  //now do a XOR op for the first column
  uint8_t xor1 = 0x00;
   printf("Final Xor value after partial decryption by last round key updholding distinguisher property: \n");
  for(int j= 0; j < 16; j++){
    for (int i = 0; i < 256; i++ )
      xor1^= ct3[j][0];
    printf("%d ",xor1);
  }
  printf("\n");
  return 0;
}

uint8_t decryption_half(uint8_t value, uint8_t key){
  uint8_t decrypted;
  decrypted = value^key;
  decrypted = Sinv[decrypted];
  return decrypted;
}

int main() {
  uint8_t pt2d[256][16];
  uint8_t ct2d[256][16];

  uint8_t pt1[256][16];
  uint8_t ct1[256][16];

  uint8_t pt2[256][16];
  uint8_t ct2[256][16];

  uint8_t pt3[256][16];
  uint8_t ct3[256][16];

  uint8_t pt4[256][16];
  uint8_t ct4[256][16];
  uint8_t next_key[16];
  uint8_t next_key3[16]={
   0x00,0x01,0x02,0x03,
   0x04,0x05,0x06,0x07,
   0x08,0x09,0x0a,0x0b,
   0x0c,0x0d,0x0e,0x0f
 };
  for(int j =0; j<16; ++j){
    uint8_t temp3;
    struct timeval tm;
    gettimeofday(&tm, NULL);
    srandom(tm.tv_sec + tm.tv_usec * 1000000ul);
    temp3 = (uint8_t)random();
    next_key[j] = temp3;
  }
  printf("MASTER KEY for lambda set:\n" );
  print_array_uint8(next_key, 16);
  uint8_t decrypted_ct3[256][16];
  distinguisher(pt2d, ct2d, next_key3);//just to execute the distinguisher otherwise
  encrypter(pt1, ct1, next_key);//just to encrypt the pts otherwise
  encrypter(pt2, ct2, next_key);
  encrypter(pt3, ct3, next_key);
  encrypter(pt4, ct4, next_key);

  //Create lambda set of 4 plaintext and corresponding ciphertext
  //send first ciphertext column for decryption of first byte, and one array to hold corresponding keys
  uint8_t cand_k1[16]={0x47, 0xf7, 0xf7, 0xbc, 0x95,
                       0x35, 0x3e, 0x03, 0xf9, 0x6c,
                       0x32, 0xbc, 0xfd, 0x05, 0x8d, 0xfd};
  part_decrypt_half(ct2d, cand_k1, decrypted_ct3);//just passing the last used round key to get an all 0 value


  uint8_t lookup_int[256];
  uint8_t temp2 = 0x00;
  for(int i=0; i<256; i++)  {
    lookup_int[i] = temp2;
    temp2 = temp2+0x01;
  }

  //now we go for decrypting for lambda-set of plaintexts

  int lambda_keys1[256][16];
  int lambda_keys2[256][16];
  int lambda_keys3[256][16];
  int lambda_keys4[256][16];

  //stores the possible candidate keys for each plaintext block of lambda set
  for(int j =0; j<16; ++j){
    for(int i = 0; i<256; ++i){
      //uint8_t xor_block1 = 0x00, xor_block2 = 0x00, xor_block3 = 0x00, xor_block4 = 0x00;
      int xor_block1 = 0, xor_block2 = 0, xor_block3 = 0, xor_block4 = 0;
      for(int k = 0; k<256; ++k){
        xor_block1 ^= decryption_half(ct1[k][j], lookup_int[i]);
        xor_block2 ^= decryption_half(ct2[k][j], lookup_int[i]);
        xor_block3 ^= decryption_half(ct3[k][j], lookup_int[i]);
        xor_block4 ^= decryption_half(ct4[k][j], lookup_int[i]);
      }
      if(xor_block1 == 0x00){
      lambda_keys1[i][j] = 1; //if xor results are 0, then its a candidate key
      //printf("CHECK1 i=%d j=%d %x\n",i,j,lookup_int[j]);
    }
      else
      lambda_keys1[i][j] = 0;//else it is not

      if(xor_block2 == 0x00){
      lambda_keys2[i][j] =1;
    //printf("CHECK2 i=%d j=%d %x\n",i,j,lookup_int[j]);
  }
      else
      lambda_keys2[i][j] = 0;

      if(xor_block3 == 0x00){
      lambda_keys3[i][j] = 1;
    //printf("CHECK3 i=%d j=%d %x \n",i,j,lookup_int[j]);
  }
      else
      lambda_keys3[i][j] = 0;

      if(xor_block4 == 0x00){
      lambda_keys4[i][j] = 1;
    //printf("CHECK4 i=%d j=%d %x \n",i,j,lookup_int[j]);
  }
      else
      lambda_keys4[i][j] = 0;
      }
      //xor_block1 = 0x00; xor_block2 = 0x00; xor_block3 = 0x00; xor_block4 = 0x00;//reinitialize to 0
    }


printf("decrypting key!\n" );

  uint8_t decrypted_key[16];
  for(int i = 0; i<16; i=i+1){
    //printf("EXECUTED1\n");
    for(int j = 0; j<256; j=j+1){
      //printf("EXECUTED2\n");
      if((lambda_keys1[j][i]==1) && (lambda_keys2[j][i]==1) && (lambda_keys3[j][i]==1) && (lambda_keys4[j][i] == 1)){
        decrypted_key[i] = lookup_int[j];//stores the possible key for the location
        //printf("EXECUTED3\n");
        //printf("i=%d %d\n",j,lookup_int[j] );
      }
    }
  }
printf("Decrypted key from lambda set\n");
print_array_uint8(decrypted_key, 16);


  for (int i = 3; i >= 0; i--) {
    prev_aes128_round_key(decrypted_key, decrypted_key, i);
    printf("i=%d, decryption key\n",i+1 );
    print_array_uint8(decrypted_key, 16);
    //copyArr(next_key,prev_key, 16);
  }

  /*printf("PRINTING lambda_keys1\n");
  print_array2_uint8(lambda_keys1, 256, 16);
  printf("PRINTING lambda_keys2\n");
  print_array2_uint8(lambda_keys2, 256, 16);
  printf("PRINTING lambda_keys3\n");
  print_array2_uint8(lambda_keys3, 256, 16);
  printf("PRINTING lambda_keys4\n");
  print_array2_uint8(lambda_keys4, 256, 16);*/

  printf("Decrypted key from lambda set\n");
  print_array_uint8(decrypted_key, 16);
  //print_array_uint8(lookup_int, 256);

//*/
  return 0;
}
