#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

/*============================
        Read from File
==============================*/
unsigned char* Read_File (char fileName[], int *fileLen)
{
    FILE *pFile;
	pFile = fopen(fileName, "r");
	if (pFile == NULL)
	{
		printf("Error opening file.\n");
		exit(0);
	}
    fseek(pFile, 0L, SEEK_END);
    int temp_size = ftell(pFile)+1; //get file size
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size); //messageLength variable from main
	fread(output, 1, temp_size, pFile); //freads(output buffer, size of element, how many elements to read, input file)
    output[temp_size] = '\0'; //null terminate after the data of temp_size
	fclose(pFile);

    *fileLen = temp_size-1;
	return output;
}
/*============================
        Write to File
==============================*/
void Write_File(char fileName[], char input[], int input_length){
  FILE *pFile;
  pFile = fopen(fileName,"w");
  if (pFile == NULL){
    printf("Error opening file. \n");
    exit(0);
  }
  //fputs(input, pFile);
  fwrite(input, 1, input_length, pFile);
  fclose(pFile);
}
/*============================
        SHA-256 Fucntion
==============================*/
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen)
{
    unsigned char *hash = malloc(SHA256_DIGEST_LENGTH);

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    EVP_DigestInit_ex(ctx, EVP_sha256(), NULL);
    EVP_DigestUpdate(ctx, input, inputlen);
    EVP_DigestFinal_ex(ctx, hash, NULL);
    EVP_MD_CTX_free(ctx);

    return hash;
}
/*============================
        convert to Hex 
==============================*/
void byte2Hex(char output[], unsigned char input[], int inputlength){
    for (int i = 0; i < inputlength; i++) {
        sprintf((char*)&output[2*i], "%02x", input[i]);
    }
    output[2 * inputlength] = '\0'; 
}

/*============================
        Showing in Hex 
==============================*/
void show_in_Hex (char name[], unsigned char hex[], int hexlen) {
	printf("%s: ", name);
	for (int i = 0 ; i < hexlen ; i++)
   		printf("%02x", hex[i]);
	printf("\n");
}
/*============================
        hex to bytes 
==============================*/
unsigned char* hex2Bytes(unsigned char hexString[], int *outLen){
    char *hex_string = (char*)hexString;
    int len = strlen(hex_string);
    *outLen = len / 2;
    unsigned char *bytes = (unsigned char*)malloc(*outLen);
    
    for (int i = 0; i < *outLen; i++) {
        sscanf(&hex_string[2*i], "%2hhx", &bytes[i]); 
    }
    
    return bytes;
}
/*============================
        PRNG Fucntion 
==============================*/
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char *pseudoRandomNumber = malloc(prnglen);

    unsigned char nonce[16] = {0};

    EVP_EncryptInit_ex(ctx, EVP_chacha20(), NULL, seed, nonce);

    unsigned char zeros[prnglen];
    memset(zeros, 0, prnglen);

    int outlen;
    EVP_EncryptUpdate(ctx, pseudoRandomNumber, &outlen, zeros, prnglen);
    EVP_EncryptFinal(ctx, pseudoRandomNumber, &outlen);

    EVP_CIPHER_CTX_free(ctx);
    return pseudoRandomNumber;
}
/*============================
      AES-CTR Function 
==============================*/
unsigned char* AES_CTR(unsigned char* key, unsigned char* message) {
    unsigned char IV[16] = "abcdefghijklmnop";

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, IV);

    unsigned char *encryptMessage = malloc(1024);

    int encryptMessageLen;
    EVP_EncryptUpdate(ctx, encryptMessage, &encryptMessageLen, message, 1024);
    EVP_EncryptFinal(ctx, encryptMessage, &encryptMessageLen);
    
    EVP_CIPHER_CTX_free(ctx);
    return encryptMessage;
}

//=====================
// HMAC-SHA256 FUNCTION 
//======================
unsigned char* HMAC_SHA256(unsigned char* key, int keyLength, unsigned char* input, unsigned long inputLength)
{
    unsigned char *result = malloc(SHA256_DIGEST_LENGTH);
    unsigned int hmacLength;
    HMAC(EVP_sha256(), key, keyLength, input, inputLength, result, &hmacLength);

    return HMAC;
}
//=====
// AES_decrypt
// ======
unsigned char* AES_CTR_Decrypt(unsigned char* key, unsigned char* ciphertext) {
    unsigned char IV[16] = "abcdefghijklmnop";
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_256_ctr(), NULL, key, IV);

    unsigned char *plaintext = malloc(1024 + EVP_MAX_BLOCK_LENGTH);
    int outlen;
    EVP_DecryptUpdate(ctx, plaintext, &outlen, ciphertext, 1024);
    EVP_DecryptFinal_ex(ctx, plaintext + outlen, &outlen);

    EVP_CIPHER_CTX_free(ctx);
    return plaintext;
}
