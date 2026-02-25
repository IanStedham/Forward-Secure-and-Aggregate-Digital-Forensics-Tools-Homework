#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void Write_File(char fileName[], char input[], int input_length);
unsigned char* Read_File(char fileName[], int *fileLen);
unsigned char* AES_CTR(unsigned char* key, unsigned char* message);
unsigned char* HMAC_SHA256(unsigned char* key, int keyLength, unsigned char* input, unsigned long inputLength)


int main(int argc, char *argv[]) {
    // Fethc message
    int messageLength;
    unsigned char* message = Read_File(argv[1], &messageLength);

    // Fetch shared seed
    int seedLength;
    unsigned char* sharedSeed = Read_File(argv[2], &seedLength);

    // Generate initial key
    unsigned char* initialKey = PRNG(sharedSeed, seedLength, 1024);

    // Parse message into array with each element being its own message
    unsigned char individualMessages[10][1024];
    unsigned char** cipherTexts = malloc(10 * sizeof(unsigned char*));
    unsigned char *currentMessage = malloc(1024);
    int currentMessagePos = 0;
    int messageCount = 0;


    for (int x = 0; x < messageLength; x++) {
        // printf("%d\n", x);
        if (message[x] == '\n') {
            currentMessage[currentMessagePos] = '\0';
            currentMessagePos = 0;
            printf("message: %s\n", currentMessage);
            cipherTexts[messageCount] = AES_CTR(initialKey, currentMessage);

            //generate new key for next message -> each message needs its own key, derived from previous key
            unsigned char *nextKey = Hash_SHA256(initialKey, 32);
            free(initialKey);
            initialKey = nextKey;
            
            printf("cipher text %d: %s\n\n", messageCount, cipherTexts[messageCount]);
            messageCount++;
        }
        else {
            currentMessage[currentMessagePos] = message[x];
            currentMessagePos++;
        }
    }
}

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
	fgets(output, temp_size, pFile);
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
    unsigned char *HMAC = malloc(SHA256_DIGEST_LENGTH);

    HMAC(EVP_sha256(), key, keyLength, input, inputLength)

    return HMAC;
}
