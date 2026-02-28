#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

unsigned char* Read_File (char fileName[], int *fileLen);
void Write_File(char fileName[], char input[], int input_length);
unsigned char* Hash_SHA256(unsigned char* input, unsigned long inputlen);
void byte2Hex(char output[], unsigned char input[], int inputlength);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* AES_CTR(unsigned char* key, unsigned char* message);
unsigned char* HMAC_SHA256(unsigned char* key, int keyLength, unsigned char* input, unsigned long inputLength);


int main(int argc, char *argv[]) {
    // Fethc message
    int messageLength;
    unsigned char* message = Read_File(argv[1], &messageLength);

    // Fetch shared seed
    int seedLength;
    unsigned char* sharedSeed = Read_File(argv[2], &seedLength);

    // Generate initial key
    unsigned char* initialKey = PRNG(sharedSeed, seedLength, 32);

    // Parse message into array and encrypt each message
    unsigned char *cipherTexts[10];
    unsigned char keys[10][1024];
    unsigned char hmacs[10][32];
    unsigned char *currentMessage = malloc(1024);
    int currentMessagePos = 0;
    int messageCount = 0;

    mempcpy(keys[0], initialKey, 32);
    for (int x = 0; x < messageLength; x++) {
        if (message[x] == '\n' || x == messageLength-1) {
            if (x == messageLength-1) {
                currentMessage[currentMessagePos] = message[x];
                currentMessagePos++;
            }
            currentMessage[currentMessagePos] = '\0';
            currentMessagePos = 0;
            cipherTexts[messageCount] = AES_CTR(initialKey, currentMessage);

            unsigned char* hmac_for_this_round = HMAC_SHA256(initialKey, 32, cipherTexts[messageCount], 1024);
            
            //copy from mem to the HMAC aggregation array
            memcpy(hmacs[messageCount], hmac_for_this_round, 32);

            //free the pointer for next round
            free(hmac_for_this_round);
        
            //generate new key for next message -> each message needs its own key, derived from previous key
            unsigned char *nextKey = Hash_SHA256(initialKey, 32);
            free(initialKey);
            initialKey = nextKey;

            messageCount++;
            if (messageCount < 10) //prevents out of bound memcpy -> should stop at memcpy(keys[9])
                memcpy(keys[messageCount], initialKey, 32);
        }
        else {
            currentMessage[currentMessagePos] = message[x];
            currentMessagePos++;
        }
    }
    free(currentMessage);

    unsigned char hexCiphers[2049 * 10];
    unsigned char hexHMAC[65*10];
    unsigned char hexKeys[65*10];
    for (int x = 0; x < messageCount; x++) {
        unsigned char hexCipher[2049];
        byte2Hex(hexCipher, cipherTexts[x], 1024);
        memcpy(hexCiphers + (2049 * x), hexCipher, 2048);
        if (x != messageCount-1) {
            hexCiphers[2049 * x + 2048] = '\n';  // newline at end of each cipher
        }
        
        unsigned char hmacHex[65];
        byte2Hex(hmacHex, hmacs[x], 32);
        memcpy(hexHMAC + (65 * x), hmacHex, 64);
        if (x != messageCount-1) {
            hexHMAC[65 * x + 64] = '\n'; 
        }

        unsigned char keyHex[65];
        byte2Hex(keyHex, keys[x], 32);
        memcpy(hexKeys + (65 * x), keyHex, 64);
        if (x != messageCount-1) {
            hexKeys[65 * x + 64] = '\n'; 
        }
    }

    unsigned char aggregateHMAC[32];
    unsigned char *currentHash = Hash_SHA256(hmacs[0], 32);
    memcpy(aggregateHMAC, currentHash, 32);
    free(currentHash);
    for (int x = 1; x < messageCount; x++) {
        unsigned char currentAggregate[64];
        memcpy(currentAggregate, aggregateHMAC, 32);
        memcpy(currentAggregate+32, hmacs[x], 32);
        
        unsigned char *currentHash = Hash_SHA256(currentAggregate, 64);
        memcpy(aggregateHMAC, currentHash, 32);
        free(currentHash);
    }
    unsigned char aggregateHMACHex[64];
    byte2Hex(aggregateHMACHex, aggregateHMAC, 32);

    
    Write_File("Ciphertexts.txt", hexCiphers, (2049 * 10 - 1));
    Write_File("IndividualHMACs.txt", hexHMAC, (65 * 10 - 1));
    Write_File("Keys.txt", hexKeys, (65 * 10 - 1));
    Write_File("AggregatedHMAC.txt", aggregateHMACHex, 64);
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
    int temp_size = ftell(pFile); //get file size
    fseek(pFile, 0L, SEEK_SET);
    unsigned char *output = (unsigned char*) malloc(temp_size + 1); //messageLength variable from main +1 for null
	fread(output, 1, temp_size, pFile); //freads(output buffer, size of element, how many elements to read, input file)
    output[temp_size] = '\0'; //null terminate after the data of temp_size
	fclose(pFile);

    *fileLen = temp_size;
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

    return result;
}

