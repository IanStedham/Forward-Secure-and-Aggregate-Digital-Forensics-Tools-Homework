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
unsigned char* AES_CTR_Decrypt(unsigned char* key, unsigned char* ciphertext);
void hex2Byte(unsigned char output[], char input[], int outputlength);
unsigned char* PRNG(unsigned char *seed, unsigned long seedlen, unsigned long prnglen);
unsigned char* AES_CTR(unsigned char* key, unsigned char* message);
unsigned char* HMAC_SHA256(unsigned char* key, int keyLength, unsigned char* input, unsigned long inputLength);

int main(int argc, char *argv[]) {
    // Bob reads the shared seed from a file named ”SharedSeed.txt”
    int seedLength;
    unsigned char* sharedSeed = Read_File(argv[1], &seedLength);

    //Bobreadstheciphertexts from ”Ciphertexts.txt”
    int cipherLength;
    // unsigned char* cipher = Read_File(argv[2], &cipherLength);
    unsigned char* cipher = Read_File("Ciphertexts.txt", &cipherLength);

    //Bobreadsthe the aggregated HMAC from ”AggregatedHMAC.txt”
    int hmacLength;
    // unsigned char* aggregateHMAC_hex = Read_File(argv[3], &hmacLength);
    unsigned char* aggregateHMAC_hex = Read_File("AggregatedHMAC.txt", &hmacLength);

    //create the initial symmetric key k1 with the shared seed
    unsigned char* initialKey = PRNG(sharedSeed, seedLength, 32);

    //parse the HEX ciphertext messages - one cipherHex message = 2048 hex chars)
    unsigned char cipherTexts[10][1024];
    for (int i = 0;i < 10; i++) {
        char cipherText_hex[2049];
         //each cipher message + newline /n = 2049
         //to get to line i, jump i * 2049 byutes into the buffer and memcpy the 2048 characters (excluding /n)
        memcpy(cipherText_hex, cipher + i * 2049, 2048);
        cipherText_hex[2048] = '\0';
        hex2Byte(cipherTexts[i], cipherText_hex, 1024); //convert received ciphermessage to bytes
    }

    //convert received aggregateHMAC sigma_1-i to bytes
    unsigned char aggregateHMAC_byte_received[32]; 
    hex2Byte(aggregateHMAC_byte_received, (char*)aggregateHMAC_hex, 32);

    //compute the aggregate hmac sigma_1-i
    unsigned char aggregateHMAC[32];
    unsigned char hmacs[10][32]; //one per cipher - 10 ciphers

    for (int i = 0;i < 10; i++) {
        unsigned char *sigma = HMAC_SHA256(initialKey, 32, cipherTexts[i], 1024);
        memcpy(hmacs[i], sigma, 32);
        free(sigma);

        //derive next hmac sigma_i+1
        unsigned char *nextKey = Hash_SHA256(initialKey, 32);
        free(initialKey);
        initialKey = nextKey;
    }

    //build aggregate hmac chain
    unsigned char *aggregateHash_s1 = Hash_SHA256(hmacs[0], 32);
    memcpy(aggregateHMAC, aggregateHash_s1, 32);
    free(aggregateHash_s1);

    for (int i = 1; i < 10; i++) { //loop needs to start at i = 1 since sigma1 is the basecase hash(sigma1) 
        unsigned char concat[64]; //concat = sigma_prev + sigma_current
        memcpy(concat, aggregateHMAC, 32);
        memcpy(concat + 32, hmacs[i], 32); 
        unsigned char *confirmationHash = Hash_SHA256(concat, 64);
        memcpy(aggregateHMAC, confirmationHash, 32);
        free(confirmationHash);
    }

    if (memcmp(aggregateHMAC, aggregateHMAC_byte_received, 32) != 0) {
        printf("HMACs do not match - data has been tampered");
        exit(1);
    }
    printf("HMACs confirmed. Decrypting now");

    initialKey = PRNG(sharedSeed, seedLength, 32);

    unsigned char plaintexts[10][1025];
    for (int i=0; i<10; i++) {
        unsigned char *plaintext = AES_CTR_Decrypt(initialKey, cipherTexts[i]);
        memcpy(plaintexts[i], plaintext, 1024);
        plaintexts[i][1024] = '\0';
        free(plaintext);

        unsigned char *nextKey = Hash_SHA256(initialKey, 32);
        free(initialKey);
        initialKey = nextKey;
    }

    unsigned char decrypted_buf[1025 * 10];
    for (int i=0; i<10; i++) {
        memcpy(decrypted_buf + i * 1025, plaintexts[i], 1024); //excludes /n***
        if (i != 9)
            decrypted_buf[i * 1025 + 1024] = '\n';
    }

    Write_File("Plaintexts.txt", decrypted_buf, 1025 * 10 - 1);
    
    return 0;

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
        hex to bytes 
==============================*/
void hex2Byte(unsigned char output[], char input[], int outputlength) {
    for (int i = 0; i < outputlength; i++) {
        //%02hhx - read 2 hex characters and store as hh (char sized), x=hex
        sscanf(&input[2*i], "%02hhx", &output[i]); //2*i since each byte is represented as 2 hex characters
    }
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
