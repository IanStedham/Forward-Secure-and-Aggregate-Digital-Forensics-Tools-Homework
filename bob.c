#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>

#include "utils.c" // Utility functions: Read_File, Write_File, Convert_to_Hex, SHA256, PRNG, AES-ENCrypt/decrypt, HMAC

int main(int argc, char *argv[]) {
    // Bob reads the shared seed from a file named ”SharedSeed.txt”
    int seedLength;
    unsigned char* sharedSeed = Read_File(argv[1], &seedLength);

    //Bobreadstheciphertexts from ”Ciphertexts.txt”
    int cipherLength;
    unsigned char* cipher = Read_File(argv[2], &cipherLength);

    //Bobreadsthe the aggregated HMAC from ”AggregatedHMAC.txt”
    int hmacLength;
    unsigned char* aggregateHMAC_hex = Read_File(argv[3], &hmacLength);

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
    hex2Byte(aggregateHMAC_byte_received, aggregateHMAC_hex, 32);

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
