#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include "utils.c" // Utility functions: Read_File, Write_File, Convert_to_Hex, SHA256, PRNG, AES-ENCrypt/decrypt, HMAC

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

    mempcpy(keys[0], initialKey, 1024);
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
            mempcpy(keys[messageCount], initialKey, 1024);
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
