#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "des.h"

#define DES_KEY_LENGTH 8
#define KEY_LENGTH 4
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHABET_LENGTH 26
#define KNOWN_PLAINTEXT "MONI"  //only 8 byte

char key_filename[] = "keyfile.key";
char input_file[256];
char ciphertext_filename[256];

void generate_keys_recursive(char* key, int index, FILE* cipher_fp, unsigned char* cipher_block);
void test_key(char* key, FILE* cipher_fp, unsigned char* cipher_block);
void generate_des_key_file();
void encrypt_file();

int main() {
	int choice;
	while (true) {
        printf("\nMENU:\n");
        printf("1. Enter Input File Name\n");
        printf("2. Generate DES Key\n");
        printf("3. Encrypt File using DES\n");
        printf("4. Brute-force Decrypt DES File\n");
        printf("0. Exit\n");
        printf("Choose an option: ");
        scanf_s("%d", &choice);

        if (choice == 0) break;
        switch (choice) {
        case 1:
            printf("Enter file name: ");
            scanf("%s", input_file);
            break;
        case 2:
			generate_des_key_file();
            break;
        case 3: 
            encrypt_file();
		    break;
        case 4: 
            FILE * cipher_fp = fopen(ciphertext_filename, "rb");
            if (!cipher_fp) {
                printf("Could not open ciphertext file.\n");
                break;
            }

            unsigned char cipher_block[8];
            size_t bytes_read = fread(cipher_block, 1, 8, cipher_fp);
            if (bytes_read != 8) {
                printf("Could not read 8 bytes from ciphertext file.\n");
                fclose(cipher_fp);
                break;
            }

            char key[KEY_LENGTH + 1];
            key[KEY_LENGTH] = '\0';

            printf("Starting Brute-force...\n");
            generate_keys_recursive(key, 0, cipher_fp, cipher_block);

            printf("Brute-force completed. No key found.\n");
            fclose(cipher_fp);
            break;

        //default:
        //    printf("Invalid choice. Try again.\n");
        }
	}
}

//void generate_des_key_file() {
//    FILE* key_file = fopen(key_filename, "wb"); //Open file in mode write binary 
//    if (!key_file) {
//        printf("Could not create key file.\n");
//        return;
//    }
//
//    unsigned char des_key[DES_KEY_LENGTH];
//    generate_key(des_key); //easy sample 
//    fwrite(des_key, 1, DES_KEY_LENGTH, key_file);
//    fclose(key_file);
//
//    printf("Key generated and saved to %s\n", key_filename);
//    printf("Key (Hex): ");
//    for (int i = 0; i < DES_KEY_LENGTH; i++) {
//        printf("%02X", des_key[i]);
//    }
//    printf("\n");
//}

void generate_des_key_file() {
    FILE* key_file = fopen(key_filename, "wb"); //Open file in mode write binary 
    if (!key_file) {
        printf("Could not create key file.\n");
        return;
    }

    unsigned char des_key[DES_KEY_LENGTH] = { 0 };
    memcpy(des_key, KNOWN_PLAINTEXT, KEY_LENGTH);

    fwrite(des_key, 1, DES_KEY_LENGTH, key_file);
    fclose(key_file);

    printf("Key generated and saved to %s\n", key_filename);
    printf("Key (Hex): ");
    for (int i = 0; i < DES_KEY_LENGTH; i++) {
        printf("%02X", des_key[i]);
    }
    printf("\n");
}

void encrypt_file() {
    FILE* key_file = fopen(key_filename, "rb");
    if (!key_file) {
        printf("Key file not found. Please generate key first.\n");
        return;
    }

    unsigned char des_key[DES_KEY_LENGTH];
    fread(des_key, 1, DES_KEY_LENGTH, key_file);
    fclose(key_file);

    FILE* input_fp = fopen(input_file, "rb");
    if (!input_fp) {
        printf("Could not open input file.\n");
        return;
    }

    printf("Enter ciphertext_filename file name: ");
    scanf("%s", ciphertext_filename);

    FILE* output_fp = fopen(ciphertext_filename, "wb");
    if (!output_fp) {
        printf("Could not create ciphertext file.\n");
        fclose(input_fp);
        return;
    }

    key_set key_sets[17];
    generate_sub_keys(des_key, key_sets);

    unsigned char data_block[8] = { 0 };
    unsigned char processed_block[8] = { 0 };
    size_t bytes_read = fread(data_block, 1, 8, input_fp);

    if (bytes_read < 8) {
        // Padding
        unsigned char padding = 8 - bytes_read;
        memset(data_block + bytes_read, padding, padding);
    }

    process_message(data_block, processed_block, key_sets, ENCRYPTION_MODE);
    fwrite(processed_block, 1, 8, output_fp);

    printf("File %s encrypted to %s\n", input_file, ciphertext_filename);

    fclose(input_fp);
    fclose(output_fp);
}

void generate_keys_recursive(char* key, int index, FILE* cipher_fp, unsigned char* cipher_block) {
    if (index == KEY_LENGTH) {
        test_key(key, cipher_fp, cipher_block);
        return;
    }

    for (int i = 0; i < ALPHABET_LENGTH; i++) {
        key[index] = ALPHABET[i];
        generate_keys_recursive(key, index + 1, cipher_fp, cipher_block);
    }
}

void test_key(char* key, FILE* cipher_fp, unsigned char* cipher_block) {
    unsigned char des_key[8] = { 0 };
    memcpy(des_key, key, KEY_LENGTH);

    key_set key_sets[17];
    generate_sub_keys(des_key, key_sets);

    unsigned char decrypted_block[8];
    process_message(cipher_block, decrypted_block, key_sets, DECRYPTION_MODE);

    // Mở file log để ghi kết quả
    FILE* log_fp = fopen("bruteforce_log.txt", "a");
    if (log_fp) {
        fprintf(log_fp, "Testing Key: %s --> Decrypted Block: ", key);
        for (int i = 0; i < 8; i++) {
            fprintf(log_fp, "%c", decrypted_block[i]);
        }
        if (memcmp(decrypted_block, KNOWN_PLAINTEXT, strlen(KNOWN_PLAINTEXT)) == 0) {
            fprintf(log_fp, " --> MATCH FOUND!\n");
            fprintf(log_fp, "Key FOUND: %s\n", key);
            fprintf(log_fp, "Decrypted Block: ");
            for (int i = 0; i < 8; i++) {
                fprintf(log_fp, "%c", decrypted_block[i]);
            }
            fprintf(log_fp, "\n");
            fclose(log_fp);
            exit(0);
        }
        else {
            fprintf(log_fp, " --> No Match\n");
        }
        fclose(log_fp);
    }
}