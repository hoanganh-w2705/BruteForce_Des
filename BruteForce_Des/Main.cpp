#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "des.h"

#define DES_KEY_LENGTH 8
#define KEY_LENGTH_CONTROL 4
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define ALPHABET_LENGTH 26
#define FOUR_BYTE_OF_KEY_KNOWN "MONI"  //only 8 byte

char key_filename[] = "keyfile.key";
char input_file[256];
char ciphertext_filename[256];
char known_plaintext[256];   
size_t known_plaintext_len = 0;

void load_known_plaintext(const char* filename);
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
            load_known_plaintext(input_file);
            break;
        case 2:
			generate_des_key_file();
            break;
        case 3: 
            encrypt_file();
		    break;
        case 4: {
            FILE* cipher_fp = fopen(ciphertext_filename, "rb");
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

            char key[KEY_LENGTH_CONTROL + 1];
            key[KEY_LENGTH_CONTROL] = '\0';

            printf("Starting Brute-force...\n");
            generate_keys_recursive(key, 0, cipher_fp, cipher_block);

            printf("Brute-force completed. No key found.\n");
            fclose(cipher_fp);
            break;
        }
        default:
            printf("Invalid choice. Try again.\n");
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

void load_known_plaintext(const char* filename) {
    FILE* fp = fopen(filename, "rb");
    if (!fp) {
        printf("Could not open known plaintext file: %s\n", filename);
        exit(1);
    }

    known_plaintext_len = fread(known_plaintext, 1, sizeof(known_plaintext) - 1, fp);
    fclose(fp);

    known_plaintext[known_plaintext_len] = '\0'; 
    printf("Loaded known plaintext: %s (length=%zu)\n", known_plaintext, known_plaintext_len);
}

void generate_des_key_file() {
    FILE* key_file = fopen(key_filename, "wb");
    if (!key_file) {
        printf("Could not create key file.\n");
        return;
    }

    unsigned char des_key[DES_KEY_LENGTH] = { 0 };

    // 4 byte đầu fix cứng "AAAA"
    memcpy(des_key, FOUR_BYTE_OF_KEY_KNOWN, KEY_LENGTH_CONTROL);

    // 4 byte sau random
// 4 byte sau random nhưng giới hạn A–Z để brute-force tìm được
    srand((unsigned)time(NULL));
    for (int i = KEY_LENGTH_CONTROL; i < DES_KEY_LENGTH; i++) {
        des_key[i] = (unsigned char)('A' + (rand() % 26));
    }

    // Ghi ra file
    fwrite(des_key, 1, DES_KEY_LENGTH, key_file);
    fclose(key_file);

    // In ra hex để kiểm tra
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
        unsigned char padding = 8 - bytes_read;
        memset(data_block + bytes_read, padding, padding);
    }

    process_message(data_block, processed_block, key_sets, ENCRYPTION_MODE);
    fwrite(processed_block, 1, 8, output_fp);

    printf("File %s encrypted to %s\n", input_file, ciphertext_filename);

    fclose(input_fp);
    fclose(output_fp);
}

// Brute-force 4 byte CUỐI (đuôi) của khoá, 4 byte ĐẦU cố định = FOUR_BYTE_OF_KEY_KNOWN ("AAAA")

void generate_keys_recursive(char* tail, int index, FILE* /*cipher_fp*/, unsigned char* cipher_block) {
    // tail có độ dài KEY_LENGTH_CONTROL, chứa 4 ký tự đuôi cần brute-force
    if (index == KEY_LENGTH_CONTROL) {
        // Khi đã sinh đủ 4 ký tự cho đuôi → thử khoá
        test_key(tail, NULL, cipher_block);
        return;
    }

    for (int i = 0; i < ALPHABET_LENGTH; i++) {
        tail[index] = ALPHABET[i];
        generate_keys_recursive(tail, index + 1, NULL, cipher_block);
    }
}

void test_key(char* tail, FILE* /*cipher_fp*/, unsigned char* cipher_block) {
    // Lắp khoá DES: 4 byte đầu cố định "AAAA", 4 byte cuối = tail đang brute-force
    unsigned char des_key[8] = { 0 };
    memcpy(des_key, FOUR_BYTE_OF_KEY_KNOWN, KEY_LENGTH_CONTROL);   // "AAAA"
    memcpy(des_key + 4, tail, KEY_LENGTH_CONTROL);   // đuôi brute-force

    // Sinh subkeys và giải mã 1 block
    key_set key_sets[17];
    generate_sub_keys(des_key, key_sets);

    unsigned char decrypted_block[8] = { 0 };
    process_message(cipher_block, decrypted_block, key_sets, DECRYPTION_MODE);

    // (Tuỳ chọn) Ghi log mỗi lần thử — cảnh báo: rất chậm nếu log mọi khoá
    FILE* log_fp = fopen("bruteforce_log.txt", "a");
    if (log_fp) {
        fprintf(log_fp, "Testing Key: HEAD=\"%.*s\" TAIL=\"%.*s\" --> Decrypted: ",
            (int)KEY_LENGTH_CONTROL, FOUR_BYTE_OF_KEY_KNOWN,
            (int)KEY_LENGTH_CONTROL, tail);
        for (int i = 0; i < 8; i++) fputc((unsigned char)decrypted_block[i], log_fp);

        if (memcmp(decrypted_block, known_plaintext, known_plaintext_len) == 0) {
            fprintf(log_fp, " --> MATCH FOUND!\n");
            fprintf(log_fp, "Full Key (ASCII): \"%.*s%.*s\"\n",
                (int)KEY_LENGTH_CONTROL, FOUR_BYTE_OF_KEY_KNOWN,
                (int)KEY_LENGTH_CONTROL, tail);

            // In thêm dạng hex cho chắc chắn
            fprintf(log_fp, "Full Key (Hex): ");
            for (int i = 0; i < 8; i++) fprintf(log_fp, "%02X", des_key[i]);
            fprintf(log_fp, "\n");
            fclose(log_fp);

            printf("MATCH FOUND! Key: \"%.*s%.*s\"\n",
                (int)KEY_LENGTH_CONTROL, FOUR_BYTE_OF_KEY_KNOWN,
                (int)KEY_LENGTH_CONTROL, tail);
            exit(0);
        }
        else {
            fprintf(log_fp, " --> No Match\n");
            fclose(log_fp);
        }
    }
    else {
        // Không mở được log: vẫn xử lý match
        if (memcmp(decrypted_block, known_plaintext, known_plaintext_len) == 0) {
            printf("MATCH FOUND! Key: \"%.*s%.*s\"\n",
                (int)KEY_LENGTH_CONTROL, FOUR_BYTE_OF_KEY_KNOWN,
                (int)KEY_LENGTH_CONTROL, tail);
            exit(0);
        }
    }
}
