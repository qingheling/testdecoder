#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_PASSWORD_LENGTH 20
#define key_decrypt_author "LingMj"

char* xor_decrypt(char* encrypted, char key) {
    int length = strlen((char*)encrypted);
    char* decrypted = malloc(length + 1);
    for (int i = 0; i < length; i++) {
        decrypted[i] = encrypted[i] ^ key;
    }
    decrypted[length] = '\0';
    return decrypted;
}

char* caesar_decrypt(char* encrypted, int shift) {
    int length = strlen(encrypted);
    char* decrypted = malloc(length + 1);
    for (int i = 0; i < length; i++) {
        if (encrypted[i] >= 'a' && encrypted[i] <= 'z') {
            decrypted[i] = 'a' + (encrypted[i] - 'a' - shift + 26) % 26;
        } else {
            decrypted[i] = encrypted[i];
        }
    }
    decrypted[length] = '\0';
    return decrypted;
}

int check_passwords(char* input1, char* input2, char* input3, char* input4, 
                    char* decrypted1, char* decrypted2, char* decrypted3, char* decrypted4) {
    return strcmp(input1, decrypted1) == 0 && strcmp(input2, decrypted2) == 0 &&
           strcmp(input3, decrypted3) == 0 && strcmp(input4, decrypted4) == 0;
}

int main() {
    char input1[MAX_PASSWORD_LENGTH];
    char input2[MAX_PASSWORD_LENGTH];
    char input3[MAX_PASSWORD_LENGTH];
    char input4[MAX_PASSWORD_LENGTH];

    printf("Enter passwords or Enter H coward mode:\n");
    int h_count = 0;
    while (1) {
        char input[20];
        scanf("%s", input);

        if (strcmp(input, "H") == 0) {
            h_count++;
            if (h_count == 100) {
                printf("Hint: Invert XOR Replace! \n");
                break;
            }
        } else {
            strcpy(input1, input);
            scanf("%s %s %s", input2, input3, input4);
            break;
        }
    }
	
	char encrypted3[] = "\x39\x2c\x7d";
	char encrypted2[] = "\x2f\x2c\x20\x38\x3a\x28";
    char encrypted1[] = "\x21\x21\x7c\x7d\x79\x78\x7b\x7a";             
    char encrypted4[] = "\x28\x3b\x24\x29\x28\x23"; 

    char key = 'M';
    char* decrypted1 = xor_decrypt(encrypted1, key);
    char* decrypted2 = xor_decrypt(encrypted2, key);
    char* decrypted3 = xor_decrypt(encrypted3, key);
    char* decrypted4 = xor_decrypt(encrypted4, key);

    if (check_passwords(input1, input2, input3, input4, decrypted1, decrypted2, decrypted3, decrypted4)) {
        char encrypted_caesar[] = "pvygob"; 
        
        char shift_char = 'j';
        int shift = shift_char - 'a' + 1;

        char* decrypted_caesar = caesar_decrypt(encrypted_caesar, shift);

        printf("[+] Enter the password successfully! you know: %s\n", decrypted_caesar);

        free(decrypted_caesar);
    } else {
        printf("[-] Incorrect password!\n");
    }

    free(decrypted1);
    free(decrypted2);
    free(decrypted3);
    free(decrypted4);

    return 0;
}
