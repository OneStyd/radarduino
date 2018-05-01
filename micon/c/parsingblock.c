#include <stdio.h>

int main() {
    // Deklarasi Variabel
    char plaintext[] = "test aja dulu", value[1024] = {0};
    unsigned int arrayHex[256] = {0}, temp=0;
    int i=0, j=0, k=0;
    char a, b, c, d;

    // Parsing Data Ke Blok Padding ANSIX923
    while (plaintext[i] != '\0') {
        temp = (temp<<8) + plaintext[i];
        if (j==3) {
            arrayHex[k] = temp;
            k++; j=0;
            temp=0;
        } else {
            j++;
        }
        i++;
    }
    if (j==1) temp = (temp<<24) + 3;
    if (j==2) temp = (temp<<16) + 2;
    if (j==3) temp = (temp<<8) + 1;
    arrayHex[k] = temp;

    // Percetakan
    printf("\n  Plaintext Awal :\n  ");
    for (i=0; i<sizeof(plaintext)-1; i++) {
        printf("%c", plaintext[i]);
    }
    printf("\n\n  Hasil Parsing :\n");
    i=0;
    while (arrayHex[i] != 0) {
        printf("  Blok ke-%d = %08X\n", i+1, arrayHex[i]);
        i++;
    }
    printf("\n");

    // Parsing Blok ke Data
    i=0; j=0;
    while (arrayHex[i] != 0) {
        a = (arrayHex[i] >> 24) & 0xFF;
        b = (arrayHex[i] >> 16) & 0xFF;
        c = (arrayHex[i] >> 8) & 0xFF;
        d = arrayHex[i] & 0xFF;
        if (d==1) {
            d = 0;
        }
        if (d==2 && c==0) {
            c = 0; d = 0;
        }
        if (d==3 && c==0 && b==0) {
            b = 0; c = 0; d = 0;
        }
        value[j] = a;
        value[j+1] = b;
        value[j+2] = c;
        value[j+3] = d;
        j += 4;
        i++;
    }

    // Percetakan
    printf("  Plaintext Kembali :\n  ");
    for (i=0; i<j; i++) {
        printf("%c", value[i]);
    }
    printf("\n\n");

    return 0;
}
