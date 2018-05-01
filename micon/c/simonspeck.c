#include <stdio.h>

// Untuk mempersingkat kodingan
typedef unsigned __int64 u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

// Fungsi Left Circular Shift
#define ROTL( n, X ) ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )

// Konstanta Simon untuk Key Scheduling
char Simonz[5][65] = {"11111010001001010110000111001101111101000100101011000011100110",
					  "10001110111110010011000010110101000111011111001001100001011010",
					  "10101111011100000011010010011000101000010001111110010110110011",
					  "11011011101011000110010111100000010010001010011100110100001111",
					  "11010001111001101011011000100000010111000011001010010011101111"};

/*  -------------------------- Definisi Variabel Simon --------------------------
	nn = word size (ukuran blok / 2)
	mm = jumlah key words 	( 	4 			if n = 16,
								3 or 4 		if nn = 24 or 32,
								2 or 3 		if nn = 48,
								2, 3, or 4 	if nn = 64			)
	T = jumlah ronde
	Cj = urutan Konstanta Simon yang digunakan
	(T, Cj) = (32,0) 						if nn = 16
			= (36,0) or (36,1) 				if nn = 24, mm = 3 or 4
			= (42,2) or (44,3) 				if nn = 32, mm = 3 or 4
			= (52,2) or (54,3) 				if nn = 48, mm = 2 or 3
			= (68,2), (69,3), or (72,4) 	if nn = 64, mm = 2, 3, or 4
	x,y = plaintext words dalam nn bits
	k[mm-1]..k[0] = key words dalam nn bits
    -----------------------------------------------------------------------------  */

// Fungsi Enkripsi Simon
void SimonEncrypt(u32 PL, u32 PR, u32* key, int blocksize, int keysize)
{
	u32 k[72] = { 0 };
	int nn = blocksize / 2;
	int mm = keysize / nn;
	int T=0, Cj=0;

	if (nn == 16) { T=32; Cj=0; };
	if (nn == 24 && mm == 3) { T=36; Cj=0; };
	if (nn == 24 && mm == 4) { T=36; Cj=1; };
	if (nn == 32 && mm == 3) { T=42; Cj=2; };
	if (nn == 32 && mm == 4) { T=44; Cj=3; };
	if (nn == 48 && mm == 2) { T=52; Cj=2; };
	if (nn == 48 && mm == 3) { T=54; Cj=3; };
	if (nn == 64 && mm == 2) { T=68; Cj=2; };
	if (nn == 64 && mm == 3) { T=69; Cj=3; };
	if (nn == 64 && mm == 4) { T=72; Cj=4; };

	int i, j=0;
	for (i=0; i<mm; i++)
	{
		k[i] = key[i];
	};

	// ------------------------- key expansion -------------------------
	for (i=mm; i<T; i++)
	{
		u32 tmp = ROTL(-3, k[i-1]);
		if (mm == 4) tmp ^= k[i-3];
		tmp = tmp ^ ROTL(-1, tmp);
		k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
	};

	// -------------------------- encryption ---------------------------
	u32 x=PL, y=PR;
	for (i=0; i<T; i++)
	{
		u32 tmp = x;
		x = y ^ ROTL(1, x) & ROTL(8, x) ^ ROTL(2, x) ^ k[i];
		y = tmp;
	};

	// printf("  Simon Encryption Result\n");
	printf("  Plaintext  : %08X %08X\n  Ciphertext : %08X %08X\n\n", PL, PR, x, y);
}

// Fungsi Dekripsi Simon
void SimonDecrypt(u32 CL, u32 CR, u32* key, int blocksize, int keysize)
{
	u32 k[72] = { 0 };
	int nn = blocksize / 2;
	int mm = keysize / nn;
	int T=0, Cj=0;

	if (nn == 16) { T=32; Cj=0; };
	if (nn == 24 && mm == 3) { T=36; Cj=0; };
	if (nn == 24 && mm == 4) { T=36; Cj=1; };
	if (nn == 32 && mm == 3) { T=42; Cj=2; };
	if (nn == 32 && mm == 4) { T=44; Cj=3; };
	if (nn == 48 && mm == 2) { T=52; Cj=2; };
	if (nn == 48 && mm == 3) { T=54; Cj=3; };
	if (nn == 64 && mm == 2) { T=68; Cj=2; };
	if (nn == 64 && mm == 3) { T=69; Cj=3; };
	if (nn == 64 && mm == 4) { T=72; Cj=4; };

	int i, j=0;
	for (i=0; i<mm; i++)
	{
		k[i] = key[i];
	};

	// ------------------------- key expansion -------------------------
	for (i=mm; i<T; i++)
	{
		u32 tmp = ROTL(-3, k[i-1]);
		if (mm == 4) tmp ^= k[i-3];
		tmp = tmp ^ ROTL(-1, tmp);
		k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
	};

	// -------------------------- decryption ---------------------------
	u32 x=CL, y=CR;
	for (i=0; i<T; ++i)
	{
		u32 tmp = y;
		y = ROTL(1, y) & ROTL(8, y) ^ ROTL(2, y) ^ x ^ k[T-i-1];
		x = tmp;
	};

	// printf("  Simon Decryption Result\n");
	printf("  Ciphertext : %08X %08X\n  Plaintext  : %08X %08X\n\n", CL, CR, x, y);
}


/*  -------------------------- Definisi Variabel Speck --------------------------
	nn = word size (ukuran blok / 2)
	mm = jumlah key words 	( 	4 			if n = 16,
								3 or 4 		if nn = 24 or 32,
								2 or 3 		if nn = 48,
								2, 3, or 4 	if nn = 64			)
	T = jumlah ronde = 	22 				if n = 16
						22 or 23 		if n = 24, m = 3 or 4
						26 or 27 		if n = 32, m = 3 or 4
						28 or 29 		if n = 48, m = 2 or 3
						32, 33, or 34 	if n = 64, m = 2, 3, or 4
	(a,b) =	(7,2)	if n = 16
			(8,3) 	selainnya
	x,y = plaintext words dalam nn bits
	l[m-2]..l[0],k[0] = key words dalam nn bits
    -----------------------------------------------------------------------------  */

// Fungsi Enkripsi Speck
void SpeckEncrypt(u32 PL, u32 PR, u32* key, int blocksize, int keysize)
{
	u32 k[34] = { 0 };
	u32 l[34] = { 0 };
	int nn = blocksize / 2;
	int mm = keysize / nn;
	int T=0, a=0, b=0;

	if (nn == 16) { T=22; };
	if (nn == 24 && mm == 3) { T=22; };
	if (nn == 24 && mm == 4) { T=23; };
	if (nn == 32 && mm == 3) { T=26; };
	if (nn == 32 && mm == 4) { T=27; };
	if (nn == 48 && mm == 2) { T=28; };
	if (nn == 48 && mm == 3) { T=29; };
	if (nn == 64 && mm == 2) { T=32; };
	if (nn == 64 && mm == 3) { T=33; };
	if (nn == 64 && mm == 4) { T=34; };

	if (nn == 16) { a=7; b=2; }
	else { a=8; b=3; }

	int i;
	k[0] = key[0];
	for (i=0; i<mm-1; i++)
	{
		l[i] = key[i+1];
	}

	// ------------------------- key expansion -------------------------
	for (i=0; i<=T-2; i++)
	{
		l[i+mm-1] = (k[i] + ROTL(-a, l[i])) ^ i;
		k[i+1] = ROTL(b, k[i]) ^ l[i+mm-1];
	}

	// ------------------------- encryption ----------------------------
	u32 x=PL, y=PR;
	for (i=0; i<=T-1; i++)
	{
		x = (ROTL(-a, x) + y) ^ k[i];
		y = ROTL(b, y) ^ x;
	}

	// printf("  Speck Encryption Result\n");
	printf("  Plaintext  : %08X %08X\n  Ciphertext : %08X %08X\n\n", PL, PR, x, y);
}

// Fungsi Dekripsi Speck
void SpeckDecrypt(u32 CL, u32 CR, u32* key, int blocksize, int keysize)
{
	u32 k[34] = { 0 };
	u32 l[34] = { 0 };
	int nn = blocksize / 2;
	int mm = keysize / nn;
	int T=0, a=0, b=0;

	if (nn == 16) { T=22; };
	if (nn == 24 && mm == 3) { T=22; };
	if (nn == 24 && mm == 4) { T=23; };
	if (nn == 32 && mm == 3) { T=26; };
	if (nn == 32 && mm == 4) { T=27; };
	if (nn == 48 && mm == 2) { T=28; };
	if (nn == 48 && mm == 3) { T=29; };
	if (nn == 64 && mm == 2) { T=32; };
	if (nn == 64 && mm == 3) { T=33; };
	if (nn == 64 && mm == 4) { T=34; };

	if (nn == 16) { a=7; b=2; }
	else { a=8; b=3; }

	int i;
	k[0] = key[0];
	for (i=0; i<mm-1; i++)
	{
		l[i] = key[i+1];
	}

	// ------------------------- key expansion -------------------------
	for (i=0; i<=T-2; i++)
	{
		l[i+mm-1] = (k[i] + ROTL(-a, l[i])) ^ i;
		k[i+1] = ROTL(b, k[i]) ^ l[i+mm-1];
	}

	// ------------------------- decryption ----------------------------
	u32 x=CL, y=CR;
	for (i=T-1; i>=0; --i)
	{
		y = ROTL(-b, (x ^ y));
		x = ROTL(a, ((x ^ k[i]) - y));
	}

	// printf("  Speck Decryption Result\n");
	printf("  Ciphertext : %08X %08X\n  Plaintext  : %08X %08X\n\n", CL, CR, x, y);
}

// Fungsi Utama
int main()
{
    u32 PL, PR, CL, CR;
    u32 key[4] = { 0 };
    char plaintext[] = "test aja dulu, hasilnya belakangan", value[1024] = {0};
    unsigned int arrayHex[256] = {0}, temp=0;
    int i=0, j=0, k=0;
    char a, b, c, d;

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

    key[3]=0x1b1a1918; key[2]=0x13121110; key[1]=0x0b0a0908; key[0]=0x03020100;

		printf("  Simon Encryption Result\n");
    i=0;
    while (arrayHex[i]!=0) {
        SimonEncrypt(arrayHex[i], arrayHex[i+1], key, 64, 128);
        // printf("  Blok ke-%d = %08X\n", i+1, arrayHex[i]);
        i+=2;
    }

    /* 	------------------------- Simon Test Vector -------------------------
		Ukuran Blok: 64
		Ukuran Kunci: 128
		Key: 1b1a1918 13121110 0b0a0908 03020100
		Plaintext: 656b696c 20646e75
		Ciphertext: 44c8fc20 b9dfa07a
	   	---------------------------------------------------------------------  */

    // key[3]=0x1b1a1918; key[2]=0x13121110; key[1]=0x0b0a0908; key[0]=0x03020100;

		// // Enkripsi
		// PL=0x656b696c; PR=0x20646e75;
	  // SimonEncrypt(PL, PR, key, 64, 128);

		// // Dekripsi
		// CL=0x44c8fc20; CR=0xb9dfa07a;
	  // SimonDecrypt(CL, CR, key, 64, 128);

		/* 	------------------------- Speck Test Vector -------------------------
			Ukuran Blok: 64
			Ukuran Kunci: 128
			Key: 1b1a1918 13121110 0b0a0908 03020100
			Plaintext: 3b726574 7475432d
			Ciphertext: 8c6fa548 454e028b
		  ---------------------------------------------------------------------  */

		// key[3]=0x1b1a1918; key[2]=0x13121110; key[1]=0x0b0a0908; key[0]=0x03020100;

		// // Enkripsi
		// PL=0x3b726574; PR=0x7475432d;
		// SpeckEncrypt(PL, PR, key, 64, 128);

		// // Dekripsi
		// CL=0x8c6fa548; CR=0x454e028b;
		// SpeckDecrypt(CL, CR, key, 64, 128);
}

