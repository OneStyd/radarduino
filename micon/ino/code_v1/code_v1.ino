// Left circular shift
#define ROTL( n, X ) ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )
#define ROTR( n, X ) ( ( ( X ) >> n ) | ( ( X ) << ( 32 - n ) ) )

// Simon Constant
char Simonz[5][65] = {"11111010001001010110000111001101111101000100101011000011100110",
                      "10001110111110010011000010110101000111011111001001100001011010",
                      "10101111011100000011010010011000101000010001111110010110110011",
                      "11011011101011000110010111100000010010001010011100110100001111",
                      "11010001111001101011011000100000010111000011001010010011101111"};

// Just a struct to save variable
struct Text {
   uint32_t left;
   uint32_t right;
};

Text SimonEncrypt64_128(uint32_t PL, uint32_t PR, uint32_t* key)
{
  uint32_t k[44] = { 0 };
  int nn = 32, mm = 4, T=44, Cj=3;
  Text ciphertext;
  int i, j;
  
  for (i=0; i<mm; i++)
  {
    k[i] = key[i];
  };

  // ------------------------- key expansion -------------------------
  for (i=mm; i<T; i++)
  {
    uint32_t tmp = ROTR(3, k[i-1]);
    if (mm == 4) tmp ^= k[i-3];
    tmp = tmp ^ ROTR(1, tmp);
    k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
  };

  // -------------------------- encryption ---------------------------
  for (i=0; i<T; i++)
  {
    uint32_t tmp = PL;
    PL = PR ^ ROTL(1, PL) & ROTL(8, PL) ^ ROTL(2, PL) ^ k[i];
    PR = tmp;
  };
  ciphertext.left = PL;
  ciphertext.right = PR;

  return ciphertext;
}

Text SimonDecrypt64_128(uint32_t CL, uint32_t CR, uint32_t* key)
{
  uint32_t k[44] = { 0 };
  int nn = 32, mm = 4, T=44, Cj=3;
  Text plaintext;
  int i, j;
  
  for (i=0; i<mm; i++)
  {
    k[i] = key[i];
  };

  // ------------------------- key expansion -------------------------
  for (i=mm; i<T; i++)
  {
    uint32_t tmp = ROTR(3, k[i-1]);
    if (mm == 4) tmp ^= k[i-3];
    tmp = tmp ^ ROTR(1, tmp);
    k[i] = (~(k[i-mm])) ^ tmp ^ (Simonz[Cj][(i-mm) % 62]-'0') ^ 3;
  };

  // -------------------------- decryption ---------------------------
  for (i=0; i<T; ++i)
  {
    uint32_t tmp = CR;
    CR = ROTL(1, CR) & ROTL(8, CR) ^ ROTL(2, CR) ^ CL ^ k[T-i-1];
    CL = tmp;
  };
  plaintext.left = CL;
  plaintext.right = CR;

  return plaintext;
}

void setup() {
  // put your setup code here, to run once:
  Serial.begin(115200);
  Serial.println();
  uint32_t PL, PR, CL, CR;
  uint32_t key[4] = { 0 };
  key[3]=0x1b1a1918; key[2]=0x13121110; key[1]=0x0b0a0908; key[0]=0x03020100;

  // Start Encryption
  PL=0x656b696c; PR=0x20646e75;
  Text cipher = SimonEncrypt64_128(PL, PR, key);

  Serial.print("Plaintext = ");
  Serial.print(PL, HEX);
  Serial.print(" ");
  Serial.println(PR, HEX);
  Serial.print("Ciphertext = ");
  Serial.print(cipher.left, HEX);
  Serial.print(" ");
  Serial.println(cipher.right, HEX);

  Serial.println();
  
  // Start Decryption
  CL=0x44c8fc20; CR=0xb9dfa07a;
  Text plain = SimonDecrypt64_128(CL, CR, key);

  Serial.print("Ciphertext = ");
  Serial.print(CL, HEX);
  Serial.print(" ");
  Serial.println(CR, HEX);
  Serial.print("Plaintext = ");
  Serial.print(plain.left, HEX);
  Serial.print(" ");
  Serial.println(plain.right, HEX);
}

void loop() {
  // put your main code here, to run repeatedly:

}
