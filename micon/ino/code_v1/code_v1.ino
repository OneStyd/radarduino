extern int __bss_end;
extern int *__brkval;

// Left circular shift
#define ROTL( n, X ) ( ( ( X ) << n ) | ( ( X ) >> ( 32 - n ) ) )
#define ROTR( n, X ) ( ( ( X ) >> n ) | ( ( X ) << ( 32 - n ) ) )

// Simon constant
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

int get_free_memory() 
{
  int free_memory;

  if((int)__brkval == 0)
    free_memory = ((int)&free_memory) - ((int)&__bss_end);
  else
    free_memory = ((int)&free_memory) - ((int)__brkval);

  return free_memory;
}

// Simon encryption function for 64bit block and 128 bit key
Text SimonEncrypt64_128(uint32_t PL, uint32_t PR, uint32_t* key)
{
  uint32_t k[44] = { 0 };
  int nn = 32, mm = 4, T=44, Cj=3;
  Text ciphertext;
  int i, j;

  // ------------------------- key expansion -------------------------  
  for (i=0; i<mm; i++)
  {
    k[i] = key[i];
  };
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

// Speck encryption function for 64bit block and 128 bit key
Text SpeckEncrypt64_128(uint32_t PL, uint32_t PR, uint32_t* key)
{
  uint32_t k[29] = { 0 };
  uint32_t l[29] = { 0 };
  int nn = 32, mm = 4, T=27, alpha=8, beta=3;
  Text ciphertext;
  int i, j;

  // ------------------------- key expansion -------------------------
  k[0] = key[0];
  for (i=0; i<mm-1; i++)
  {
    l[i] = key[i+1];
  };
  for (i=0; i<T-1; i++)
  {
    l[i+mm-1] = (k[i] + ROTR(alpha, l[i])) ^ i;
    k[i+1] = ROTL(beta, k[i]) ^ l[i+mm-1];
  };

  // -------------------------- encryption ---------------------------
  for (i=0; i<T; i++)
  {
    PL = (ROTR(alpha, PL) + PR) ^ k[i];
    PR = ROTL(beta, PR) ^ PL;
  };
  ciphertext.left = PL;
  ciphertext.right = PR;

  return ciphertext;
}

// Simon decryption function for 64bit block and 128 bit key
Text SimonDecrypt64_128(uint32_t CL, uint32_t CR, uint32_t* key)
{
  uint32_t k[44] = { 0 };
  int nn = 32, mm = 4, T=44, Cj=3;
  Text plaintext;
  int i, j;

  // ------------------------- key expansion -------------------------
  for (i=0; i<mm; i++)
  {
    k[i] = key[i];
  };
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

// Speck decryption function for 64bit block and 128 bit key
Text SpeckDecrypt64_128(uint32_t CL, uint32_t CR, uint32_t* key)
{
  uint32_t k[29] = { 0 };
  uint32_t l[29] = { 0 };
  int nn = 32, mm = 4, T=27, alpha=8, beta=3;
  Text plaintext;
  int i, j;

  // ------------------------- key expansion -------------------------
  k[0] = key[0];
  for (i=0; i<mm-1; i++)
  {
    l[i] = key[i+1];
  };
  for (i=0; i<T-1; i++)
  {
    l[i+mm-1] = (k[i] + ROTR(alpha, l[i])) ^ i;
    k[i+1] = ROTL(beta, k[i]) ^ l[i+mm-1];
  };

  // -------------------------- decryption ---------------------------
  for (i=T-1; i>=0; --i)
  {
    CR = ROTR(beta, (CL ^ CR));
    CL = ROTL(alpha, ((CL ^ k[i]) - CR));
  };
  plaintext.left = CL;
  plaintext.right = CR;

  return plaintext;
}

// Main code to run once
void setup() {
  Serial.begin(115200);
  // Declare key
  uint32_t key[4] = {0x03020100, 0x0b0a0908, 0x13121110, 0x1b1a1918};
  uint32_t plaintext_hex[100] = {0}, ciphertext_hex[100] = {0}, tmp = 0;
  int i, j=0, k=0;

  // Declare data
//  String ipaddress = "128.0.0.1";
//  float latitude = -6.6325536;
//  float longitude = 106.7649527;
//  String plaintext;
//  plaintext += ipaddress + "/";
//  plaintext += String(latitude, 7) + "/";
//  plaintext += String(longitude, 7);

  // Test size
  String trainblock = "abcdefgh";
  String plaintext;
  unsigned long dataSize = 6400;
  unsigned long counter = dataSize/64; 
  for (i=0; i<counter; i++) {
    plaintext += trainblock;
  }

  // Print plaintext
  Serial.println(F("Plaintext:"));
  Serial.print(F("\""));
  Serial.print(plaintext);
  Serial.println(F("\""));
  Serial.println();
  Serial.println(F("Plaintext Size:"));
  Serial.print(plaintext.length()*8);
  Serial.println(F(" bit"));
  Serial.println();

  unsigned long startTime = micros();

  // Parsing data to blocks
  for (i=0; i<plaintext.length(); i++) {
    tmp = (tmp<<8) + plaintext[i];
    if (j==3) {
      plaintext_hex[k] = tmp;
      k++; j=0; tmp=0;
    } 
    else {
      j++;
    }
  }
  if (j==0 && k%2==0) {
    plaintext_hex[k] = 0;
    plaintext_hex[k+1] = 8;
    k++;
  } 
  else if (j==0 && k%2!=0) {
    plaintext_hex[k] = 4;
  } 
  else if (j!=0 && k%2==0) {
    plaintext_hex[k] = tmp<<(8*j);
    plaintext_hex[k+1] = j + 4;
    k++;
  } 
  else {
    plaintext_hex[k] = (tmp<<(8*j)) + j;
  }
  
  // Encrypt data
  for (i=0; i<k; i+=2) {
    Text cipher = SimonEncrypt64_128(plaintext_hex[i], plaintext_hex[i+1], key);
    ciphertext_hex[i] = cipher.left;
    ciphertext_hex[i+1] = cipher.right;
  }

  // Print encryption result
  Serial.println(F("Hasil Enkripsi:"));
  Serial.print(F("\"0x"));
  for (i=0; i<=k; i++) {
    Serial.print(ciphertext_hex[i], HEX);
  }
  Serial.println(F("\""));

  // Measure execution time
  unsigned long endTime = micros();
  unsigned long duration = endTime - startTime;
  Serial.println();
  Serial.print(F("Execution time: "));
  Serial.print(duration);
  Serial.println(F(" microseconds"));
  Serial.print(F("Free memory: "));
  Serial.println(get_free_memory());
}

// Main code to run repeatedly:
void loop() {

}
