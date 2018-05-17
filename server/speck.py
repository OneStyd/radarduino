import binascii

class SpeckCipher(object):
    # valid cipher configurations
    # block_size: {key_size: number_rounds}
    valid_setups = {32: {64: 22},
                    48: {72: 22, 96: 23},
                    64: {96: 26, 128: 27},
                    96: {96: 28, 144: 29},
                    128: {128: 32, 192: 33, 256: 34}}

    # class constructor
    def __init__(self, block_size, key_size, key):
        # variable initiation and validation
        try:
            self.block_validation = self.valid_setups[block_size]
            self.block_size = block_size
            self.word_size = self.block_size >> 1
        except KeyError:
            print()
            print("  Ukuran blok tidak tersedia, pilih salah satu ukuran blok berikut:")
            print(" ", [x for x in self.valid_setups.keys()])
            return

        try:
            self.rounds = self.block_validation[key_size]
            self.key_size = key_size
            self.key_words = self.key_size // self.word_size
        except KeyError:
            print()
            print("  Ukuran key tidak tersedia, pilih salah satu ukuran key berikut:")
            print(" ", [x for x in self.block_validation.keys()])
            return

        try:
            self.key = key & ((2 ** self.key_size) - 1)
        except (ValueError, TypeError):
            print()
            print("  Key bermasalah, pastikan key berupa integer")
            return

        # create properly sized bit mask
        self.mod_mask = (2 ** self.word_size) - 1
        self.mod_mask_sub = (2 ** self.word_size)

        # setup circular shift parameters
        if self.block_size == 32:
            self.alpha_shift = 7
            self.beta_shift = 2
        else:
            self.alpha_shift = 8
            self.beta_shift = 3

        # key scheduling
        self.key_schedule = [(self.key >> (self.word_size * (self.key_words-1))) & self.mod_mask]
        l_schedule = []

        for i in range(self.key_words-1):
            counter = self.word_size * (self.key_words-i-2)
            l_schedule.append((self.key >> counter) & self.mod_mask)

        for i in range(self.rounds-1):
            rotr_a = ((l_schedule[i] << (self.word_size-self.alpha_shift)) + (l_schedule[i] >> self.alpha_shift)) & self.mod_mask
            new_l = ((self.key_schedule[i] + rotr_a) & self.mod_mask) ^ i
            rotl_b = ((self.key_schedule[i] >> (self.word_size-self.beta_shift)) + (self.key_schedule[i] << self.beta_shift)) & self.mod_mask
            l_schedule.append(new_l)
            self.key_schedule.append(rotl_b ^ new_l)

        # print test vector 
        # print()
        # print("  Test Vector")
        # print("  -----------")
        # print("  key         :", hex(self.key))
        # print("  key_size    :", self.key_size)
        # print("  block_size  :", self.block_size)
        # print("  word_size   :", self.word_size)
        # print("  key_words   :", self.key_words)
        # print("  alpha_shift :", self.alpha_shift)
        # print("  beta_shift  :", self.beta_shift)
        # print("  mask        :", hex(self.mod_mask))

    # speck encrypt function
    def encrypt_function(self, upper_word, lower_word):    
        x = upper_word
        y = lower_word 

        # round function
        for k in self.key_schedule:
            rotr_a = ((x << (self.word_size-self.alpha_shift)) + (x >> self.alpha_shift)) & self.mod_mask
            x = ((rotr_a + y) & self.mod_mask) ^ k
            rotl_b = ((y >> (self.word_size-self.beta_shift)) + (y << self.beta_shift)) & self.mod_mask
            y = rotl_b ^ x
            
        return x, y    

    # speck decrypt function
    def decrypt_function(self, upper_word, lower_word):    
        x = upper_word
        y = lower_word

        # round function
        for k in reversed(self.key_schedule): 
            rotr_b = (((x^y) << (self.word_size-self.beta_shift)) + ((x^y) >> self.beta_shift)) & self.mod_mask
            y = rotr_b
            xsub = (((x ^ k) - y) + self.mod_mask_sub) % self.mod_mask_sub
            rotl_a = ((xsub >> (self.word_size-self.alpha_shift)) + (xsub << self.alpha_shift)) & self.mod_mask
            x = rotl_a

        return x,y

    # parsing block function for encrypt
    def encrypt(self, plaintext):
        # variable initiation and validation
        if isinstance(plaintext, int):
            plaintext_length = (len(hex(plaintext)) - 2) // 2
            hex_block_size = self.block_size // 8
            padding_size = hex_block_size - (plaintext_length % hex_block_size)
        else:
            return

        # add padding
        plaintext = int(hex(plaintext) + ('00' * (padding_size-1) + '0' + str(padding_size)), 0)
        number_blocks = round((len(hex(plaintext)) - 2) / hex_block_size / 2)

        # encrypt text per block
        ciphertext = 0
        for i in range(number_blocks):
            counter = self.block_size * (number_blocks-i-1)
            text_block = (plaintext >> counter) & ((2 ** self.block_size) - 1)
            b = (text_block >> self.word_size) & self.mod_mask
            a = text_block & self.mod_mask
            b, a = self.encrypt_function(b, a)
            ciphertext = (ciphertext << self.block_size) + ((b << self.word_size) + a)

        return ciphertext

    # parsing block function for decrypt
    def decrypt(self, ciphertext):
        # variable initiation and validation
        if isinstance(ciphertext, int):
            hex_block_size = self.block_size // 8
            number_blocks = -(-(len(hex(ciphertext)) - 2) // hex_block_size) // 2
        else:
            return
        
        # decrypt text per block
        plaintext = 0
        for i in range(number_blocks):
            counter = self.block_size * (number_blocks-i-1)
            text_block = (ciphertext >> counter) & ((2 ** self.block_size) - 1)
            b = (text_block >> self.word_size) & self.mod_mask
            a = text_block & self.mod_mask
            b, a = self.decrypt_function(b, a)
            plaintext = (plaintext << self.block_size) + ((b << self.word_size) + a)

        # remove padding
        plaintext_length = len(hex(plaintext))
        padding_size = int(hex(plaintext)[-1:])
        isPadding = 1
        for i in range(plaintext_length-padding_size*2, plaintext_length-2):
            if hex(plaintext)[i] != "0":
                isPadding = 0
        if isPadding == 1:
            plaintext = plaintext >> (int(hex(plaintext)[-1:]) * 8)

        return plaintext

if __name__ == "__main__":
    # parameter declaration
    block_size = 64
    key_size = 128
    key = 0x030201000b0a0908131211101b1a1918
    data =  "128.0.0.1/-6.63255/106.76495".encode()
    plaintext = int("0x" + binascii.hexlify(data).decode("utf-8"), 0)
    ciphertext = 0xcaea5158349ab4548657d5fd295100d972a1e3a2885ae518eaf2e20ee80b5f6

    # run speck
    cipher = SpeckCipher(block_size, key_size, key)

    # print result encryption
    try:
        result = cipher.encrypt(plaintext)
        if isinstance(result, int):
            print()
            print("  Result :")
            print("  --------")
            print(" ", hex(result))
            print()
        else:
            print()
            print("  Result :")
            print("  --------")
            print("  Plaintext bermasalah, pastikan plaintext berupa integer")
            print()
    except (TypeError, AttributeError):
        print()

    # print result decryption
    # try:
    #     result = cipher.decrypt(ciphertext)
    #     if isinstance(result, int):
    #         print()
    #         print("  Result :")
    #         print("  --------")
    #         print(" ", binascii.unhexlify(hex(result)[2:]).decode("utf-8"))
    #         print()
    #     else:
    #         print()
    #         print("  Result :")
    #         print("  --------")
    #         print("  Ciphertext bermasalah, pastikan ciphertext berupa integer")
    #         print()
    # except (TypeError, AttributeError):
    #     print()