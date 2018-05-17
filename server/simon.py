import binascii

class SimonCipher(object):
    # Z's contant arrays
    z0 = [1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 1, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0]
    z1 = [1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 1, 0, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0]
    z2 = [1, 0, 1, 0, 1, 1, 1, 1, 0, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 1, 1]
    z3 = [1, 1, 0, 1, 1, 0, 1, 1, 1, 0, 1, 0, 1, 1, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 0, 0, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1, 1, 1, 1]
    z4 = [1, 1, 0, 1, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 0, 1, 1, 0, 1, 1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 1, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 1, 1, 0, 1, 1, 1, 1]

    # valid cipher configurations
    # block_size: {key_size: (number_rounds, z sequence)}
    valid_setups = {32: {64: (32, z0)},
                    48: {72: (36, z0), 96: (36, z1)},
                    64: {96: (42, z2), 128: (44, z3)},
                    96: {96: (52, z2), 144: (54, z3)},
                    128: {128: (68, z2), 192: (69, z3), 256: (72, z4)}}

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
            self.rounds, self.zseq = self.block_validation[key_size]
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

        # key scheduling
        self.key_schedule = []
        
        for i in range(self.key_words):
            counter = self.word_size * (self.key_words-i-1)
            self.key_schedule.append((self.key >> counter) & self.mod_mask)

        for i in range(self.key_words, self.rounds):
            rotr_3 = ((self.key_schedule[i-1] << (self.word_size-3)) + (self.key_schedule[i-1] >> 3)) & self.mod_mask
            if self.key_words == 4:
                rotr_3 = rotr_3 ^ self.key_schedule[i-3]
            rotr_1 = (((rotr_3 << (self.word_size-1)) + (rotr_3 >> 1)) & self.mod_mask)
            c_z = (self.zseq[(i-self.key_words) % 62]) ^ 3
            new_k = (~(self.key_schedule[i-self.key_words])) ^ rotr_1 ^ rotr_3 ^ c_z
            self.key_schedule.append(new_k & self.mod_mask)

        # print test vector 
        # print()
        # print("  Test Vector")
        # print("  -----------")
        # print("  key         :", hex(self.key))
        # print("  key_size    :", self.key_size)
        # print("  block_size  :", self.block_size)
        # print("  word_size   :", self.word_size)
        # print("  key_words   :", self.key_words)
        # print("  mask        :", hex(self.mod_mask))

    # simon encrypt function
    def encrypt_function(self, upper_word, lower_word):
        x = upper_word
        y = lower_word 

        # round function
        for k in self.key_schedule:
            rotl_1 = ((x >> (self.word_size-1)) + (x << 1)) & self.mod_mask
            rotl_8 = ((x >> (self.word_size-8)) + (x << 8)) & self.mod_mask
            rotl_2 = ((x >> (self.word_size-2)) + (x << 2)) & self.mod_mask

            tmp = x
            x = y ^ (rotl_1 & rotl_8) ^ rotl_2 ^ k
            y = tmp
        
        return x, y

    # simon decrypt function
    def decrypt_function(self, upper_word, lower_word):
        x = upper_word
        y = lower_word 

        # round function
        for k in reversed(self.key_schedule):
            rotl_1 = ((y >> (self.word_size-1)) + (y << 1)) & self.mod_mask
            rotl_8 = ((y >> (self.word_size-8)) + (y << 8)) & self.mod_mask
            rotl_2 = ((y >> (self.word_size-2)) + (y << 2)) & self.mod_mask

            tmp = y
            y = x ^ (rotl_1 & rotl_8) ^ rotl_2 ^ k
            x = tmp
        
        return x, y

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
    ciphertext = 0x8CC2BDE43BB868D3DB954A9AF161316A3C0037022D2E139B474B544BC1A42B4F

    # run simon
    cipher = SimonCipher(block_size, key_size, key)

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