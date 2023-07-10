import math
import random
import numpy as np

class AES:

    def __init__(self):
        self.sbox = self.__initialize_aes_sbox__()
        self.key = self.__generate_random_key__()
        self.rcon = self.__initialize_aes_rcon__()

    # From the wikipedia definition
    # See (https://en.wikipedia.org/wiki/Rijndael_S-box) for more details
    def __initialize_aes_sbox__(self):
        ROTL8 = lambda x, shift: (x << shift) | (x >> (8 - shift))
        sbox = [0] * 256
        p = q = 1
        while True:
            # multiply p by 3 
            p = p ^ (p << 1) ^ (0x1B if p & 0x80 else 0)
            p = p & 255
            # divide q by 3 (equals multiplication by 0xf6)
            q ^= q << 1
            q ^= q << 2
            q ^= q << 4
            q ^= (0x09 if q & 0x80 else 0)
            q = q & 255
            # compute the affine transformation
            xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4)
            sbox[p] = (xformed ^ 0x63) & 255
            if p == 1:
                break
        sbox[0] = 0x63
        sbox = [hex(x) for x in sbox]
        sbox = np.array(sbox).reshape(16, 16)
        return sbox

    def __generate_random_key__(self):
        key_block = []
        key = bytearray(random.SystemRandom().randint(0, 255) for _ in range(16))
        key = [hex(x) for x in key]
        key = np.array(key).reshape(4, 4)
        return key
    def __set_key__(self, key):
        self.key = key

    def __generate_key_from_password__(self, password):
        pass_size = len(password)
        padding_size = 16 - pass_size

        if pass_size > 16:
            password = password[:16]
        
        if padding_size > 0:
            padding  = ' ' * padding_size
            password += padding

        key_block = []
        key = bytearray((ord(c) for c in password))
        key = [hex(x) for x in key]
        key = np.array(key).reshape(4, 4)
        return key

    # AES Round Constants
    def __initialize_aes_rcon__(self):
        rcon = []
        row = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]
        rcon.append(row)
        row = [0] * 10
        for i in range(3):
            rcon.append(row)

        return np.array(rcon)

    def __get_matrix_colum__(self, matrix, col):
        return [row[col] for row in matrix]

    # AES Key Expansion
    def __key_schedule__(self):

        keys = np.array([self.key] * 11)

        for i in range(1,11):
            # Build RotWord
            last_key = keys[i-1]
            rot_word = [last_key[3][1], last_key[3][2], last_key[3][3], last_key[3][0],]
            sub_word = [0] * 4

            # SubBytes in RotWord (Build SubWord)
            for j in range(4):
                tmp = int(rot_word[j], 16)
                row = tmp // 0x10
                col = tmp % 0x10
                sub_word[j] = self.sbox[row][col]

            rcon = [hex(x) for x in self.__get_matrix_colum__(self.rcon, i-1)]

            previous_word = self.__arr_xor__(sub_word, rcon)


            curr_word = self.__arr_xor__(last_key[0], previous_word)

            round_key = np.array([curr_word])
            previous_word = curr_word

            for l in range(1, 4):
                curr_word = self.__arr_xor__(last_key[l], previous_word)
                round_key = np.append(round_key, [curr_word], axis=0)
                previous_word = curr_word

            round_key = np.array(round_key.reshape(4, 4))
            keys[i] = round_key

        keys = np.concatenate([[self.key], keys[:-1]])
        return keys

    # Matrix XOR bitwise operation
    def __matrix_column_xor__(self, m1, m2):
        rows_len = len(m1)
        cols_len = len(m1[0])
        
        for i in range(rows_len):
            for j in range(cols_len):
                a = int(m1[i][j], 16)
                b = int(m2[i][j], 16)
                m1[i][j] = hex(a ^ b)
        return np.array(m1).transpose(1, 0)

    def __arr_xor__(self, arr1, arr2):
        for i in range(len(arr1)):
            a = int(arr1[i], 16)
            b = int(arr2[i], 16)
            arr1[i] = hex(a ^ b)
        return arr1

    # AES AddRoundKey transformation
    def __add_round_key__(self, state, round_key):
        state = self.__matrix_column_xor__(state, round_key)
        return state

    def __self_idx_to_hex__(self, idx):
        if idx < 10:
            return str(idx)
        idx = str(idx)

        idx = 'a' if idx == "10" else idx
        idx = 'b' if idx == "11" else idx
        idx = 'c' if idx == "12" else idx
        idx = 'd' if idx == "13" else idx
        idx = 'e' if idx == "14" else idx
        idx = 'f' if idx == "15" else idx

        return idx
   
    def __inv_sbox__(self, element):
        row = ""
        col = ""
        for i in range(16):
            for j in range(16):
                if self.sbox[i][j] == element:
                    row = self.__self_idx_to_hex__(i)
                    col = self.__self_idx_to_hex__(j)
        return row + col


    # AES SubBytes transformation
    def __sub_bytes__(self, state, inv = False):

        if not inv:
            for i in range(4):
                for j in range(4):
                    tmp = int(state[i][j], 16)
                    row = tmp // 0x10
                    col = tmp % 0x10
                    state[i][j] = self.sbox[row][col]
        else:
            inv_state = state.flatten()
            for i in range(16):
                inv_state[i] = "0x" + self.__inv_sbox__(inv_state[i])
            state = inv_state.reshape(4, 4)

        return state

    # AES ShiftRows transformation
    def __shift_rows__(self, state, inv = False):
        
        if not inv:
            for i in range(1, 4):
                state[i] = np.concatenate((state[i][i:], state[i][:i]))
        else:
            for i in range(1, 4):
                state[i] = np.concatenate((state[i][4-i:4], state[i][0:4-i]))

        return state

    
    def __galois_multiplication__(self, a, b):
        # Multiplication in the AES field GF(2^8)
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi_bit_set = a & 0x80
            a <<= 1
            if hi_bit_set:
                a ^= 0x1B  # XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1
            b >>= 1
        p = p if p <= 256 else p - 256
        return p

    # AES MixColumns transformation
    def __mix_columns__(self, state, inv = False):
        # The AES mix_columns matrix
        mix_matrix = [
            [0x02, 0x03, 0x01, 0x01],
            [0x01, 0x02, 0x03, 0x01],
            [0x01, 0x01, 0x02, 0x03],
            [0x03, 0x01, 0x01, 0x02]
        ]

        inv_mix_matrix = [
            [0xe, 0xb, 0xd, 0x9],
            [0x9, 0xe, 0xb, 0xd],
            [0xd, 0x9, 0xe, 0xb],
            [0xb, 0xd, 0x9, 0xe]
        ]

        # Perform the matrix multiplication
        result_state = np.array([[0] * 4 for _ in range(4)])
        for i in range(4):
            for j in range(4):
                for k in range(4):

                    if not inv:
                        a = mix_matrix[i][k]
                    else:
                        a = inv_mix_matrix[i][k]
                    b = int(state[k][j], 16)

                    result_state[i][j] = result_state[i][j] ^ self.__galois_multiplication__(a, b)

                    if inv:
                        value = str(hex(result_state[i][j])).split("0x")[1]
                        if len(value) > 2:
                            value = "0x" + value[1:3]
                            result_state[i][j] = int(value, 16)
                        
        result_state = [hex(x) for x in result_state.flatten()]
        result_state = np.array(result_state).reshape(4, 4)
        
        return result_state

    def __plaintext_to_blocks__(self, plaintext, nb_of_blocks):
        blocks = []
        text_len = len(plaintext)
        start = end = 0

        for i in range(0, nb_of_blocks):
            start = end
            end = start + 16 if start + 16 <= text_len else text_len
            block_text = plaintext[start:end]
            block = []
            for j in range(4):
                k = j * 4
                chars_list = list((block_text[k:k + 4]))
                hex_bytes = [hex(ord(x)) for x in chars_list]
                block.append(hex_bytes)

            blocks.append(block)
        return np.array(blocks)

    def __print_blocks_as_hex__(self, block):
        text = ""

        for i in range(len(block)):
            for j in range(len(block[i])):
                for k in range(len(block[i][j])):
                    text += block[i][j][k].split("0x")[1] + " "

    def __print_key_as_hex__(self, key):
        text = ""

        for i in range(len(key)):
            for j in range(len(key[i])):
                    text += key[i][j].split("0x")[1] + " "

    def hex_to_text(self, plaintext):
        str_bytes = [x for x in plaintext.split(" ") if x]
        text = "".join([chr(int(x, 16)) for x in str_bytes])
        return text

    # AES encryption
    def encrypt(self, plaintext, key = None):
        if key is not None:
            key = self.__generate_key_from_password__(key)
            self.__set_key__(key)

        plaintext_size = len(plaintext)
        nb_of_blocks = math.ceil(plaintext_size / 16)
        
        padding_size = (nb_of_blocks * 16) - plaintext_size
        padding  = ' ' * padding_size

        plaintext += padding
        blocks = self.__plaintext_to_blocks__(plaintext, nb_of_blocks)

        self.__print_blocks_as_hex__(blocks)
        self.__print_key_as_hex__(self.key)

        round_keys = self.__key_schedule__()

        ciphertext = ""
        
        for i in range(0, nb_of_blocks):
            state = blocks[i]
            round_key = round_keys[0]
            
            # Initial round
            state = self.__add_round_key__(state, round_key)

            # Main rounds
            for j in range(1, 10):
                state = self.__sub_bytes__(state)
                state = self.__shift_rows__(state)
                state = self.__mix_columns__(state)
                state = self.__add_round_key__(state, round_keys[j].transpose(1,0))
                state = state.transpose(1, 0)
            
            # Final round
            state = self.__sub_bytes__(state)
            state = self.__shift_rows__(state)
            state = self.__add_round_key__(state, round_keys[-1].transpose(1,0))

            ciphertext += ' '.join(str(x) for x in state.flatten()) + " "
            
        return ciphertext.encode()

    # AES decryption
    def decrypt(self, ciphertext, key):
        ciphertext = [x for x in ciphertext.decode().split(" ") if x]
        nb_of_blocks = math.ceil(len(ciphertext) / 16)
        
        blocks = []

        for i in range(nb_of_blocks):
            start = i * 16
            end = start + 16 if start + 16 <= len(ciphertext) else len(ciphertext)
            blocks.append(np.array(ciphertext[start:end]).reshape(4, 4))
        
        decrypted = ""

        round_keys = self.__key_schedule__()

        for j in range(nb_of_blocks):

            state = blocks[j]

            # Initial round
            state = self.__add_round_key__(state, round_keys[-1])
            state = self.__shift_rows__(state, inv= True)
            state = self.__sub_bytes__(state, inv= True)


            # Main rounds
            for i in range(9, 1, -1):
                state = state.transpose(1, 0)
                state = self.__add_round_key__(state, round_keys[i])
                state = self.__mix_columns__(state, inv = True)
                state = self.__shift_rows__(state, inv = True)
                state = self.__sub_bytes__(state, inv = True)

            # Final round
            state = self.__add_round_key__(state, round_keys[1].transpose(1,0)).transpose(1, 0)
            state = self.__mix_columns__(state, inv = True)
            state = self.__shift_rows__(state, inv = True)
            state = self.__sub_bytes__(state, inv= True)
            state = self.__add_round_key__(state, round_keys[0].transpose(1,0))

            decrypted += ' '.join(str(x) for x in state.flatten()) + " "

        message = "".join([chr(int(c, 16)) for c in decrypted.split(" ") if c])
        return message
