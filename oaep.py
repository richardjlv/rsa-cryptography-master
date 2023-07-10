import string
import math
import hashlib
import random

class OAEP:
    "Implementação baseada no código disponível em https://gist.github.com/ppoffice/e10e0a418d5dafdd5efe9495e962d3d2"

    def __xor__(self, data, mask):
        masked = b''
        l_data = len(data)
        l_mask = len(mask)
        for i in range(max(l_data, l_mask)):
            if i < l_data and i < l_mask:
                masked += (data[i] ^ mask[i]).to_bytes(1, byteorder='big')
            elif i < l_data:
                masked += data[i].to_bytes(1, byteorder='big')
            else:
                break
        return masked

    def __sha256__(self, message):
        return hashlib.sha3_256(message).digest()

    def __mgf1__(self, seed, length):
        mask = b""
        h_len = hashlib.sha3_256().digest_size

        if(length > pow(2, h_len)):
            print("Ocorreu um erro. Mascara muito grande")
            exit()       

        for counter in range(0, math.ceil(length / h_len)):
            byteCounter = counter.to_bytes(4, byteorder='big')
            mask += hashlib.sha3_256(seed + byteCounter).digest()
        return mask[:length]

    def encode(self, message, modulus):
        label = ""
        m_len = len(message)
        h_label = self.__sha256__(bytes(label, "UTF-8"))
        h_len = len(h_label)
        mod_size = modulus.bit_length() // 8

        if(m_len > mod_size - 2*h_len -2):
            print("Ocorreu um erro. A mensagem é muito grande.")
            exit()

        padding_string = b"\x00" * (mod_size - m_len - 2*h_len - 2)
        data_block = h_label + padding_string + b"\x01" + message
        seed = "".join(random.choices(string.ascii_letters, k=h_len)).encode("UTF-8")
        mask = self.__mgf1__(seed, mod_size -h_len -1)
        masked_db = self.__xor__(data_block, mask)
        seed_mask = self.__mgf1__(masked_db, h_len)
        masked_seed = self.__xor__(seed, seed_mask)
        encripted_message = b"\x00" + masked_seed + masked_db

        return encripted_message

    def decode(self, message, modulus):
        label = ""
        h_label = self.__sha256__(bytes(label, "UTF-8"))
        hLen = len(h_label)
        mod_size = modulus.bit_length() // 8

        if(mod_size < 2*hLen + 2):
            print("Ocorreu um erro.")
            exit()

        if(len(message) != mod_size):
            print("Ocorreu um erro.")
            exit()

        buff = bytearray()
        buff.append(message[0])
        if(buff != b"\x00"):
            print("Ocorreu um erro.")
            exit()

        masked_seed = message[1:hLen+1]
        masked_db = message[hLen+1:]
        seed_mask = self.__mgf1__(masked_db, hLen)
        seed = self.__xor__(masked_seed, seed_mask)
        mask = self.__mgf1__(seed, mod_size - hLen -1)
        data_block = self.__xor__(masked_db, mask)
        h_label_new = data_block[:hLen]

        if(h_label != h_label_new):
            print("Ocorreu um erro.")
            exit()

        newBlock = data_block[hLen:]
        count = 0

        for i in newBlock:
            buff = bytearray()
            buff.append(i)
            if buff == b"\x00":
                count = count + 1
            else:
                if buff == b"\x01":
                    break
                else:
                    print("Ocorreu um erro.")
                    exit()

        return newBlock[count+1:]