import math
import random
import base64
from oaep import OAEP
from file import FileHandler

class RSA:

    def __init__(self, path):
        self.file_path = path
        self.filehandler = FileHandler(path)
        self.message = self.filehandler.read()

    def __generate_prime_numbers__(self):
        p = random.getrandbits(1024)
        q = random.getrandbits(1024)
        
        while not self.__is_prime__(p):
            p = random.getrandbits(1024)

        while not self.__is_prime__(q):
            q = random.getrandbits(1024)

        return p, q

    # Implementation credit: https://gist.github.com/Ayrx/5884790
    def  __miller_rabin__(self, n, k):
        if n == 2:
            return True
        
        if n % 2 == 0:
            return False

        r, s = 0, n - 1
        while s % 2 == 0:
            r += 1
            s //= 2
        for _ in range(k):
            a = random.randrange(2, n - 1)
            x = pow(a, s, n)
            if x == 1 or x == n - 1:
                continue
            for _ in range(r - 1):
                x = pow(x, 2, n)
                if x == n - 1:
                    break
            else:
                return False
        return True

    def __is_prime__(self, n):
        return self.__miller_rabin__(n, 64)

    def __egcd__(self, a, b):
        if a == 0:
            return (b, 0, 1)
        else:
            g, y, x = self.__egcd__(b % a, a)
            return (g, x - (b // a) * y, y)

    def __mod_inv__(self, e, phi):
        g, x, y = self.__egcd__(e, phi)
        if g != 1:
            raise Exception('Modular inverse not found.')
        else:
            return x % phi
 
    
    def __totient_function__(self, p, q):
        return (p-1) * (q-1)

    def generate_key_pair(self):
        # Prime numbers
        p, q = self.__generate_prime_numbers__()

        n = p * q

        # Numbers of coprimes of n
        phi = self.__totient_function__(p, q)

        # Forcing e (Public key) to be 65537
        e = 65537

        # Private key
        d = self.__mod_inv__(e, phi)

        self.filehandler.pub_key(e, n)
        self.filehandler.priv_key(d, n)

        return e, n, d

    def __break_string_into_lines__(self, text, n = 64):
        nb_of_lines = math.ceil(len(text) / n)
        text_size = len(text)
        lines = []
        for i in range(0, nb_of_lines):
            start = i * n
            end = start + n if start + n < text_size else text_size
            lines.append(text[start:end])
        
        return "\n".join(lines)

    def __bytes_to_int__(self, b):
        return int.from_bytes(b, byteorder='little')

    def __int_to_bytes__(self, i):
        return i.to_bytes(math.ceil(i.bit_length() / 8), byteorder='little')

    def encrypt(self, m, e, n):
        oaep = OAEP()
        encoded_message = oaep.encode(m, n)
        m = self.__bytes_to_int__(encoded_message)
        cipher = pow(m, e, n)
        b64_cipher = base64.b64encode(self.__int_to_bytes__(cipher)).decode()
        self.filehandler.write(b64_cipher)
        return b64_cipher
       
    def decrypt(self, c,  d, n):
        c = self.__bytes_to_int__(base64.b64decode(c))
        oaep = OAEP()
        m = pow(c, d, n)
        encoded_message = self.__int_to_bytes__(m)
        m = oaep.decode(encoded_message, n)
        message = m.decode()
        self.filehandler.write(message, False)
        return message

    def sign_message(self, m, d, n):
        hash_message = OAEP().__sha256__(m)
        h = self.__bytes_to_int__(hash_message)
        s = pow(h, d, n)
        signature = base64.b64encode(self.__int_to_bytes__(s)).decode()
        self.filehandler.signature(signature)
        return signature

    def check_signature(self, m, s, e, n):
        s = self.__bytes_to_int__(base64.b64decode(s))
        hash_message = OAEP().__sha256__(m)

        h = pow(s, e, n)

        return False if h != self.__bytes_to_int__(hash_message) else True