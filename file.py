class FileHandler:

    def __init__(self, path):
        self.path = path
        self.filename = path.split(".")[0]
    
    def read(self):
        with open(self.path, "rb") as file:
                return file.read()
            
    def read_cipher(self):
        with open(f"./out/{self.filename}.encrypted", "rb") as file:
                return file.read()

    def read_signature(self):
        with open(f"./out/{self.filename}.signature", "rb") as file:
                return file.read()

    def write(self, data, encrypted=True):
        if encrypted:
            with open(f"./out/{self.filename}.encrypted", "w") as file:
                return file.write(str(data))
        else:
            with open(f"./out/{self.filename}.decrypted", "w") as file:
                return file.write(str(data))
    def signature(self, data):
        with open(f"./out/{self.filename}.signature", "w") as file:
                return file.write(str(data))

    def pub_key(self, e, n):
        data  = f"-----BEGIN PUBLIC KEY-----\n"
        data += f"Public exponent (e): {e}\n"
        data += f"Public modulus (n): {n}\n"
        data += f"-----END PUBLIC KEY-----"
        with open(f"./out/{self.filename}.public_key", "w") as file:
                return file.write(str(data))
                
    def priv_key(self, d, n):
        data  = f"-----BEGIN PRIVATE KEY-----\n"
        data += f"Private exponent (d): {d}\n"
        data += f"Public modulus (n): {n}\n"
        data += f"-----END PRIVATE KEY-----"
        with open(f"./out/{self.filename}.private_key", "w") as file:
                return file.write(str(data))