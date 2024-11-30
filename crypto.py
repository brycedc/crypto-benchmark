from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto import Random
import time
import argparse


class AESCipher:
    def __init__(self):
        # Creates a random key and iv
        rndFile = Random.new()
        self.key = rndFile.read(16)

    def encrypt(self, plaintext):
        try:
            return AES.new(self.key, AES.MODE_ECB).encrypt(plaintext)
        except Exception as e:
            print(f"Error AES encryption: {e}")
            exit(1)

    def decrypt(self, cipher_text):
        try:
            return AES.new(self.key, AES.MODE_ECB).decrypt(cipher_text)
        except Exception as e:
            print(f"Error AES decryption: {e}")
            exit(1)


class DESCipher:
    def __init__(self):
        # Creates a random key and iv
        rndFile = Random.new()
        self.key = rndFile.read(8)

    def encrypt(self, plaintext):
        try:
            return DES.new(self.key, DES.MODE_ECB).encrypt(plaintext)
        except Exception as e:
            print(f"Error DES encryption: {e}")
            exit(1)

    def decrypt(self, cipher_text):
        try:
            return DES.new(self.key, DES.MODE_ECB).decrypt(cipher_text)
        except Exception as e:
            print(f"Error DES decryption: {e}")
            exit(1)


class RSACipher:
    def __init__(self):
        private_key = RSA.generate(2048)
        public_key = private_key.public_key()
        self.rsa_public = PKCS1_OAEP.new(public_key)
        self.rsa_private = PKCS1_OAEP.new(private_key)

    def encrypt(self, plaintext):
        try:
            chunk_size = 214 # Key size minus 42 bytes (when using PKCS1_OAEP)
            encrypted_data = b""
            for i in range(0, len(plaintext), chunk_size):
                decrypted_chunk = plaintext[i : i + chunk_size]
                encrypted_chunk = self.rsa_public.encrypt(decrypted_chunk)
                encrypted_data += encrypted_chunk
            return encrypted_data
        except Exception as e:
            print(f"Error RSA encryption: {e}")
            exit(1)

    def decrypt(self, cipher_text):
        try:
            chunk_size = 256 # RSA key size
            decrypted_data = b""
            for i in range(0, len(cipher_text), chunk_size):
                encrypted_chunk = cipher_text[i : i + chunk_size]
                decrypted_chunk = self.rsa_private.decrypt(encrypted_chunk)
                decrypted_data += decrypted_chunk
            return decrypted_data
        except Exception as e:
            print(f"Error RSA decryption: {e}")
            exit(1)


def main():
    # Sets up an argument parser
    parser = argparse.ArgumentParser(
        prog="crypto", description="a simple file encrypt/decrypt program"
    )
    # Adds arguments to the parser
    parser.add_argument("--file", help="file to be encrypted/decrypted", required=True)
    parser.add_argument(
        "--output", help="outputs the decrypted cipher text, should match input file"
    )
    parser.add_argument(
        "cipher", help="the cipher to be used", choices=["DES", "AES", "RSA"]
    )
    # Parses Arguments
    args = parser.parse_args()

    # Reads file to plaintext
    try:
        with open(args.file, "rb") as file:
            plaintext = file.read()
    except Exception as e:
        print(f"An error while reading the input file: {e}")
        exit(1)

    if args.cipher == "DES":
        ###############################
        des_cipher = DESCipher()
        start_time = time.perf_counter()
        encrypted_file = des_cipher.encrypt(plaintext)
        decrypted_file = des_cipher.decrypt(encrypted_file)
        end_time = time.perf_counter()
        print(f"DES Cipher: {(end_time - start_time)*1000} ms")
        ###############################
    elif args.cipher == "AES":
        ###############################
        aes_cipher = AESCipher()
        start_time = time.perf_counter()
        encrypted_file = aes_cipher.encrypt(plaintext)
        decrypted_file = aes_cipher.decrypt(encrypted_file)
        end_time = time.perf_counter()
        print(f"AES Cipher: {(end_time - start_time)*1000} ms")
        ###############################
    elif args.cipher == "RSA":
        rsa_cipher = RSACipher()
        start_time = time.perf_counter()
        encrypted_file = rsa_cipher.encrypt(plaintext)
        decrypted_file = rsa_cipher.decrypt(encrypted_file)
        end_time = time.perf_counter()
        print(f"RSA Cipher: {(end_time - start_time)*1000} ms")
        ###############################
    else:
        print(f"The provided cipher {args.cipher} is not valid")
        exit(1)

    # Writes string to decryption file to verify
    if args.output:
        with open(args.output, "wb") as f:
            if decrypted_file != None:
                f.write(decrypted_file)


if __name__ == "__main__":
    main()
