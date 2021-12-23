import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def load_file(file):
    """
    Loads the key from the current directory named `key.key`
    """
    return open(file, "r").read()


def hex_to_bytes(_hex):
    """
    Converts hex strings to bytes
    :param _hex: string
    :return: bytes
    """
    return bytes.fromhex(_hex)


class AuthenticatedEncryption:

    def __init__(self, **kwargs):

        self.directory = kwargs['directory']
        self.key_n = kwargs['key_n']
        self.nonce_n = kwargs['nonce_n']

        self.key_file = os.path.join(self.directory, self.key_n)
        self.nonce_file = os.path.join(self.directory, self.nonce_n)

    def generate_key(self):
        """
        Generates a key and save it into a file
        """
        key = AESGCM.generate_key(bit_length=256)

        with open(os.path.join(self.directory, self.key_file), "w") as key_file:
            key_file.write(key.hex())

        return key

    def write_file(self, encrypted_data):
        """
        Writes a string into a file named data.enc saved into the directory specified in the class
        :param encrypted_data: bytes
        :return:
        """
        new_file = os.path.join(self.directory, "data")
        enc_file = new_file + '.enc'
        with open(enc_file, "w") as file:
            file.write(encrypted_data.hex())

    def encrypt(self, _file, key):
        """
        Given a filename (str) and key (bytes), it encrypts the file and write it
        """

        aesgcm = AESGCM(key)
        nonce = os.urandom(12)

        with open(os.path.join(self.directory, self.nonce_file), "w") as nf:
            nf.write(nonce.hex())
        _data = str.encode(load_file(_file))
        encrypted_data = aesgcm.encrypt(nonce, _data, None)
        self.write_file(encrypted_data)

    def decrypt(self, encrypted_data):
        """
        Given a filename (str) and key (bytes), it decrypts the file and write it
        """

        nonce = hex_to_bytes(load_file(self.nonce_file))

        key = hex_to_bytes(load_file(self.key_file))

        aesgcm = AESGCM(key)
        d_data = aesgcm.decrypt(nonce, encrypted_data, None)

        decr_file = os.path.join(self.directory, 'decrypted_data.dat')

        with open(decr_file, "w") as file:
            file.write(d_data.decode())

        return d_data
