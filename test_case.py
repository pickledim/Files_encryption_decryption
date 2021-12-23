import src.encryption as enc 
import os

# fill the data
directory = r'./'
key_name = 'key.key'
nonce_name = 'nonce.key'
file_ = 'test_data.dat'

inputs = {
    'directory': directory,
    'key_n': key_name,
    'nonce_n': nonce_name
        }

ath_encr = enc.AuthenticatedEncryption(**inputs)
key = ath_encr.generate_key()
ath_encr.encrypt(file_, key)

encr_data = enc.hex_to_bytes(enc.load_file(os.path.join(directory, 'data.enc')))
decrypted_data = ath_encr.decrypt(encr_data)
