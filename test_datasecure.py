
from datasecure import  encrypt_data, decrypt_text




#encrypted must be a string.
# encrypted should not be equal to original_text (it should be encrypted).
# decrypted must be equal to original_text (it should be decrypted back to the original text).
def test_encrypt_decrypt_success():
    original_text = "SecretMessage"
    passkey = "mysecretpass"

    
    encrypted = encrypt_data(original_text, passkey)
    assert isinstance(encrypted, str) 
    assert encrypted != original_text 

    decrypted = decrypt_text(encrypted, passkey)
    assert decrypted == original_text



# This assumes decrypt_text returns None if the key is incorrect 
def test_decrypt_with_wrong_passkey():
    text = "Confidential"
    right_key = "correct"
    wrong_key = "wrong"

    encrypted = encrypt_data(text, right_key)

    decrypted = decrypt_text(encrypted, wrong_key)

    assert decrypted is None # Expect None on decryption failure (wrong key)

def test_decrypt_with_corrupted_data():
    
    original_text = "ValidData"
    passkey = "mykey"
    encrypted = encrypt_data(original_text, passkey)
    print(f"Encrypted: {encrypted}")
    corrupted_encrypted = encrypted[:-5] + "XXXXX" # slice 0 t0 -5 and and add "XXXXX" to the end of the string to corrupt it.

    decrypted = decrypt_text(corrupted_encrypted, passkey)
    assert decrypted is None # Expect None if data is corrupted (Fernet raises InvalidToken)

