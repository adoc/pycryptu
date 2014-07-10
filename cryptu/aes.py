"""
"""

from Crypto import Random
from Crypto.Cipher import AES

import cryptu.pkcs7


random = Random.new().read


def gen_keyiv(keylen=32, ivlen=16):
    """
    """
    return (random(keylen), random(ivlen))


# @param    bstr    text
# @param    bstr    key
# @param    bstr    iv
# @return   bstr  
def decrypt(ctext, key, iv, mode=AES.MODE_CBC):
    """
    """
    cipher = AES.new(key, mode, iv) # A new cipher each time is required.
    padded_text = cipher.decrypt(ctext)
    return cryptu.pkcs7.decode(padded_text)


# @param    str     text
# @param    bstr    key
# @param    bstr    iv
# @return   bstr    
def encrypt(text, key, iv, mode=AES.MODE_CBC):
    cipher = AES.new(key, mode, iv) # A new cipher each time is required.
    padded_text = cryptu.pkcs7.encode(text)
    return cipher.encrypt(padded_text)


class Aes(object):
    """Simply hangs on to a key/iv and exposes `encrypt` and `decrypt`.
    """
    def __init__(self, key, iv):
        self.key, self.iv = key, iv

    def encrypt(self, text):
        return encrypt(text, self.key, self.iv)

    def decrypt(self, ctext):
        return decrypt(ctext, self.key, self.iv)