import hmac
import hashlib
import time
import sys
import struct
import json

root = "https://hdechallenge-solve.appspot.com/challenge/003/endpoint"
content_type = "application/json"
userid = "karthusliu@gmail.com"
secret_suffix = "HDECHALLENGE003"
shared_secret = userid + secret_suffix

timestep = 30
T0 = 0


def HOTP(K, C, digits=10):
    """HTOP:
    K is the shared key
    C is the counter value
    digits control the response length
    """
    K_bytes = str.encode(K)
    print("K_bytes: ", K_bytes)
    C_bytes = struct.pack(">Q", C)  # unsigned long long
    print("C_byte: ", C_bytes)
    hmac_sha512 = hmac.new(key=K_bytes, msg=C_bytes, digestmod=hashlib.sha512).hexdigest()
    print("hmac_sha512", hmac_sha512)
    print(len(hmac_sha512))
    return Truncate(hmac_sha512)


def Truncate(hmac_sha512):
    """truncate sha512 value"""
    offset = int(hmac_sha512[-1], 16)
    print("offset: ", offset)
    print(hmac_sha512[(offset * 2):((offset * 2) + 8)])
    binary = int(hmac_sha512[(offset * 2):((offset * 2) + 8)], 16) & 0x7FFFFFFF
    print("binary: ", binary)
    return str(binary)


def TOTP(K, digits=10, timeref=0, timestep=30):
    """TOTP, time-based variant of HOTP
    digits control the response length
    the C in HOTP is replaced by ((currentTime - timeref) / timestep)
    """
    C = int(time.time() - timeref) // timestep
    print("C: ", C)
    return HOTP(K, C, digits=digits)


if __name__ == '__main__':
    passwd = TOTP(shared_secret, 20, T0, timestep).zfill(10)
    print("passwd: ", passwd)
