import random


def gcd(a, b):
    while b:
        a, b = b, a % b
    return a


def mod_inverse(e, phi):
    def extended_gcd(a, b):
        if a == 0:
            return b, 0, 1
        gcd_val, x1, y1 = extended_gcd(b % a, a)
        x = y1 - (b // a) * x1
        y = x1
        return gcd_val, x, y

    _, x, _ = extended_gcd(e % phi, phi)
    return (x % phi + phi) % phi


def is_prime(n, k=5):
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False

    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)

        if x == 1 or x == n - 1:
            continue

        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False

    return True


def generate_prime(bits=512):
    while True:
        num = random.getrandbits(bits)
        num |= (1 << (bits - 1)) | 1

        if is_prime(num):
            return num


def generate_keypair(bits=1024):
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)

    n = p * q
    phi = (p - 1) * (q - 1)

    e = 65537

    while gcd(e, phi) != 1:
        e = random.randrange(2, phi)

    d = mod_inverse(e, phi)

    return (e, n), (d, n)


# ===========================================================
# RSA FUNCTIONS
# ===========================================================

def rsa_encrypt(public_key, plaintext):
    e, n = public_key
    return [pow(ord(char), e, n) for char in plaintext]


def rsa_decrypt(private_key, ciphertext):
    d, n = private_key
    return ''.join(chr(pow(char, d, n)) for char in ciphertext)


# ===========================================================
# HELPER FUNCTIONS
# ===========================================================

def generate_random_des_key():
    chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()"
    return ''.join(random.choice(chars) for _ in range(8))


def encrypt_list_to_string(encrypted_list):
    return ",".join(map(str, encrypted_list))


def string_to_encrypted_list(encrypted_string):
    return [int(x) for x in encrypted_string.split(",")]


# ===========================================================
# DES PLACEHOLDER (XOR)
# ===========================================================

def des_encrypt(key, plaintext):
    """
    Placeholder DES: menggunakan XOR sederhana.
    Ganti dengan implementasi DES asli bila diperlukan.
    """
    print(f"[Using placeholder DES_ENCRYPT with key '{key}']")

    key_bytes = key.encode()
    plain_bytes = plaintext.encode()
    key_len = len(key_bytes)

    cipher_bytes = bytearray()

    for i in range(len(plain_bytes)):
        cipher_bytes.append(plain_bytes[i] ^ key_bytes[i % key_len])

    return cipher_bytes.hex()


def des_decrypt(key, ciphertext_hex):
    """
    Placeholder DES decrypt: XOR sederhana.
    """
    print(f"[Using placeholder DES_DECRYPT with key '{key}']")

    key_bytes = key.encode()

    try:
        cipher_bytes = bytes.fromhex(ciphertext_hex)
    except ValueError:
        return "ERROR: Invalid hex data"

    key_len = len(key_bytes)
    plain_bytes = bytearray()

    for i in range(len(cipher_bytes)):
        plain_bytes.append(cipher_bytes[i] ^ key_bytes[i % key_len])

    try:
        return plain_bytes.decode()
    except UnicodeDecodeError:
        return "ERROR: Gagal decode (kunci salah)"
