
import os
import hashlib
import hmac
import base64
from typing import List

s_box = [
    # 0     1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
]

inv_s_box = [0]*256
for i,v in enumerate(s_box):
    inv_s_box[v] = i

Rcon = [0x00,0x01,0x02,0x04,0x08,0x10,0x20,0x40,0x80,0x1b,0x36]


def xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x^y for x,y in zip(a,b))

def pad_pkcs7(data: bytes) -> bytes:
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]*pad_len)

def unpad_pkcs7(data: bytes) -> bytes:
    if len(data)==0 or len(data)%16 != 0:
        raise ValueError("Invalid padded data length")
    pad = data[-1]
    if pad<1 or pad>16:
        raise ValueError("Invalid padding")
    if data[-pad:] != bytes([pad])*pad:
        raise ValueError("Invalid PKCS7 padding.")
    return data[:-pad]

def sub_word(word: List[int]) -> List[int]:
    return [s_box[b] for b in word]

def rot_word(word: List[int]) -> List[int]:
    return word[1:]+word[:1]

def key_expansion(key: bytes) -> List[int]:

    Nk = 4
    Nb = 4
    Nr = 10
    w = [0]*(4*(Nr+1)*4)

    words = []
    for i in range(Nk):
        words.append([key[4*i], key[4*i+1], key[4*i+2], key[4*i+3]])
    for i in range(Nk, Nb*(Nr+1)):
        temp = words[i-1].copy()
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            temp[0] ^= Rcon[i//Nk]
        word_i = [ (words[i-Nk][j] ^ temp[j]) for j in range(4) ]
        words.append(word_i)

    expanded = []
    for w in words:
        expanded.extend(w)
    return expanded 

def add_round_key(state: List[int], round_key: List[int]):
    for i in range(16):
        state[i] ^= round_key[i]

def sub_bytes(state: List[int]):
    for i in range(16):
        state[i] = s_box[state[i]]

def inv_sub_bytes(state: List[int]):
    for i in range(16):
        state[i] = inv_s_box[state[i]]

def shift_rows(state: List[int]):

    tmp = state.copy()

    state[1]  = tmp[5]
    state[5]  = tmp[9]
    state[9]  = tmp[13]
    state[13] = tmp[1]

    state[2]  = tmp[10]
    state[6]  = tmp[14]
    state[10] = tmp[2]
    state[14] = tmp[6]

    state[3]  = tmp[15]
    state[7]  = tmp[3]
    state[11] = tmp[7]
    state[15] = tmp[11]

def inv_shift_rows(state: List[int]):
    tmp = state.copy()

    state[1]  = tmp[13]
    state[5]  = tmp[1]
    state[9]  = tmp[5]
    state[13] = tmp[9]
    state[2]  = tmp[10]
    state[6]  = tmp[14]
    state[10] = tmp[2]
    state[14] = tmp[6]
    state[3]  = tmp[7]
    state[7]  = tmp[11]
    state[11] = tmp[15]
    state[15] = tmp[3]

def xtime(a):
    return ((a<<1) ^ 0x1b) & 0xff if (a & 0x80) else (a<<1)

def mix_single_column(a):

    t = a[0] ^ a[1] ^ a[2] ^ a[3]
    u = a[0]
    a[0] ^= t ^ xtime(a[0] ^ a[1])
    a[1] ^= t ^ xtime(a[1] ^ a[2])
    a[2] ^= t ^ xtime(a[2] ^ a[3])
    a[3] ^= t ^ xtime(a[3] ^ u)
    return a

def mix_columns(state: List[int]):
    for i in range(4):
        col = [state[i], state[i+4], state[i+8], state[i+12]]
        col = mix_single_column(col)
        state[i], state[i+4], state[i+8], state[i+12] = col

def mul(a, b):
    res = 0
    for i in range(8):
        if b & 1:
            res ^= a
        hi_bit_set = a & 0x80
        a = (a << 1) & 0xff
        if hi_bit_set:
            a ^= 0x1b
        b >>= 1
    return res

def inv_mix_columns(state: List[int]):
    for i in range(4):
        a0 = state[i]; a1 = state[i+4]; a2 = state[i+8]; a3 = state[i+12]
        state[i]   = (mul(a0,0x0e) ^ mul(a1,0x0b) ^ mul(a2,0x0d) ^ mul(a3,0x09)) & 0xff
        state[i+4] = (mul(a0,0x09) ^ mul(a1,0x0e) ^ mul(a2,0x0b) ^ mul(a3,0x0d)) & 0xff
        state[i+8] = (mul(a0,0x0d) ^ mul(a1,0x09) ^ mul(a2,0x0e) ^ mul(a3,0x0b)) & 0xff
        state[i+12]= (mul(a0,0x0b) ^ mul(a1,0x0d) ^ mul(a2,0x09) ^ mul(a3,0x0e)) & 0xff

def encrypt_block(input_bytes: bytes, expanded_key: List[int]) -> bytes:

    state = list(input_bytes)
    Nr = 10

    add_round_key(state, expanded_key[0:16])
    for rnd in range(1, Nr):
        sub_bytes(state)
        shift_rows(state)
        mix_columns(state)
        add_round_key(state, expanded_key[16*rnd:16*(rnd+1)])

    sub_bytes(state)
    shift_rows(state)
    add_round_key(state, expanded_key[16*Nr:16*(Nr+1)])
    return bytes(state)

def decrypt_block(input_bytes: bytes, expanded_key: List[int]) -> bytes:
    state = list(input_bytes)
    Nr = 10
    add_round_key(state, expanded_key[16*Nr:16*(Nr+1)])
    inv_shift_rows(state)
    inv_sub_bytes(state)
    for rnd in range(Nr-1, 0, -1):
        add_round_key(state, expanded_key[16*rnd:16*(rnd+1)])
        inv_mix_columns(state)
        inv_shift_rows(state)
        inv_sub_bytes(state)
    add_round_key(state, expanded_key[0:16])
    return bytes(state)


def derive_key(password: str) -> bytes:

    digest = hashlib.sha256(password.encode("utf-8")).digest()
    return digest 

def aes_encrypt(plaintext: str, password: str) -> str:
    key_material = derive_key(password)
    aes_key = key_material[:16]  
    hmac_key = hashlib.sha256(key_material[16:]+b"HMAC").digest() 
    iv = os.urandom(16)
    expanded = key_expansion(aes_key)
    data = pad_pkcs7(plaintext.encode("utf-8"))
   
    blocks = [data[i:i+16] for i in range(0,len(data),16)]
    prev = iv
    ct = b""
    for blk in blocks:
        x = xor_bytes(blk, prev)
        enc = encrypt_block(x, expanded)
        ct += enc
        prev = enc

    tag = hmac.new(hmac_key, iv+ct, hashlib.sha256).digest()
    packed = iv + tag + ct
    return base64.b64encode(packed).decode("utf-8")

def aes_decrypt(token_b64: str, password: str) -> str:
    key_material = derive_key(password)
    aes_key = key_material[:16]
    hmac_key = hashlib.sha256(key_material[16:]+b"HMAC").digest()
    data = base64.b64decode(token_b64)
    if len(data) < 16+32:
        raise ValueError("Token too short")
    iv = data[:16]
    tag = data[16:48]
    ct = data[48:]

    calc = hmac.new(hmac_key, iv+ct, hashlib.sha256).digest()
    if not hmac.compare_digest(calc, tag):
        raise ValueError("HMAC verification failed (wrong password or corrupted data)")

    expanded = key_expansion(aes_key)
    if len(ct) % 16 != 0:
        raise ValueError("Ciphertext length invalid")
    blocks = [ct[i:i+16] for i in range(0,len(ct),16)]
    prev = iv
    plain_bytes = b""
    for blk in blocks:
        dec = decrypt_block(blk, expanded)
        plain_bytes += xor_bytes(dec, prev)
        prev = blk
    p = unpad_pkcs7(plain_bytes)
    return p.decode("utf-8")
