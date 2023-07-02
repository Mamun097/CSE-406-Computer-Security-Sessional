from BitVector import *
import time

# Sbox for encryption
Sbox = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
)

# InvSbox for decryption
InvSbox = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D
)

Mixer = [
    [BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03"), BitVector(hexstring="01")],
    [BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02"), BitVector(hexstring="03")],
    [BitVector(hexstring="03"), BitVector(hexstring="01"), BitVector(hexstring="01"), BitVector(hexstring="02")]
]
 
InvMixer = [
    [BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09")],
    [BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B"), BitVector(hexstring="0D")],
    [BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E"), BitVector(hexstring="0B")],
    [BitVector(hexstring="0B"), BitVector(hexstring="0D"), BitVector(hexstring="09"), BitVector(hexstring="0E")]
]

round_constants = [1,2,4,8,16,32,64,128,27,54]

#defining an array of all roundkeys
roundkeys = []
cipher_text_chunks = []
decipher_text_chunks = []
AES_modulus = BitVector(bitstring='100011011')

def g(word, round):
    '''rotate the word by 1 byte'''
    word = word << 8
    '''substitute each byte of the word with the corresponding byte in the sbox'''
    for i in range(4):
        word[i*8:i*8+8] = BitVector(intVal=Sbox[word[i*8:i*8+8].intValue()], size=8)
    '''XOR the first byte of the word with the round constant'''
    word[0:8] = word[0:8] ^ BitVector(intVal=round_constants[round-1], size=8)
    return word

def generate_roundkey(prev_roundkey, round):
    '''Split the previous round key into 4 words'''
    w0 = prev_roundkey[0:32]
    w1 = prev_roundkey[32:64]
    w2 = prev_roundkey[64:96]
    w3 = prev_roundkey[96:128]

    temp = w3.deep_copy()

    w4 = w0 ^ g(w3, round)
    w5 = w4 ^ w1
    w6 = w5 ^ w2
    w7 = w6 ^ temp

    return w4 + w5 + w6 + w7

'''Function for Galois Field multiplication'''
def gf_multiply(a, b):
    if isinstance(a, int):
        a = BitVector(intVal=a, size=8)
    if isinstance(b, int):
        b = BitVector(intVal=b, size=8)
    p = a.gf_multiply_modular(b, AES_modulus, 8)
    return p.int_val()

def bitwise_xor_of_two_bitvectors(bitvec1, bitvec2):
    w0 = bitvec1[0:32]
    w1 = bitvec1[32:64]
    w2 = bitvec1[64:96]
    w3 = bitvec1[96:128]

    w0 = w0 ^ bitvec2[0:32]
    w1 = w1 ^ bitvec2[32:64]
    w2 = w2 ^ bitvec2[64:96]
    w3 = w3 ^ bitvec2[96:128]

    return w0 + w1 + w2 + w3

def generate_matrix_in_column_major_order(text):
    '''generate matrix from text in column major order'''
    matrix = [[0 for x in range(4)] for y in range(4)]
    for i in range(4):
        for j in range(4):
            matrix[j][i] = text[i*32+j*8:i*32+j*8+8]
    return matrix

def substitute_bytes(matrix, by_which_one):
    '''substitute each byte of the matrix with the corresponding byte in the Sbox/InvSbox'''
    for i in range(4):
        for j in range(4):
            if by_which_one == "by_sbox":
                matrix[i][j] = BitVector(intVal=Sbox[matrix[i][j].intValue()], size=8)
            elif by_which_one == "by_invsbox":
                matrix[i][j] = BitVector(intVal=InvSbox[matrix[i][j].intValue()], size=8)
    return matrix

def shift_rows(matrix, direction):
    '''
    Circular left/right shift R1 by 1 byte, R2 by 2 byte, R3 by 3 byte
    for left shift, direction = 1
    for right shift, direction = -1
    '''
    matrix[1] = matrix[1][direction*1:] + matrix[1][:direction*1]
    matrix[2] = matrix[2][direction*2:] + matrix[2][:direction*2]
    matrix[3] = matrix[3][direction*3:] + matrix[3][:direction*3]
    return matrix

def mix_columns(matrix, by_which_one):
    result = [[0 for x in range(4)] for y in range(4)]
    for i in range(4):
        for j in range(4):
            for k in range(4):
                if by_which_one == "by_mixer":
                    result[i][j] ^= gf_multiply(Mixer[i][k], matrix[k][j])
                elif by_which_one == "by_invmixer":
                    result[i][j] ^= gf_multiply(InvMixer[i][k], matrix[k][j])
    return result

def convert_matrix_to_bitvector(matrix):
    for i in range(4):
        for j in range(4):
            matrix[i][j] = BitVector(intVal=matrix[i][j], size=8)
    return matrix   

def bitwise_xor_of_two_matrices(matrix1, matrix2):
    for i in range(4):
        for j in range(4):
            matrix1[i][j] ^= matrix2[i][j]
    return matrix1

def form_cipher_text_from_bitvector(matrix):
    cipher_text = BitVector(size=0)
    for i in range(4):
        for j in range(4):
            bv = matrix[j][i]
            cipher_text = cipher_text + bv
    return cipher_text


def encryption_rounds(cipher_text, roundkey, round_no):
    if round_no==0:
        return bitwise_xor_of_two_bitvectors(cipher_text, roundkey)
    state_matrix = generate_matrix_in_column_major_order(cipher_text)
    state_matrix = substitute_bytes(state_matrix, "by_sbox")
    state_matrix = shift_rows(state_matrix, 1)
    if round_no!=10:
        state_matrix = mix_columns(state_matrix, "by_mixer")
        state_matrix = convert_matrix_to_bitvector(state_matrix)
    roundkey_matrix = generate_matrix_in_column_major_order(roundkey)
    resultant_matrix = bitwise_xor_of_two_matrices(state_matrix, roundkey_matrix)
    return form_cipher_text_from_bitvector(resultant_matrix)

def decryption_rounds(cipher_text, roundkey , round_no):
    if round_no==0:
        return bitwise_xor_of_two_bitvectors(cipher_text, roundkey)
    state_matrix = generate_matrix_in_column_major_order(cipher_text)
    state_matrix = shift_rows(state_matrix, -1)
    state_matrix = substitute_bytes(state_matrix, "by_invsbox")
    roundkey_matrix = generate_matrix_in_column_major_order(roundkey)
    resultant_matrix = bitwise_xor_of_two_matrices(state_matrix, roundkey_matrix)
    if round_no!=10:
        resultant_matrix = mix_columns(resultant_matrix, "by_invmixer")
        resultant_matrix = convert_matrix_to_bitvector(resultant_matrix)
    return form_cipher_text_from_bitvector(resultant_matrix)

def encryption(plain_text_bitvector, chunk_count):
    #chunk by chunk encryption
    for i in range(chunk_count):
        cipher_text = encryption_rounds(plain_text_bitvector[i*128:(i+1)*128], roundkeys[0], 0)
        for i in range(1, 11):
            cipher_text = encryption_rounds(cipher_text, roundkeys[i], i)
        cipher_text_chunks.append(cipher_text)

    #merge all the chunks
    cipher_text = BitVector(size=0)
    for i in range(chunk_count):
        cipher_text += cipher_text_chunks[i]
    return cipher_text

def decryption(cipher_text, chunk_count):
    #chunk by chunk decryption
    for i in range(chunk_count):
        decipher_text = decryption_rounds(cipher_text[i*128:(i+1)*128], roundkeys[10], 0)
        for i in range(9, -1, -1):
            decipher_text = decryption_rounds(decipher_text, roundkeys[i], 10-i)
        decipher_text_chunks.append(decipher_text)

    #merge all the chunks
    decipher_text = BitVector(size=0)
    for i in range(chunk_count):
        decipher_text += decipher_text_chunks[i]
    return decipher_text

def main():
    print("Plain Text:")
    plain_text = input("In ASCII: ")
    plain_text_hex = plain_text.encode("utf-8").hex()
    print("In Hex:",plain_text_hex,"\n")

    pad_count=0
    chunk_count=0

    plain_text_bitvector = BitVector(size=0)
    if (len(plain_text) % 16) != 0:
        pad_count = 16 - len(plain_text) % 16
        plain_text = plain_text + " " * pad_count
    chunk_count = int(len(plain_text) / 16)

    #convert plain text to bitvector
    for i in range(chunk_count):
        plain_text_bitvector += BitVector(textstring=plain_text[i*16:i*16+16])
    
    print("Key:")
    initial_roundkey = input("In ASCII: ")
    if len(initial_roundkey) > 16:
        initial_roundkey = initial_roundkey[0: 16]
    elif len(initial_roundkey) < 16:
        initial_roundkey = initial_roundkey + '0' * (16 - len(initial_roundkey))
    initial_roundkey_hex = initial_roundkey.encode("utf-8").hex()
    print("In Hex:",initial_roundkey_hex,"\n")
    roundkeys.append(BitVector(textstring=initial_roundkey))

    #generating all the roundkeys
    start_roundkey=time.time()
    for i in range(10):
        roundkeys.append(generate_roundkey(roundkeys[i], i+1))
    end_roundkey=time.time()

    start_encryption=time.time()
    cipher_text = encryption(plain_text_bitvector, chunk_count)
    end_encryption=time.time()
    decipher_text = decryption(cipher_text, chunk_count)
    end_decryption=time.time()

    print("Cipher Text:")
    print("In Hex: ", cipher_text.get_hex_string_from_bitvector())
    print("In ASCII: ", cipher_text.get_bitvector_in_ascii())

    #print ascii text removing the padding and make it same as input
    decipher_text_length=len(decipher_text.get_bitvector_in_ascii())-pad_count
    print("\nDeciphered Text:")
    print("In Hex:",decipher_text.get_hex_string_from_bitvector())
    print("In ASCII:",decipher_text.get_bitvector_in_ascii()[0:decipher_text_length])

    #time calculation
    print("\nExecution time details:")
    print("Key scheduling:",end_roundkey-start_roundkey,"seconds")
    print("Encryption Time:",end_encryption-start_encryption,"seconds")
    print("Decryption Time:",end_decryption-end_encryption,"seconds\n")

if __name__ == '__main__':
    main()
