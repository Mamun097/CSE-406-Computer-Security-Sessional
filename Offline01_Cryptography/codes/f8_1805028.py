import random

def gcd(a,b):
    if b==0:
        return a
    else:
        return gcd(b,a%b)

def find_modular_exponent(base, power, n):
    '''
    Function to find (a^b)mod n
    '''
    product = 1
    while power > 0:
        if power % 2 == 1:
            product = (product * base) % n
        base = (base * base) % n
        power >>= 1
    return product

def is_prime(n):
    if n == 2 or n == 3:
        return True
    if n<=1 or n % 2 == 0:
        return False
    
    '''write n-1 as 2^r*d'''
    r = 0
    d = n-1
    while d % 2 == 0:
        d //= 2
        r += 1
    for i in range(50):
        a = random.randint(2, n-2)
        x = find_modular_exponent(a, d, n)
        if x == 1 or x == n-1:
            continue
        for j in range(r-1):
            x = find_modular_exponent(x, 2, n)
            if x == n-1:
                break
        else:
            return False
    return True

def generate_prime_number(k):
    while True:
        p = random.randint(2**(k-1), 2**k)
        if is_prime(p) and is_prime((p-1)//2):
            break
    return p

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        g, x, y = extended_gcd(b % a, a)
        return g, y - (b // a) * x, x

def encrypt_each_char(char, e, n):
    char = ord(char)
    return find_modular_exponent(char, e, n)
def decrypt_each_char(val, d, n):
    val = find_modular_exponent(val, d, n)
    return chr(val)

def encrypt(message, e, n):
    encrypted_message = [ encrypt_each_char(char, e, n) for char in message ]
    return encrypted_message
def decrypt(encrypted_message, d, n):
    decrypted_message = [ decrypt_each_char(char, d, n) for char in encrypted_message ]
    return ''.join(decrypted_message)

def generate_p_q_n_phi(k):
    p=generate_prime_number(k/16)
    q=generate_prime_number(k/16)
    n=p*q
    phi=(p-1)*(q-1)
    return p,q,n,phi

def calculate_public_exponent(phi):
    e=random.randint(2,phi-1)
    while gcd(e,phi)!=1:
        e=random.randint(2,phi-1)
    return e

def calculate_private_exponent(e, phi):
    _, x, _ = extended_gcd(e, phi)
    return x % phi


def main():
    k=int(input("Enter the value of k: "))
    p,q,n,phi=generate_p_q_n_phi(k)

    e=calculate_public_exponent(phi)
    d=calculate_private_exponent(e,phi)
    
    print("Public key: ",e,n)
    print("Private key: ",d,n)
    plain_text=input("Enter the message: ")

    cipher_text=encrypt(plain_text,e,n)
    print("Encrypted message: ",cipher_text)

    decrypted_message=decrypt(cipher_text,d,n)
    print("Decrypted message: ",decrypted_message)

if __name__ == '__main__':
    main()
