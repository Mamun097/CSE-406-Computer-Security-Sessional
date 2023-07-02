from math import sqrt
import random
import time

k=int(input("Enter the value of k: "))

def find_modular_exponent(a, b, n):
    '''
    Function to find (a^b)mod n
    '''
    product = 1
    while b > 0:
        if b % 2 == 1:
            product = (product * a) % n
        a = (a * a) % n
        b >>= 1
    return product

#check if a number is prime by Miller-Rabin primality test
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

def generate_primitive_root(p):
    '''
    Generating a random number g such that 1 < g < p-1.
    If (g^2)mod p != 1 and (g^((p-1)/2))mod p != 1, then g is a primitive root modulo p
    '''
    while True:
        g = random.randint(2, p-2)
        if find_modular_exponent(g, 2, p) != 1 and find_modular_exponent(g, (p-1)//2, p) != 1:
            break
    return g

def generate_secret_key():
    return random.randint(2**(k//2-1), 2**(k//2))

def generate_public_key(g, a, p):
    return find_modular_exponent(g, a, p)

def generate_shared_secret_key(A, b, p):
    return find_modular_exponent(A, b, p)

def main():
    p_start=time.time()
    p = generate_prime_number(k)
    p_end=time.time()

    g_start=time.time()
    g = generate_primitive_root(p)
    g_end=time.time()

    a_start=time.time()
    a = generate_secret_key()
    a_end=time.time()
    b = generate_secret_key()

    A_start=time.time()
    A = generate_public_key(g, a, p)
    A_end=time.time()
    B = generate_public_key(g, b, p)

    s1_start=time.time()
    s1 = generate_shared_secret_key(B, a, p)
    s1_end=time.time()
    s2 = generate_shared_secret_key(A, b, p)

    if s1 == s2:
        print("Shared secret key generated successfully!")
        print("Shared secret key is: ", s1)
    
    print("\nComputational time:")
    print("-------------------")
    print("Time taken to generate prime number: ", p_end-p_start," seconds")
    print("Time taken to generate primitive root: ", g_end-g_start," seconds")
    print("Time taken to generate secret key: ", a_end-a_start," seconds")
    print("Time taken to generate public key: ", A_end-A_start, " seconds")
    print("Time taken to generate shared key: ", s1_end-s1_start, " seconds")   

if __name__ == '__main__':
    main()