from math import sqrt
import random

k=128
def find_modular_exponent(a, b, n):
    product = 1
    while b > 0:
        if b % 2 == 1:
            product = (product * a) % n
        a = (a * a) % n
        b >>= 1
    return product
def is_prime(n):
    if n == 2 or n == 3:
        return True
    if n<=1 or n % 2 == 0:
        return False
    
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