import random
from math import gcd

# Parameters for Kyber
n = 256  # Lattice dimension
q = 3329  # Modulus
k = 2  # Number of reconciliation bits
h = 3  # Number of non-zero coefficients in the error polynomial

def generate_keypair():
    # Generate a random secret key
    sk = [random.randint(-(q // 2), q // 2) for _ in range(n)]

    # Compute the public key
    A = [[random.randint(-(q // 2), q // 2) for _ in range(n)] for _ in range(n)]
    pk = [sum(A[i][j] * sk[j] for j in range(n)) % q for i in range(n)]

    return pk, sk

def encapsulate(public_key):
    # Generate a random error polynomial
    error = [random.randint(-(q // 2), q // 2) for _ in range(n)]
    error[:h] = [0] * h  # Ensure only 'h' non-zero coefficients

    # Compute the ciphertext
    S = [random.randint(-(q // 2), q // 2) for _ in range(n)]
    e = [sum(S[i] * public_key[i] for i in range(n)) + error[i] for i in range(n)]
    
    return S, e

def decapsulate(ciphertext, secret_key):
    # Recover the error polynomial
    error = [ciphertext[i] - sum(secret_key[i] * ciphertext[j] for j in range(n)) for i in range(n)]

    # Perform reconciliation
    error[:h] = [0] * h

    # Decrypt the shared secret
    shared_secret = [ciphertext[i] - error[i] for i in range(n)]

    return shared_secret

# Key exchange example
alice_public_key, alice_secret_key = generate_keypair()
bob_public_key, bob_secret_key = generate_keypair()

alice_ciphertext, alice_error = encapsulate(bob_public_key)
shared_secret_alice = decapsulate(alice_ciphertext, alice_secret_key)
shared_secret_bob = decapsulate(alice_ciphertext, bob_secret_key)

if shared_secret_alice == shared_secret_bob:
    print("Shared secrets match - Key exchange successful!")
else:
    print("Key exchange failed - Shared secrets do not match!")
