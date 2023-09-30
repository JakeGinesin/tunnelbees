import random
from Crypto.Util.number import *

def keygen(bits=256):
    """Generate public and private key."""
    p = getPrime(bits)
    g = getRandomRange(2, p-1)
    x = getRandomRange(2, p-2)  # private key
    y = pow(g, x, p)             # public key
    return (p, g, y), x

def prover_commitment(p, g):
    """Step 1: Prover sends a commitment."""
    r = getRandomRange(2, p-2)
    t = pow(g, r, p)
    return t, r

def verifier_challenge(p):
    """Step 2: Verifier sends a challenge."""
    return getRandomRange(1, p-1)

def prover_response(r, c, x, p):
    """Step 3: Prover sends a response."""
    s = (r + c * x) % (p-1)
    return s

def verifier_check(p, g, y, t, c, s):
    """Verifier checks the prover's response."""
    return pow(g, s, p) == (t * pow(y, c, p)) % p

def schnorr_protocol(bits=256):
    """Demonstrate the Schnorr protocol."""
    # Key generation
    params, x = keygen(bits)
    p, g, y = params

    # Step 1: Commitment
    t, r = prover_commitment(p, g)

    # Step 2: Challenge
    c = verifier_challenge(p)

    # Step 3: Response
    s = prover_response(r, c, x, p) 

    # Verification
    if verifier_check(p, g, y, t, c, s):
        print("Verification successful!")
    else:
        print("Verification failed!")

schnorr_protocol()
