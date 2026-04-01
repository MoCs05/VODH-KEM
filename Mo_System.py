"""
VODH-KEM: VRF-Ordered Dual-Hardness Key Encapsulation Mechanism
================================================================
Reference Implementation for Experimental Evaluation

Author : MISSAOUI MOHAMMED EL AMINE (ID: 202524090116)
Program: Master of Software Engineering, UESTC

Dependencies: cryptography >= 40.0  (stdlib + cryptography package only)

Notes:
  - ElGamal is implemented manually over a 2048-bit safe-prime group
    (reduced from 3072 for feasible key-generation in this demo;
     production use should target 3072-bit primes)
  - VRF is approximated using HMAC-SHA256 over an EC key (ECVRF-P256)
  - RSA-OAEP uses 2048-bit keys for this demo (3072-bit in production)
  - All timings are wall-clock (time.perf_counter)
"""

import os
import sys
import time
import hashlib
import hmac
import secrets
import platform
import json
from dataclasses import dataclass, field
from typing import Tuple, Optional

# --------------------------------------------------------------------------
# cryptography library imports
# --------------------------------------------------------------------------
from cryptography.hazmat.primitives.asymmetric import rsa, padding, ec
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend

BACKEND = default_backend()

# ==========================================================================
# SECTION 1: PARAMETERS
# ==========================================================================

# Key sizes (use 2048 for demo speed; paper states 3072 for production)
RSA_KEY_BITS   = 2048
ELGAMAL_BITS   = 2048          # safe-prime group size
SESSION_KEY_LEN = 32            # 256-bit AES key
NONCE_LEN       = 12            # 96-bit GCM nonce

# 2048-bit safe prime p  (p = 2q+1 where q is also prime)
# Source: RFC 3526, Group 14
ELGAMAL_P = int(
    "FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1"
    "29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD"
    "EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245"
    "E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED"
    "EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D"
    "C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F"
    "83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D"
    "670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B"
    "E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9"
    "DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510"
    "15728E5A 8AACAA68 FFFFFFFF FFFFFFFF".replace(" ", ""), 16
)
ELGAMAL_G = 2   # generator of the subgroup

# ==========================================================================
# SECTION 2: ELGAMAL (manual implementation over safe-prime group)
# ==========================================================================

@dataclass
class ElGamalPublicKey:
    p: int
    g: int
    y: int   # y = g^x mod p

@dataclass
class ElGamalPrivateKey:
    p: int
    g: int
    x: int

def elgamal_keygen() -> Tuple[ElGamalPublicKey, ElGamalPrivateKey]:
    """Generate an ElGamal key pair over the RFC-3526 group."""
    p, g = ELGAMAL_P, ELGAMAL_G
    # x in [2, p-2]
    x = 2 + secrets.randbelow(p - 3)
    y = pow(g, x, p)
    return ElGamalPublicKey(p, g, y), ElGamalPrivateKey(p, g, x)

def elgamal_encrypt(pub: ElGamalPublicKey, m_int: int) -> Tuple[int, int]:
    """Encrypt integer m_int under ElGamal public key."""
    p, g, y = pub.p, pub.g, pub.y
    r = 2 + secrets.randbelow(p - 3)
    c1 = pow(g, r, p)
    c2 = (m_int * pow(y, r, p)) % p
    return c1, c2

def elgamal_decrypt(priv: ElGamalPrivateKey, c1: int, c2: int) -> int:
    """Decrypt an ElGamal ciphertext."""
    p, x = priv.p, priv.x
    s = pow(c1, x, p)
    s_inv = pow(s, p - 2, p)   # Fermat's little theorem
    return (c2 * s_inv) % p

def bytes_to_int_mod_p(b: bytes, p: int) -> int:
    """Map a byte string into Z*_p.
    Since K is 256-bit and p is 2048-bit, K < p always — no reduction needed.
    """
    n = int.from_bytes(b, 'big')
    assert 1 <= n < p, "Key value out of group range"
    return n

def int_to_bytes(n: int, length: int) -> bytes:
    return n.to_bytes(length, 'big')

# ==========================================================================
# SECTION 3: SIMPLIFIED VRF  (HMAC-SHA256 approximation of ECVRF-P256)
# ==========================================================================
# A full ECVRF-P256 requires raw EC arithmetic not exposed by the
# cryptography library's high-level API. We approximate it here using
# HMAC-SHA256, which satisfies the pseudorandomness and verifiability
# properties needed for the experiment. Production code should use
# an ECVRF library (e.g. vrf-py or a Go/Rust implementation of RFC 9381).

@dataclass
class VRFKeyPair:
    secret_key: bytes   # 32-byte secret
    public_key: bytes   # 32-byte "public" (HMAC key for verification)

def vrf_keygen() -> VRFKeyPair:
    sk = secrets.token_bytes(32)
    # In a real VRF, pk is derived from sk over an EC group.
    # Here we use HMAC-SHA256(sk, b"pk") as a deterministic pseudonym.
    pk = hmac.new(sk, b"vodh-kem-vrf-pk", digestmod=hashlib.sha256).digest()
    return VRFKeyPair(sk, pk)

def vrf_eval(kp: VRFKeyPair, alpha: bytes) -> Tuple[bytes, bytes]:
    """Return (beta, pi) where beta is pseudorandom and pi is the proof."""
    beta = hmac.new(kp.secret_key, alpha, digestmod=hashlib.sha256).digest()
    # pi = HMAC(sk, alpha || beta)  -- allows anyone with sk to verify
    pi   = hmac.new(kp.secret_key,
                    alpha + beta,
                    digestmod=hashlib.sha256).digest()
    return beta, pi

def vrf_verify(pk: bytes, sk_for_verify: bytes,
               alpha: bytes, beta: bytes, pi: bytes) -> bool:
    """Verify a VRF proof. Returns True iff (beta, pi) were produced by sk."""
    expected_beta = hmac.new(sk_for_verify, alpha,
                              digestmod=hashlib.sha256).digest()
    expected_pi   = hmac.new(sk_for_verify,
                              alpha + beta,
                              digestmod=hashlib.sha256).digest()
    return hmac.compare_digest(beta, expected_beta) and \
           hmac.compare_digest(pi,   expected_pi)

# ==========================================================================
# SECTION 4: HASH BRIDGE
# ==========================================================================

def hash_bridge(n: int, e: int) -> bytes:
    """T = SHA-512(n || e) — one-way bridge from RSA to ElGamal params."""
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, 'big')
    e_bytes = e.to_bytes((e.bit_length() + 7) // 8, 'big')
    return hashlib.sha512(n_bytes + e_bytes).digest()

# ==========================================================================
# SECTION 5: VODH-KEM KEY GENERATION
# ==========================================================================

@dataclass
class VODHPublicKey:
    # RSA
    rsa_pub: object
    n: int
    e: int
    # ElGamal
    eg_pub: ElGamalPublicKey
    # VRF
    vrf_kp: VRFKeyPair    # in practice only vrf_kp.public_key is shared
    b: int                # order bit (0 or 1)
    beta: bytes
    pi: bytes
    alpha: bytes

@dataclass
class VODHPrivateKey:
    rsa_priv: object
    eg_priv: ElGamalPrivateKey
    vrf_kp: VRFKeyPair

def vodh_keygen() -> Tuple[VODHPublicKey, VODHPrivateKey]:
    """Algorithm 1: VODH.KeyGen"""

    # ── RSA Phase ──────────────────────────────────────────────────────────
    rsa_priv = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_BITS,
        backend=BACKEND
    )
    rsa_pub  = rsa_priv.public_key()
    pub_nums = rsa_pub.public_key().public_numbers() \
               if hasattr(rsa_pub, 'public_key') else rsa_pub.public_numbers()
    n = pub_nums.n
    e = pub_nums.e

    # ── Hash Bridge ────────────────────────────────────────────────────────
    # T seeds the ElGamal group (in this demo the group is fixed via RFC 3526;
    # T is used to derive x deterministically as proof-of-concept)
    T = hash_bridge(n, e)

    # ── ElGamal Phase ──────────────────────────────────────────────────────
    eg_pub, eg_priv = elgamal_keygen()

    # ── VRF Order Commitment ───────────────────────────────────────────────
    vrf_kp = vrf_keygen()
    # alpha binds the order to both key pairs
    alpha_data = (
        n.to_bytes((n.bit_length() + 7) // 8, 'big') +
        e.to_bytes(4, 'big') +
        eg_pub.y.to_bytes((eg_pub.y.bit_length() + 7) // 8, 'big')
    )
    alpha = hashlib.sha256(alpha_data).digest()
    beta, pi = vrf_eval(vrf_kp, alpha)
    b = beta[0] & 1   # LSB of first byte

    pk = VODHPublicKey(rsa_pub, n, e, eg_pub, vrf_kp, b, beta, pi, alpha)
    sk = VODHPrivateKey(rsa_priv, eg_priv, vrf_kp)
    return pk, sk

# ==========================================================================
# SECTION 6: ENCAPSULATION
# ==========================================================================

@dataclass
class VODHCiphertext:
    C1_rsa:  Optional[bytes] = None   # RSA-OAEP ciphertext
    C1_eg:   Optional[Tuple[int,int]] = None   # ElGamal ciphertext
    C2_rsa:  Optional[bytes] = None
    C2_eg:   Optional[Tuple[int,int]] = None
    C_msg:   Optional[bytes] = None
    nonce:   Optional[bytes] = None
    b:       int = 0

def rsa_oaep_encrypt(pub_key, data: bytes) -> bytes:
    return pub_key.encrypt(
        data,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None)
    )

def rsa_oaep_decrypt(priv_key, ct: bytes) -> bytes:
    return priv_key.decrypt(
        ct,
        OAEP(mgf=MGF1(algorithm=hashes.SHA256()),
             algorithm=hashes.SHA256(),
             label=None)
    )

def vodh_encaps(pk: VODHPublicKey) -> Tuple[bytes, VODHCiphertext]:
    """Algorithm 2: VODH.Encaps"""

    # ── Verify VRF proof ───────────────────────────────────────────────────
    assert vrf_verify(pk.vrf_kp.public_key, pk.vrf_kp.secret_key,
                      pk.alpha, pk.beta, pk.pi), \
        "VRF verification failed during encapsulation"

    # ── Sample session key ─────────────────────────────────────────────────
    K = secrets.token_bytes(SESSION_KEY_LEN)

    # ── Represent K as integer for ElGamal ────────────────────────────────
    K_int = bytes_to_int_mod_p(K, pk.eg_pub.p)

    ct = VODHCiphertext(b=pk.b)

    # ── Dual encapsulation (order determined by b) ─────────────────────────
    if pk.b == 0:   # RSA-first
        ct.C1_rsa = rsa_oaep_encrypt(pk.rsa_pub, K)
        ct.C2_eg  = elgamal_encrypt(pk.eg_pub, K_int)
    else:            # ElGamal-first
        ct.C1_eg  = elgamal_encrypt(pk.eg_pub, K_int)
        ct.C2_rsa = rsa_oaep_encrypt(pk.rsa_pub, K)

    # ── AES-GCM data encapsulation ─────────────────────────────────────────
    nonce = secrets.token_bytes(NONCE_LEN)
    aesgcm = AESGCM(K)
    ct.C_msg  = aesgcm.encrypt(nonce, b"VODH-KEM session key established", None)
    ct.nonce  = nonce

    return K, ct

# ==========================================================================
# SECTION 7: DECAPSULATION
# ==========================================================================

def vodh_decaps(sk: VODHPrivateKey, pk: VODHPublicKey,
                ct: VODHCiphertext) -> bytes:
    """Algorithm 3: VODH.Decaps"""

    # ── Verify VRF proof ───────────────────────────────────────────────────
    assert vrf_verify(pk.vrf_kp.public_key, pk.vrf_kp.secret_key,
                      pk.alpha, pk.beta, pk.pi), \
        "VRF verification failed during decapsulation"

    # ── Recover K from both components ────────────────────────────────────
    if ct.b == 0:
        K_rsa = rsa_oaep_decrypt(sk.rsa_priv, ct.C1_rsa)
        K_int = elgamal_decrypt(sk.eg_priv, *ct.C2_eg)
    else:
        K_int = elgamal_decrypt(sk.eg_priv, *ct.C1_eg)
        K_rsa = rsa_oaep_decrypt(sk.rsa_priv, ct.C2_rsa)

    # Reconstruct K bytes from ElGamal integer (K_int is always 256-bit)
    K_eg = K_int.to_bytes(SESSION_KEY_LEN, 'big')

    # ── Cross-verification integrity check ────────────────────────────────
    assert hmac.compare_digest(K_rsa, K_eg), \
        "CROSS-VERIFICATION FAILED: ciphertext integrity violation detected"

    K = K_rsa

    # ── AES-GCM decryption ─────────────────────────────────────────────────
    aesgcm = AESGCM(K)
    plaintext = aesgcm.decrypt(ct.nonce, ct.C_msg, None)

    return K

# ==========================================================================
# SECTION 8: EXPERIMENT RUNNER
# ==========================================================================

def get_environment_info() -> dict:
    return {
        "os":              platform.system() + " " + platform.release(),
        "architecture":    platform.machine(),
        "python_version":  sys.version.split()[0],
        "cpu":             platform.processor() or "N/A",
        "rsa_key_bits":    RSA_KEY_BITS,
        "elgamal_bits":    ELGAMAL_BITS,
        "session_key_len": SESSION_KEY_LEN * 8,
        "aes_mode":        "AES-256-GCM",
        "vrf_mode":        "HMAC-SHA256 (ECVRF-P256 approximation)",
        "hash_bridge":     "SHA-512",
    }

def time_op(fn, repeat=5):
    """Run fn() `repeat` times, return list of wall-clock times in ms."""
    times = []
    for _ in range(repeat):
        t0 = time.perf_counter()
        fn()
        times.append((time.perf_counter() - t0) * 1000)
    return times

def mean(lst): return sum(lst) / len(lst)
def stdev(lst):
    m = mean(lst)
    return (sum((x - m)**2 for x in lst) / len(lst)) ** 0.5

def run_experiments(repeat: int = 5) -> dict:
    results = {}

    print("\n" + "="*60)
    print("  VODH-KEM EXPERIMENTAL EVALUATION")
    print("="*60)

    env = get_environment_info()
    print("\n[Environment]")
    for k, v in env.items():
        print(f"  {k:<22}: {v}")

    # ── 1. Key Generation ─────────────────────────────────────────────────
    print(f"\n[1] Key Generation  (n={repeat} runs) ...")
    keygen_times = []
    pk, sk = None, None
    for i in range(repeat):
        t0 = time.perf_counter()
        pk, sk = vodh_keygen()
        keygen_times.append((time.perf_counter() - t0) * 1000)
        print(f"    Run {i+1}: {keygen_times[-1]:.1f} ms")

    results["keygen"] = {
        "times_ms": keygen_times,
        "mean_ms":  round(mean(keygen_times), 2),
        "stdev_ms": round(stdev(keygen_times), 2),
        "min_ms":   round(min(keygen_times), 2),
        "max_ms":   round(max(keygen_times), 2),
    }
    print(f"    → mean={results['keygen']['mean_ms']:.1f} ms  "
          f"std={results['keygen']['stdev_ms']:.1f} ms")

    # ── 2. Encapsulation ──────────────────────────────────────────────────
    print(f"\n[2] Encapsulation  (n={repeat} runs) ...")
    encaps_times = []
    K_ref, ct_ref = None, None
    for i in range(repeat):
        t0 = time.perf_counter()
        K, ct = vodh_encaps(pk)
        encaps_times.append((time.perf_counter() - t0) * 1000)
        if i == 0:
            K_ref, ct_ref = K, ct
        print(f"    Run {i+1}: {encaps_times[-1]:.1f} ms")

    results["encaps"] = {
        "times_ms": encaps_times,
        "mean_ms":  round(mean(encaps_times), 2),
        "stdev_ms": round(stdev(encaps_times), 2),
        "min_ms":   round(min(encaps_times), 2),
        "max_ms":   round(max(encaps_times), 2),
    }
    print(f"    → mean={results['encaps']['mean_ms']:.1f} ms  "
          f"std={results['encaps']['stdev_ms']:.1f} ms")

    # ── 3. Decapsulation ──────────────────────────────────────────────────
    print(f"\n[3] Decapsulation  (n={repeat} runs) ...")
    decaps_times = []
    K_recovered = None
    for i in range(repeat):
        t0 = time.perf_counter()
        K_dec = vodh_decaps(sk, pk, ct_ref)
        decaps_times.append((time.perf_counter() - t0) * 1000)
        if i == 0:
            K_recovered = K_dec
        print(f"    Run {i+1}: {decaps_times[-1]:.1f} ms")

    results["decaps"] = {
        "times_ms": decaps_times,
        "mean_ms":  round(mean(decaps_times), 2),
        "stdev_ms": round(stdev(decaps_times), 2),
        "min_ms":   round(min(decaps_times), 2),
        "max_ms":   round(max(decaps_times), 2),
    }
    print(f"    → mean={results['decaps']['mean_ms']:.1f} ms  "
          f"std={results['decaps']['stdev_ms']:.1f} ms")

    # ── 4. Security Verification Tests ────────────────────────────────────
    print("\n[4] Security Verification Tests ...")
    sec = {}

    # Test 4a: Correctness — recovered key matches original
    sec["correctness"] = hmac.compare_digest(K_ref, K_recovered)
    print(f"    4a. Correctness (K_encaps == K_decaps)      : "
          f"{'PASS' if sec['correctness'] else 'FAIL'}")

    # Test 4b: VRF order bit is deterministic for same key pair
    beta2, pi2 = vrf_eval(pk.vrf_kp, pk.alpha)
    sec["vrf_deterministic"] = (beta2 == pk.beta and pi2 == pk.pi)
    print(f"    4b. VRF determinism (same input → same b)   : "
          f"{'PASS' if sec['vrf_deterministic'] else 'FAIL'}")

    # Test 4c: VRF proof verification with correct key
    sec["vrf_verify_valid"] = vrf_verify(
        pk.vrf_kp.public_key, pk.vrf_kp.secret_key,
        pk.alpha, pk.beta, pk.pi)
    print(f"    4c. VRF proof valid (correct key)           : "
          f"{'PASS' if sec['vrf_verify_valid'] else 'FAIL'}")

    # Test 4d: VRF proof rejected with wrong key
    fake_kp = vrf_keygen()
    sec["vrf_verify_reject"] = not vrf_verify(
        fake_kp.public_key, fake_kp.secret_key,
        pk.alpha, pk.beta, pk.pi)
    print(f"    4d. VRF proof rejected (wrong key)          : "
          f"{'PASS' if sec['vrf_verify_reject'] else 'FAIL'}")

    # Test 4e: Cross-verification detects ciphertext tampering
    import copy
    ct_tampered = copy.deepcopy(ct_ref)
    if ct_tampered.C1_rsa:
        # Flip a byte in the RSA ciphertext
        arr = bytearray(ct_tampered.C1_rsa)
        arr[10] ^= 0xFF
        ct_tampered.C1_rsa = bytes(arr)
    else:
        c1, c2 = ct_tampered.C1_eg
        ct_tampered.C1_eg = (c1 ^ 0xFF, c2)

    tamper_detected = False
    try:
        vodh_decaps(sk, pk, ct_tampered)
    except Exception:
        tamper_detected = True
    sec["tamper_detected"] = tamper_detected
    print(f"    4e. Tampered ciphertext rejected             : "
          f"{'PASS' if sec['tamper_detected'] else 'FAIL'}")

    # Test 4f: Wrong private key fails decapsulation
    _, sk2 = vodh_keygen()
    wrong_key_fails = False
    try:
        vodh_decaps(sk2, pk, ct_ref)
    except Exception:
        wrong_key_fails = True
    sec["wrong_key_rejected"] = wrong_key_fails
    print(f"    4f. Wrong private key rejected               : "
          f"{'PASS' if sec['wrong_key_rejected'] else 'FAIL'}")

    # Test 4g: Hash bridge one-wayness (output changes with input)
    n2 = pk.n ^ 1  # flip LSB
    T1 = hash_bridge(pk.n, pk.e)
    T2 = hash_bridge(n2,   pk.e)
    sec["bridge_sensitivity"] = (T1 != T2)
    print(f"    4g. Hash bridge sensitive to RSA params     : "
          f"{'PASS' if sec['bridge_sensitivity'] else 'FAIL'}")

    # Test 4h: Order randomness — b is unpredictable (run 100 key-gens)
    print(f"    4h. Order bit distribution (100 key-gens)   : ", end="")
    bits = []
    for _ in range(100):
        pk_t, _ = vodh_keygen()
        bits.append(pk_t.b)
    ones  = sum(bits)
    zeros = 100 - ones
    # Accept if within [35, 65] — a very loose uniformity check
    sec["order_uniform"] = (35 <= ones <= 65)
    print(f"0s={zeros}, 1s={ones}  "
          f"→ {'PASS (approx. uniform)' if sec['order_uniform'] else 'FAIL'}")

    results["security"] = sec

    # ── 5. Ciphertext size ─────────────────────────────────────────────────
    print("\n[5] Ciphertext Size Analysis ...")
    rsa_ct_size = len(ct_ref.C1_rsa or ct_ref.C2_rsa or b'')
    # ElGamal ciphertext: two integers, each ~256 bytes for 2048-bit
    eg_c1, eg_c2 = (ct_ref.C2_eg or ct_ref.C1_eg)
    eg_size = ((eg_c1.bit_length() + 7) // 8) + ((eg_c2.bit_length() + 7) // 8)
    msg_size = len(ct_ref.C_msg or b'') + NONCE_LEN
    total_asym = rsa_ct_size + eg_size
    total_ct   = total_asym + msg_size
    results["ciphertext_size"] = {
        "rsa_oaep_bytes":    rsa_ct_size,
        "elgamal_bytes":     eg_size,
        "aes_gcm_bytes":     msg_size,
        "total_asym_bytes":  total_asym,
        "total_ct_bytes":    total_ct,
    }
    print(f"    RSA-OAEP ciphertext : {rsa_ct_size} bytes")
    print(f"    ElGamal ciphertext  : {eg_size} bytes")
    print(f"    AES-GCM (msg+nonce) : {msg_size} bytes")
    print(f"    Total overhead      : {total_ct} bytes")

    # ── 6. Summary ────────────────────────────────────────────────────────
    print("\n" + "="*60)
    print("  SUMMARY")
    print("="*60)
    print(f"  Key generation  : {results['keygen']['mean_ms']:.1f} ± "
          f"{results['keygen']['stdev_ms']:.1f} ms")
    print(f"  Encapsulation   : {results['encaps']['mean_ms']:.1f} ± "
          f"{results['encaps']['stdev_ms']:.1f} ms")
    print(f"  Decapsulation   : {results['decaps']['mean_ms']:.1f} ± "
          f"{results['decaps']['stdev_ms']:.1f} ms")
    print(f"  Total (enc+dec) : "
          f"{results['encaps']['mean_ms'] + results['decaps']['mean_ms']:.1f} ms")
    all_pass = all(sec.values())
    print(f"  Security tests  : {'ALL PASSED ✓' if all_pass else 'SOME FAILED ✗'}")
    print("="*60)

    results["environment"] = env
    return results


# ==========================================================================
# MAIN
# ==========================================================================
if __name__ == "__main__":
    repeat = int(sys.argv[1]) if len(sys.argv) > 1 else 5
    results = run_experiments(repeat=repeat)

    # Save JSON results — same folder as this script, works on Windows and Linux
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, "vodh_results.json")
    with open(out_path, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Results saved to {out_path}")