from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
from math import gcd

# RSA-Schlüsselerzeugung
def generate_rsa_keys(bits=1024):
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    e = 65537
    d = inverse(e, phi)
    return (e, d, n, p, q)

# Abbildung des Plaintexts auf numerische Blöcke
def plaintext_to_int(plaintext):
    return bytes_to_long(plaintext.encode('utf-8'))

def int_to_plaintext(integer):
    return long_to_bytes(integer).decode('utf-8')

# RSA-Verschlüsselung
def rsa_encrypt(m, e, n):
    return pow(m, e, n)

# RSA-Entschlüsselung
def rsa_decrypt(c, d, n):
    return pow(c, d, n)

# Chosen Ciphertext Attacke 3
def cca3_attack(c, e, n, decryption_oracle):
    r = random.randint(2, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(2, n - 1)
    c_prime = (c * pow(r, e, n)) % n
    m_prime = decryption_oracle(c_prime)
    r_inv = inverse(r, n)
    recovered_m = (m_prime * r_inv) % n
    return recovered_m, r, c_prime, m_prime

# Miller-Rabin-Primalitätstest
def is_probable_prime(n, k=10):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randrange(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True

# Funktion zur Bestätigung der Primzahlen
def verify_primes(p, q):
    p_prime = is_probable_prime(p)
    q_prime = is_probable_prime(q)
    print("🔍 Primalitätstest:")
    print(f"p ist {'eine Primzahl' if p_prime else 'keine Primzahl'}")
    print(f"q ist {'eine Primzahl' if q_prime else 'keine Primzahl'}\n")

# Beispielnachricht
message = "Hallo Alice"
message_int = plaintext_to_int(message)

# RSA-Schlüssel erzeugen
e, d, n, p, q = generate_rsa_keys()
assert message_int < n, "Nachricht zu lang für Modulus!"

# Primzahlen prüfen
verify_primes(p, q)

# Verschlüsselung
cipher = rsa_encrypt(message_int, e, n)

# Oracle (Entschlüsselungssimulation)
oracle = lambda c: rsa_decrypt(c, d, n)

# Angriff ausführen
recovered_int, r_used, manipulated_cipher, oracle_output = cca3_attack(cipher, e, n, oracle)
recovered_msg = int_to_plaintext(recovered_int)

# Strukturierte Ausgabe
print("RSA-Schlüssel:")
print(f"Public Key (e, n):\n  e = {e}\n  n = {n}\n")
print(f"Private Key (d):\n  {d}\n")
print(f"Primzahlen:\n  p = {p}\n  q = {q}\n")

print("✉Nachricht & Konvertierung:")
print(f"Plaintext: {message}")
print(f"Numerische Repräsentation: {message_int}\n")

print("RSA-Verschlüsselung:")
print(f"Ciphertext:\n  {cipher}\n")

print("Chosen Ciphertext Attacke 3:")
print(f"Zufälliger Wert r:\n  {r_used}")
print(f"Manipulierter Ciphertext c' = c * r^e mod n:\n  {manipulated_cipher}")
print(f"Oracle-Rückgabe (m * r mod n):\n  {oracle_output}\n")

print("Wiederhergestellter Klartext:")
print(f"Numerisch: {recovered_int}")
print(f"Als Text: {recovered_msg}")
