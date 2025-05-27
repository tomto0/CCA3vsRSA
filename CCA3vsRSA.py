from Crypto.Util.number import getPrime, inverse, bytes_to_long, long_to_bytes
import random
from math import gcd

# RSA-Schlüsselerzeugung
def generate_rsa_keys(bits=1024):
    # Zwei zufaellige Primzahlen erzeugen
    p = getPrime(bits // 2)
    q = getPrime(bits // 2)
    # Modulus n und Eulersche Phi-Funktion berechnen
    n = p * q
    phi = (p - 1) * (q - 1)
    # Oeffentlicher Exponent (fest)
    e = 65537
    # Privater Exponent berechnen (multiplikatives Inverses von e modulo phi)
    d = inverse(e, phi)
    return (e, d, n, p, q)

# Abbildung des Plaintexts auf numerische Bloecke
def plaintext_to_int(plaintext):
    return bytes_to_long(plaintext.encode('utf-8'))

def int_to_plaintext(integer):
    return long_to_bytes(integer).decode('utf-8')

# RSA-Verschluesselung: c = m^e mod n
def rsa_encrypt(m, e, n):
    return pow(m, e, n)

# RSA-Entschluesselung: m = c^d mod n
def rsa_decrypt(c, d, n):
    return pow(c, d, n)

# Chosen Ciphertext Attacke 3
def cca3_attack(c, e, n, decryption_oracle):
    # Zufaellige Zahl r mit gcd(r, n) = 1 auswaehlen
    r = random.randint(2, n - 1)
    while gcd(r, n) != 1:
        r = random.randint(2, n - 1)
    # Manipulierter Ciphertext: c' = c * r^e mod n
    c_prime = (c * pow(r, e, n)) % n
    # Orakel liefert m' = m * r mod n
    m_prime = decryption_oracle(c_prime)
    # Berechne r⁻¹ mod n
    r_inv = inverse(r, n)
    # Rekonstruiere m = m' * r⁻¹ mod n
    recovered_m = (m_prime * r_inv) % n
    return recovered_m, r, c_prime, m_prime

# Miller-Rabin-Primalitaetstest
def is_probable_prime(n, k=10):
    if n < 2:
        return False
    for _ in range(k):
        a = random.randrange(2, n - 1)
        if pow(a, n - 1, n) != 1:
            return False
    return True

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

# Nachricht verschlüsseln
cipher = rsa_encrypt(message_int, e, n)

# Entschlüsselungsorakel definieren
oracle = lambda c: rsa_decrypt(c, d, n)

# Angriff
recovered_int, r_used, manipulated_cipher, oracle_output = cca3_attack(cipher, e, n, oracle)
recovered_msg = int_to_plaintext(recovered_int)

# Ausgabe
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
