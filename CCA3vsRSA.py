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

# Erweiterte Version für Aufgabe 35: Chosen Ciphertext Angriff nur mit sinnvollen (gültigen) Texten
def cca3_attack_valid_only(c, e, n, decryption_oracle, maxAttemps=100000):
    attempts = 0

    while attempts < maxAttemps:
        # Waehle zufaelliges r im Bereich [2, n-1]
        r = random.randint(2, n - 1)
        # Stelle sicher, dass r invertierbar modulo n ist (ggT(r, n) == 1)
        if gcd(r, n) != 1:
            continue

        # Manipuliere den urspruenglichen Ciphertext: c' = c * r^e mod n
        c_prime = (c * pow(r, e, n)) % n

        # Frage das Orakel mit c' – das gibt m' = m * r mod n oder None zurück
        m_prime = decryption_oracle(c_prime)

        # Wenn das Orakel nichts zurueckgibt (ungueltiger Text), naechster Versuch
        if m_prime is None:
            attempts += 1
            continue

        try:
            # Rekonstruiere m = m' * r⁻¹ mod n
            recovered = (m_prime * inverse(r, n)) % n
            decoded = long_to_bytes(recovered).decode('utf-8')

            return decoded, attempts + 1

        except:
            # Wenn Umwandlung in UTF-8 fehlschlaegt: versuche erneut
            attempts += 1
            continue

    # Kein gueltiger Text innerhalb der max. Versuche gefunden
    return None, attempts


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
    print("Primalitätstest:")
    print(f"p ist {'eine Primzahl' if is_probable_prime(p) else 'keine Primzahl'}")
    print(f"q ist {'eine Primzahl' if is_probable_prime(q) else 'keine Primzahl'}\n")

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

# Eingeschränktes Orakel (gibt None zurück bei ungültigem Text)
def oracle_text_only(c):
    try:
        m = rsa_decrypt(c, d, n)
        _ = long_to_bytes(m).decode('utf-8')  # Gültigkeit prüfen
        return m
    except:
        return None

# -------------------------
# Aufgabe 34: CCA3 Angriff
# -------------------------
print("Aufgabe 34 – Standard-CCA3:\n")

recovered_int, r_used, manipulated_cipher, oracle_output = cca3_attack(cipher, e, n, oracle)
recovered_msg = int_to_plaintext(recovered_int)

# Ausgabe
print("RSA-Schlüssel:")
print(f"Public Key (e, n):\n  e = {e}\n  n = {n}\n")
print(f"Private Key (d):\n  {d}\n")
print(f"Primzahlen:\n  p = {p}\n  q = {q}\n")

print("Nachricht & Konvertierung:")
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

# -------------------------
# Aufgabe 35: mit gültigen Texten
# -------------------------
print("\n\n Aufgabe 35 – Erweiterter Angriff mit gültigen Texten:\n")

recovered_valid_msg, attempts = cca3_attack_valid_only(cipher, e, n, oracle_text_only)

if recovered_valid_msg:
    print(f"Erfolgreich nach {attempts} Versuchen.")
    print(f"Wiederhergestellter Text: {recovered_valid_msg}")
else:
    print(f"Kein gültiger Text gefunden nach {attempts} Versuchen.")
