# poc/poc_sss.py
# PoC de Shamir Secret Sharing (compatibilidad Python 3.12+)


import secrets
from functools import reduce #opcional para pruebas 
import os

def _eval_polynomial(coeffs, x, prime):
    """Evalúa un polinomio con coeficientes mod prime."""
    return sum([coeff * pow(x, i, prime) for i, coeff in enumerate(coeffs)]) % prime

def generar_shares(secret_int, n=5, t=3, prime=2**521 - 1):
    """Genera n shares, donde se requieren t para reconstruir el secreto."""
    coeffs = [secret_int] + [secrets.randbelow(prime) for _ in range(t - 1)]
    shares = [(i, _eval_polynomial(coeffs, i, prime)) for i in range(1, n + 1)]
    return shares

def recombinar_shares(shares, prime=2**521 - 1):
    """Reconstruye el secreto usando interpolación de Lagrange."""
    def _lagrange_basis(j):
        xj, yj = shares[j]
        num = den = 1
        for m in range(len(shares)):
            if m != j:
                xm, _ = shares[m]
                num = (num * -xm) % prime
                den = (den * (xj - xm)) % prime
        return (yj * num * pow(den, -1, prime)) % prime
    return sum(_lagrange_basis(j) for j in range(len(shares))) % prime

# Pruebas
def main():
    print("=== PoC SSS Básico (sin dependencias externas) ===\n")

    # Generar clave maestra (256 bits)
    clave_bytes = secrets.token_bytes(32)
    clave_int = int.from_bytes(clave_bytes, "big")
    print(f" Clave maestra (hex): {clave_bytes.hex()}\n")

    # Divide 
    shares = generar_shares(clave_int, n=5, t=3)
    os.makedirs("custodios", exist_ok=True)
    for i, (x, y) in enumerate(shares, 1):
        with open(f"custodios/share_{i}.txt", "w") as f:
            f.write(f"{x},{y}")
    print("Se generaron 5 partes en /custodios\n")

    # Usar 3 para recuperar
    partes_para_usar = shares[:3]
    clave_recuperada_int = recombinar_shares(partes_para_usar)
    clave_recuperada_bytes = clave_recuperada_int.to_bytes(32, "big")

    print(f" Clave reconstruida (hex): {clave_recuperada_bytes.hex()}\n")
    print("Coinciden" if clave_bytes == clave_recuperada_bytes else "❌ Error: no coinciden")

if __name__ == "__main__":
    main()
