# 🔐 PoC: Shamir Secret Sharing en Python

## 📘 Descripción

Este repositorio contiene una **Prueba de Concepto (PoC)** del algoritmo **Shamir Secret Sharing (SSS)** implementado en **Python 3.12+** sin dependencias externas.

Permite **dividir una clave secreta** en varias partes, de forma que solo un subconjunto mínimo de ellas pueda **reconstruir el secreto original**.

---

## ⚙️ Ejecución

```bash
python poc_sss.py
```

### 📦 Salida esperada

```
=== PoC SSS Básico (sin dependencias externas) ===

🔑 Clave maestra (hex): 8f2b76d3cfe4a...f91321c

🔹 Se generaron 5 partes en /custodios

🔒 Clave reconstruida (hex): 8f2b76d3cfe4a...f91321c

✅ Coinciden
```

---

## 🧩 Explicación técnica

- **Generación de clave:** `secrets.token_bytes(32)` → clave de 256 bits.
- **División:** polinomio aleatorio mod `2^521 - 1`.
- **Reconstrucción:** interpolación de Lagrange modular.
- **Archivos generados:** `/custodios/share_1.txt` a `/custodios/share_5.txt`.

---

## 🔒 Propósito

Demostrar cómo un **HSM o sistema distribuido** puede usar Shamir Secret Sharing para:

- Custodiar claves privadas sin punto único de fallo.
- Requerir quorum mínimo de custodios para recuperación.
- Evitar exposición de la clave completa en ningún nodo individual.

---

## 📄 Autor

**Grupo 1**

> Prueba de concepto desarrollada como parte del módulo de seguridad criptográfica.
