#!/usr/bin/env python3
"""
Actividad Sesión 22 de Octubre: Cifrado Asimétrico con Curvas Elípticas (ECIES)
Curso: Criptografía 2027-1 (Facultad de Ingeniería, UNAM)
Profesor: Dra. Rocío Alejandra Aldeco Pérez
Equipo 6: Secure Digital Document Vault

Este programa implementa y demuestra el funcionamiento del esquema ECIES:
1. Generación de llaves asimétricas (Pública y Privada) usando curvas elípticas (SECP256R1).
2. Cifrado de un secreto compartido mediante ECIES (ECDH efímero + HKDF-SHA256 + ChaCha20-Poly1305).
3. Inspección del paquete criptográfico (Punto efímero R, Nonce, Ciphertext, Tag Poly1305).
4. Descifrado exitoso por parte del destinatario legítimo (Bob).
5. Verificación de seguridad Fail-Closed ante un atacante no autorizado (Eve) o manipulación.
"""

import sys
import os
import json
from base64 import b64encode, b64decode

# Asegurar importación del paquete encryption desde src/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from encryption.ecies_core import (
    generate_ec_key_pair,
    compute_ec_fingerprint,
    ecies_encrypt,
    ecies_decrypt,
    export_public_key_pem,
    export_private_key_pem,
    ECIESDecryptionError,
)

def print_separator(title=""):
    width = 75
    if title:
        print(f"\n{'='*5} {title} {'='*(width - len(title) - 7)}")
    else:
        print("=" * width)

def main():
    print_separator("ACTIVIDAD 22 DE OCTUBRE: CIFRADO ASIMÉTRICO ECIES (ECC)")
    print("Módulo: Esquema de Cifrado Integrado de Curva Elíptica (ECIES)")
    print("Curva: SECP256R1 (NIST P-256) | KDF: HKDF-SHA256 | Cifrador: ChaCha20-Poly1305")
    
    # -----------------------------------------------------------------------
    # PASO 1: Generación de llaves para Bob (Receptor)
    # -----------------------------------------------------------------------
    print_separator("PASO 1: GENERACIÓN DE LLAVES ASIMÉTRICAS (ECC)")
    bob_priv, bob_pub = generate_ec_key_pair()
    bob_fp = compute_ec_fingerprint(bob_pub)
    
    print("[+] Llaves generadas para Bob (Destinatario):")
    print(f"    - Curva Elíptica: {bob_pub.curve.name}")
    print(f"    - Tamaño de Llave: {bob_pub.key_size} bits (Seguridad equivalente a RSA de 3072 bits)")
    print(f"    - Fingerprint SHA-256 (SPKI DER): {bob_fp}")
    
    # Mostrar extracto de la llave pública de Bob en PEM
    bob_pub_pem = export_public_key_pem(bob_pub).decode('utf-8')
    print("\n[+] Clave Pública de Bob (formato PEM transmitible):")
    for line in bob_pub_pem.strip().split('\n')[:3]:
        print(f"    {line}")
    print("    ...")
    print(f"    {bob_pub_pem.strip().splitlines()[-1]}")

    # -----------------------------------------------------------------------
    # PASO 2: Alice cifra un secreto para Bob usando ECIES
    # -----------------------------------------------------------------------
    print_separator("PASO 2: ALICE CIFRA UN SECRETO PARA BOB CON ECIES")
    secreto_original = b"CONFIDENTIAL_VAULT_DEK_KEY_0x7f9a2b8e4c1d6e3f"
    print(f"[+] Secreto original a transmitir: '{secreto_original.decode('utf-8')}' ({len(secreto_original)} bytes)")
    
    # Cifrado ECIES
    aad_contexto = b"Vault-Session-2026-10-22"
    paquete_ecies = ecies_encrypt(
        recipient_public_key=bob_pub,
        plaintext=secreto_original,
        aad=aad_contexto
    )
    
    print("\n[+] Paquete ECIES generado por Alice:")
    print(f"    - Esquema: {paquete_ecies['scheme']}")
    print(f"    - Clave Pública Efímera (R): {paquete_ecies['ephemeral_public_key'][:24]}... (Punto SEC1 comprimido)")
    print(f"    - Nonce (96 bits): {paquete_ecies['nonce']}")
    print(f"    - Ciphertext: {paquete_ecies['ciphertext']}")
    print(f"    - Tag de Autenticación Poly1305 (128 bits): {paquete_ecies['tag']}")

    # -----------------------------------------------------------------------
    # PASO 3: Bob descifra el secreto con su clave privada
    # -----------------------------------------------------------------------
    print_separator("PASO 3: BOB DESCIFRA EL SECRETO CON SU CLAVE PRIVADA")
    secreto_recuperado = ecies_decrypt(
        recipient_private_key=bob_priv,
        package=paquete_ecies,
        aad=aad_contexto
    )
    
    print(f"[+] Secreto recuperado por Bob: '{secreto_recuperado.decode('utf-8')}'")
    assert secreto_recuperado == secreto_original
    print("[✓] ÉXITO: El secreto recuperado coincide exactamente con el secreto original.")

    # -----------------------------------------------------------------------
    # PASO 4: Prueba de Seguridad Fail-Closed (Atacante no autorizado)
    # -----------------------------------------------------------------------
    print_separator("PASO 4: PRUEBA DE SEGURIDAD - ATACANTE NO AUTORIZADO (EVE)")
    eve_priv, eve_pub = generate_ec_key_pair()
    print("[+] Eve intercepta el paquete ECIES e intenta descifrar con su propia clave privada...")
    
    try:
        ecies_decrypt(
            recipient_private_key=eve_priv,
            package=paquete_ecies,
            aad=aad_contexto
        )
        print("[!] ERROR: Eve pudo descifrar (Fallo de seguridad)")
    except ECIESDecryptionError as e:
        print(f"[✓] ÉXITO (Fail-Closed): El sistema rechazó a Eve de inmediato:")
        print(f"    Motivo: {e}")

    # -----------------------------------------------------------------------
    # PASO 5: Prueba de Integridad (Detección de Manipulación en Tránsito)
    # -----------------------------------------------------------------------
    print_separator("PASO 5: PRUEBA DE INTEGRIDAD - MANIPULACIÓN DEL CIPHERTEXT")
    print("[+] Un atacante modifica un bit del texto cifrado en tránsito...")
    paquete_manipulado = dict(paquete_ecies)
    raw_ct = bytearray(b64decode(paquete_manipulado["ciphertext"]))
    raw_ct[0] ^= 0x01
    paquete_manipulado["ciphertext"] = b64encode(raw_ct).decode('utf-8')
    
    try:
        ecies_decrypt(
            recipient_private_key=bob_priv,
            package=paquete_manipulado,
            aad=aad_contexto
        )
        print("[!] ERROR: Se aceptó texto manipulado (Fallo de integridad)")
    except ECIESDecryptionError as e:
        print(f"[✓] ÉXITO (AEAD): Poly1305 detectó la alteración y abortó:")
        print(f"    Motivo: {e}")

    print_separator("FIN DE LA DEMOSTRACIÓN ECIES - TODAS LAS VERIFICACIONES APROBADAS")

if __name__ == "__main__":
    main()
