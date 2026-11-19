
"""D5: demostracion de rechazo de ataques criptograficos."""

import json
import sys
from base64 import b64decode, b64encode
from pathlib import Path

# Permite importar los modulos desde src.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from encryption.hybrid_core import generate_keypair
from encryption.signed_hybrid import (
    encrypt_signed_hybrid,
    decrypt_signed_hybrid,
)
from signatures.signature_core import generate_signing_keypair


def verificar_rechazo(
    nombre,
    contenedor,
    clave_receptor,
    clave_firmante,
    motivo_esperado,
):
    """
    Verifica que un ataque sea rechazado por la causa esperada.

    No basta con detectar cualquier error:
    comprobamos que corresponda al escenario evaluado.
    """
    try:
        decrypt_signed_hybrid(
            contenedor,
            clave_receptor,
            clave_firmante,
        )

    except ValueError as error:
        if motivo_esperado not in str(error):
            raise AssertionError(
                f"{nombre}: rechazo por causa inesperada: {error}"
            ) from error

        print(f"[OK] {nombre}")
        print(f"     Motivo verificado: {error}")

    else:
        raise AssertionError(
            f"ERROR DE SEGURIDAD: {nombre} fue aceptado."
        )


def main():
    print("=== DEMOSTRACION DE SEGURIDAD D3 + D5 ===")

    # Generar pares de claves X25519 para los participantes.
    _, alice_public = generate_keypair()
    bob_private, bob_public = generate_keypair()
    charlie_private, _ = generate_keypair()

    # Generar claves Ed25519 independientes para las firmas.
    signing_private, signing_public = generate_signing_keypair()
    _, wrong_signing_public = generate_signing_keypair()

    # Documento confidencial.
    original = b"Informe privado de Alice para Bob."

    # Alice cifra para dos destinatarios y firma el contenedor.
    contenedor = encrypt_signed_hybrid(
        original,
        "informe.txt",
        [alice_public, bob_public],
        signing_private,
    )

    print("\n[1] Alice genero un contenedor cifrado y firmado.")

    # ==========================================================
    # CASO 1: MODIFICACION DEL CIPHERTEXT
    # ==========================================================

    datos = json.loads(contenedor)
    ciphertext = b64decode(datos["ciphertext"], validate=True)

    # Modificar un bit del contenido cifrado.
    modificado = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
    datos["ciphertext"] = b64encode(modificado).decode("ascii")

    contenedor_alterado = json.dumps(datos).encode("utf-8")

    print("\n[2] ATAQUE: modificar el contenido cifrado")

    verificar_rechazo(
        "Contenedor manipulado rechazado",
        contenedor_alterado,
        bob_private,
        signing_public,
        "Firma digital inválida",
    )

    # ==========================================================
    # CASO 2: CLAVE PUBLICA DE FIRMA INCORRECTA
    # ==========================================================

    print("\n[3] ATAQUE: utilizar otra clave de firma")

    verificar_rechazo(
        "Firmante incorrecto rechazado",
        contenedor,
        bob_private,
        wrong_signing_public,
        "El firmante no coincide",
    )

    # ==========================================================
    # CASO 3: DESTINATARIO NO AUTORIZADO
    # ==========================================================

    print("\n[4] ATAQUE: Charlie intenta descifrar")

    verificar_rechazo(
        "Destinatario no autorizado rechazado",
        contenedor,
        charlie_private,
        signing_public,
        "Destinatario no autorizado",
    )

    print("\nRESULTADO: TRES ESCENARIOS DE SEGURIDAD SUPERADOS")


if __name__ == "__main__":
    main()
