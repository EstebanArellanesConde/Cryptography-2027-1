
"""D3 + D5: demostracion de intercambio seguro Alice/Bob."""

from pathlib import Path
import sys

# Permite importar los modulos existentes desde src.
ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from encryption.hybrid_core import generate_keypair
from encryption.signed_hybrid import (
    encrypt_signed_hybrid,
    decrypt_signed_hybrid,
)
from signatures.signature_core import generate_signing_keypair


def main():
    print("=== DEMOSTRACION D3 + D5: ALICE Y BOB ===")

    # Alice y Bob generan sus claves X25519.
    _, alice_public = generate_keypair()
    bob_private, bob_public = generate_keypair()

    # Alice genera un par independiente para firmar.
    signing_private, signing_public = generate_signing_keypair()

    print("[1] Claves X25519 y Ed25519 generadas.")

    # Documento original.
    original = b"Documento confidencial enviado por Alice."
    filename = "documento.txt"

    # D3 requiere al menos dos destinatarios autorizados.
    recipients = [alice_public, bob_public]

    # Cifrado hibrido y firma digital.
    container = encrypt_signed_hybrid(
        original,
        filename,
        recipients,
        signing_private,
    )

    print("[2] Alice cifro el documento con ChaCha20-Poly1305.")
    print("[3] Clave de archivo protegida para Alice y Bob.")
    print("[4] Contenedor firmado con Ed25519.")
    print(f"[5] Contenedor protegido: {len(container)} bytes.")

    # Simulacion de entrega del contenedor a Bob.
    received_container = container
    print("[6] Bob recibio el contenedor (simulacion local).")

    # D5 verifica la firma antes de llamar al descifrado D3.
    recovered, metadata = decrypt_signed_hybrid(
        received_container,
        bob_private,
        signing_public,
    )

    print("[7] Firma de Alice verificada correctamente.")
    print("[8] Bob descifro el documento.")

    # Comparacion de integridad del resultado.
    assert recovered == original
    print("[9] Documento recuperado identico al original.")
    print("RESULTADO: DEMOSTRACION EXITOSA")


if __name__ == "__main__":
    main()
