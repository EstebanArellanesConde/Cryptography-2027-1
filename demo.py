"""
Secure Vault - Demostraciones del proyecto
D3: Cifrado hibrido con X25519
D5: Firmas digitales Ed25519

NO SE UTILIZA RSA
"""

from demos.demo_alice_bob import main as demo_alice_bob
from demos.demo_security_failures import main as demo_seguridad


def main():
    print("\n====================================")
    print("       SECURE VAULT - DEMO")
    print("====================================")
    print("1. Cifrado y descifrado: Alice y Bob")
    print("2. Pruebas de seguridad")
    print("3. Ejecutar ambas demostraciones")
    print("0. Salir")

    opcion = input("\nSelecciona una opcion: ")

    if opcion == "1":
        demo_alice_bob()

    elif opcion == "2":
        demo_seguridad()

    elif opcion == "3":
        demo_alice_bob()
        print("\n-------------------------------\n")
        demo_seguridad()

    elif opcion == "0":
        print("Saliendo de Secure Vault...")

    else:
        print("Opcion no valida.")


if __name__ == "__main__":
    main()