import json
from src.encryption.hybrid_core import generate_rsa_keypair, encrypt_hybrid, decrypt_hybrid

print("\n--- 0. PREPARING KEYS (ALICE, BOB, AND CHARLIE) ---")
alice_priv, alice_pub = generate_rsa_keypair()
bob_priv, bob_pub = generate_rsa_keypair()
charlie_priv, charlie_pub = generate_rsa_keypair() # Charlie will be unauthorized

print("\n--- 1. VALID ENCRYPTION -> DECRYPTION WORKS ---")
# Read original file
with open("message.txt", "rb") as f:
    plaintext = f.read()

# Encrypt the file authorizing Alice and Bob
container_bytes = encrypt_hybrid(plaintext, "message.txt", [alice_pub, bob_pub])
with open("hybrid_package.svlt", "wb") as f:
    f.write(container_bytes)
print("[+] File successfully encrypted into 'hybrid_package.svlt'.")
input("\n[PAUSE] Press Enter to decrypt as Alice...")

# Alice decrypts with her private key
with open("hybrid_package.svlt", "rb") as f:
    encrypted_data = f.read()

recovered_plaintext, meta = decrypt_hybrid(encrypted_data, alice_priv)
with open("recovered_alice.txt", "wb") as f:
    f.write(recovered_plaintext)
print("[+] Successful decryption for Alice. 'recovered_alice.txt' created.")
input("\n[PAUSE] Press Enter to demonstrate that Bob can also decrypt...")

print("\n--- 2. SHARED FILE -> RECIPIENT CAN DECRYPT ---")
# Bob decrypts with his private key
recovered_plaintext_bob, meta_bob = decrypt_hybrid(encrypted_data, bob_priv)
with open("recovered_bob.txt", "wb") as f:
    f.write(recovered_plaintext_bob)
print("[+] Successful decryption for Bob (shared file).")
input("\n[PAUSE] Press Enter to attempt decryption as Charlie (Unauthorized)...")

print("\n--- 3. NON-RECIPIENT CANNOT DECRYPT ---")
try:
    # Charlie attempts to decrypt but is not in the recipient list
    decrypt_hybrid(encrypted_data, charlie_priv)
except Exception as e:
    print(f"[!] Access denied for Charlie. Caught error: {type(e).__name__} - {str(e)}")
input("\n[PAUSE] Go to your editor, change or delete one character from 'ciphertext' in the JSON, save it, and press Enter...")

print("\n--- 4. MODIFIED FILE -> DECRYPTION FAILS ---")
try:
    # Alice attempts to decrypt a tampered file
    with open("hybrid_package.svlt", "rb") as f:
        tampered_data = f.read()
    decrypt_hybrid(tampered_data, alice_priv)
except Exception as e:
    print(f"[!] Tampering detected. Decryption safely aborted. Error: {type(e).__name__}")
print("\n--- DEMONSTRATION FINISHED ---")