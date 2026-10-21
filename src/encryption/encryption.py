import os
import json
from datetime import datetime
from base64 import b64encode, b64decode
from Crypto.Cipher import AES

class VaultEncryption:
    def __init__(self, key: bytes = None):
        # Genera una llave fresca de 256 bits si no se proporciona una
        self.key = key or os.urandom(32)

    def encrypt_file(self, plaintext: bytes, filename: str) -> dict:
        # Generación de Nonce seguro (96 bits para GCM) usando APIs del OS
        nonce = os.urandom(12)
        cipher = AES.new(self.key, AES.MODE_GCM, nonce=nonce)
        
        # Metadatos requeridos
        metadata = {
            "filename": filename,
            "algorithm_version": "AES-GCM-256",
            "creation_timestamp": datetime.utcnow().isoformat()
        }
        
        # Vincular metadatos a la encriptación (Associated Authenticated Data - AAD)
        aad = json.dumps(metadata, sort_keys=True).encode('utf-8')
        cipher.update(aad)
        
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        
        # Producir contenedor cifrado
        return {
            "header": metadata,
            "nonce": b64encode(nonce).decode('utf-8'),
            "ciphertext": b64encode(ciphertext).decode('utf-8'),
            "authentication_tag": b64encode(tag).decode('utf-8')
        }

    def decrypt_file(self, container: dict, provided_key: bytes) -> bytes:
        nonce = b64decode(container["nonce"])
        ciphertext = b64decode(container["ciphertext"])
        tag = b64decode(container["authentication_tag"])
        
        cipher = AES.new(provided_key, AES.MODE_GCM, nonce=nonce)
        
        # Reconstruir y verificar metadatos
        aad = json.dumps(container["header"], sort_keys=True).encode('utf-8')
        cipher.update(aad)
        
        # Falla de forma segura si la llave, el ciphertext o los metadatos fueron modificados
        return cipher.decrypt_and_verify(ciphertext, tag)
