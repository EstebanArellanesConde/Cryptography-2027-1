import os
import json
from datetime import datetime
from base64 import b64encode, b64decode
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

def encrypt_bytes(plaintext: bytes, filename: str) -> tuple[bytes, bytes]:
    # 1. Se genera una llave de 32 bytes y un nonce de 12 bytes de forma aleatoria y segura. 
    # El nonce nunca debe repetirse con la misma llave.
    key = ChaCha20Poly1305.generate_key()
    nonce = os.urandom(12)
    
    # 2. Se crea un diccionario con los metadatos que se desean ocultar (nombre, fecha y tamaño).
    metadata = {
        "filename": filename,
        "timestamp": datetime.utcnow().isoformat(),
        "plaintext_size": len(plaintext)
    }
    # Se convierten los metadatos a formato JSON y luego a bytes para poder encriptarlos.
    meta_bytes = json.dumps(metadata).encode('utf-8')
    
    # Se guarda el tamaño exacto de los metadatos en los primeros 4 bytes. 
    # Esto servirá al desencriptar para saber exactamente dónde terminan los metadatos y dónde empieza el archivo.
    meta_len = len(meta_bytes).to_bytes(4, 'big')
    
    # Se une todo: los 4 bytes del tamaño + los metadatos en bytes + el archivo original. 
    # Todo este bloque será encriptado.
    payload = meta_len + meta_bytes + plaintext

    # 3. Se definen los Datos Autenticados Adicionales (AAD). 
    # Esta información será pública (no encriptada), pero el algoritmo verificará que nadie la altere.
    header = {
        "format": "SecureVault",
        "version": "1.0",
        "algorithm": "ChaCha20-Poly1305"
    }
    aad = json.dumps(header, sort_keys=True).encode('utf-8')

    # 4. Se configura el encriptador con la llave y se ejecuta la encriptación.
    # Se le pasa el nonce, el payload (lo que se quiere ocultar) y el AAD (lo que se quiere proteger de modificaciones).
    chacha = ChaCha20Poly1305(key)
    ct_with_tag = chacha.encrypt(nonce, payload, aad)
    
    # La librería devuelve el texto cifrado y un "tag" de autenticación pegados. 
    # Se separan: los últimos 16 bytes son el tag, el resto es el texto cifrado.
    ciphertext = ct_with_tag[:-16]
    tag = ct_with_tag[-16:]
    
    # 5. Se empaqueta todo en un JSON para que sea fácil de guardar o enviar.
    # Se convierten los datos binarios (nonce, ciphertext, tag) a texto usando Base64.
    container = {
        "header": header,
        "nonce": b64encode(nonce).decode('utf-8'),
        "ciphertext": b64encode(ciphertext).decode('utf-8'),
        "tag": b64encode(tag).decode('utf-8')
    }
    
    # Se devuelve el contenedor JSON en bytes listo para guardarse, junto con la llave (que se debe guardar en un lugar seguro).
    return json.dumps(container, indent=2).encode('utf-8'), key

def encrypt_file(input_path: str, output_path: str) -> bytes:
    # Se lee todo el contenido del archivo original en modo binario ('rb').
    with open(input_path, 'rb') as f:
        plaintext = f.read()
    
    # Se llama a la función principal de encriptación pasándole los datos y el nombre del archivo.
    container_bytes, key = encrypt_bytes(plaintext, os.path.basename(input_path))
    
    # Se guarda el JSON resultante en un nuevo archivo.
    with open(output_path, 'wb') as f:
        f.write(container_bytes)
        
    # Se retorna la llave para que el usuario la guarde. ¡Ojo, la llave no se guarda en el archivo por seguridad!
    return key

def decrypt_file(input_path: str, output_path: str, key: bytes) -> dict:
    # Se lee el archivo encriptado (que es un JSON) y se convierte a diccionario.
    with open(input_path, 'r') as f:
        container = json.load(f)

    # Se revierte la conversión Base64 para recuperar los bytes originales.
    nonce = b64decode(container["nonce"])
    
    # Se vuelve a unir el texto cifrado y el tag de autenticación porque así lo requiere la librería para desencriptar.
    ct_with_tag = b64decode(container["ciphertext"]) + b64decode(container["tag"])
    
    # Se reconstruye el AAD exactamente como estaba. (Se usa sort_keys=True para garantizar el mismo orden).
    aad = json.dumps(container["header"], sort_keys=True).encode('utf-8')

    # Se configura el desencriptador con la llave proporcionada.
    chacha = ChaCha20Poly1305(key)
    
    # Se desencripta. Si un solo bit del archivo, del tag, o del header (AAD) fue modificado por un atacante, 
    # esta línea fallará automáticamente lanzando un error "InvalidTag".
    payload = chacha.decrypt(nonce, ct_with_tag, aad)

    # Se extraen los primeros 4 bytes para saber de qué tamaño son los metadatos.
    meta_len = int.from_bytes(payload[:4], 'big')
    
    # Se corta el payload usando ese tamaño para recuperar el JSON de metadatos y convertirlo a diccionario.
    metadata = json.loads(payload[4:4+meta_len].decode('utf-8'))
    
    # El resto de la información es el archivo original intacto.
    plaintext = payload[4+meta_len:]
    
    # Se guarda el archivo original ya desencriptado en la ruta destino.
    with open(output_path, 'wb') as f:
        f.write(plaintext)
        
    # Se devuelven los metadatos ocultos por si el programa los necesita.
    return metadata