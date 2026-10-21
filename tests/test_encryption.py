import pytest
import os
import json
import base64
from cryptography.exceptions import InvalidTag
from encryption.chacha20_core import encrypt_file, decrypt_file, encrypt_bytes

def test_encrypt_decrypt_returns_identical(tmp_path):
    # Se definen rutas temporales para los archivos de entrada, salida y el archivo recuperado.
    # tmp_path es una herramienta de pytest que crea una carpeta temporal segura para cada prueba.
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.svlt"
    recovered_file = tmp_path / "recovered.txt"
    
    # Se crea un mensaje de prueba y se escribe en el archivo de entrada.
    original_data = b"Contenido super secreto para el vault"
    input_file.write_bytes(original_data)
    
    # Se ejecuta el proceso de encriptación y se guarda la llave generada.
    key = encrypt_file(str(input_file), str(output_file))
    
    # Se ejecuta el proceso de desencriptación usando la llave correcta.
    metadata = decrypt_file(str(output_file), str(recovered_file), key)
    
    # Se verifica que el contenido del archivo recuperado sea exactamente igual al original.
    assert recovered_file.read_bytes() == original_data
    
    # Se verifica que los metadatos ocultos se hayan guardado y recuperado correctamente.
    assert metadata["filename"] == "input.txt"
    assert metadata["plaintext_size"] == len(original_data)

def test_wrong_key_fails(tmp_path):
    # Se preparan los archivos temporales para la prueba.
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.svlt"
    recovered_file = tmp_path / "recovered.txt"
    
    # Se escribe información en el archivo de entrada y se encripta.
    input_file.write_bytes(b"Data")
    encrypt_file(str(input_file), str(output_file))
    
    # Se genera una llave aleatoria totalmente nueva (incorrecta).
    wrong_key = os.urandom(32)
    
    # Se verifica que al intentar desencriptar con la llave incorrecta, 
    # el sistema bloquee el proceso y lance la excepción 'InvalidTag'.
    with pytest.raises(InvalidTag):
        decrypt_file(str(output_file), str(recovered_file), wrong_key)

def test_modified_ciphertext_fails(tmp_path):
    # Se preparan los archivos temporales.
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.svlt"
    recovered_file = tmp_path / "recovered.txt"
    
    # Se crea el archivo y se encripta de manera normal, guardando la llave correcta.
    input_file.write_bytes(b"Data")
    key = encrypt_file(str(input_file), str(output_file))
    
    # Se simula el comportamiento de un atacante abriendo el archivo JSON resultante.
    container = json.loads(output_file.read_text())
    
    # Se extrae el texto cifrado y se decodifica de Base64 a bytes.
    raw_ct = bytearray(base64.b64decode(container["ciphertext"]))
    
    # Se altera intencionalmente el primer byte de la información cifrada (usando una operación XOR).
    if len(raw_ct) > 0:
        raw_ct[0] ^= 0xFF
        
    # Se vuelve a codificar en Base64 y se sobrescribe el archivo encriptado con los datos corruptos.
    container["ciphertext"] = base64.b64encode(raw_ct).decode('utf-8')
    output_file.write_text(json.dumps(container))
    
    # Se verifica que el sistema detecte la manipulación de los datos cifrados 
    # y aborte la desencriptación lanzando un 'InvalidTag', incluso si la llave es correcta.
    with pytest.raises(InvalidTag):
        decrypt_file(str(output_file), str(recovered_file), key)

def test_modified_header_aad_fails(tmp_path):
    # Se preparan los archivos temporales.
    input_file = tmp_path / "input.txt"
    output_file = tmp_path / "output.svlt"
    recovered_file = tmp_path / "recovered.txt"
    
    # Se encripta un archivo y se guarda la llave legítima.
    input_file.write_bytes(b"Data")
    key = encrypt_file(str(input_file), str(output_file))
    
    # Se simula a un atacante intentando modificar los Datos Autenticados Adicionales (AAD).
    container = json.loads(output_file.read_text())
    
    # Se altera un dato público, cambiando la versión de "1.0" a "2.0" en el encabezado JSON.
    container["header"]["version"] = "2.0" 
    
    # Se guardan los cambios maliciosos en el archivo.
    output_file.write_text(json.dumps(container))
    
    # Se verifica que, dado que el encabezado fue alterado, la validación de autenticidad falle
    # y se lance la excepción 'InvalidTag', protegiendo la integridad de la estructura.
    with pytest.raises(InvalidTag):
        decrypt_file(str(output_file), str(recovered_file), key)

def test_multiple_encryptions_produce_different_outputs():
    # Se define un fragmento de datos idéntico.
    data = b"Same data"
    
    # Se encripta exactamente la misma información dos veces consecutivas.
    container1_bytes, key1 = encrypt_bytes(data, "test.txt")
    container2_bytes, key2 = encrypt_bytes(data, "test.txt")
    
    # Se convierten los resultados de bytes a diccionarios JSON para poder analizarlos.
    c1 = json.loads(container1_bytes)
    c2 = json.loads(container2_bytes)
    
    # Se verifica que el "nonce" (número de uso único) generado en la primera encriptación 
    # sea distinto al de la segunda.
    assert c1["nonce"] != c2["nonce"]
    
    # Se verifica que, como resultado de tener llaves y nonces diferentes, 
    # el texto cifrado resultante sea completamente diferente para el mismo archivo.
    assert c1["ciphertext"] != c2["ciphertext"]
