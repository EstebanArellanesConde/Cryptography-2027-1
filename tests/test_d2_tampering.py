"""D2: pruebas de manipulacion de nonce y tag."""

import json
from base64 import b64decode, b64encode

import pytest
from cryptography.exceptions import InvalidTag

from encryption.chacha20_core import encrypt_bytes, decrypt_file