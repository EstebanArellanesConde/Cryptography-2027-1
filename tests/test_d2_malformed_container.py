"""D2: pruebas de seguridad para contenedores malformados."""

import json

import pytest

from encryption.chacha20_core import (
    encrypt_bytes,
    decrypt_file,
)