#
#  Read Private/Public Keys from file, PEM format
#

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from base64 import b64encode
import os

def load_prv_key(data):
  return load_pem_private_key(data, password=None, backend=default_backend())

def load_pub_key(data):
  return load_pem_private_key(data, backend=default_backend())

def generate_asymmetric_keys():
  prv_key = rsa.generate_private_key(
      public_exponent = 65537,
      key_size = 2048,
      backend = default_backend()
    )
  return (prv_key, prv_key.public_key())

def write_pub_key(key, file):
  pem = key.public_bytes(
    serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
  )

  with open(file, "wb") as output:
    output.write(pem)

def write_prv_key(key, file):
  pem = key.private_bytes(
    serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
  )

  with open(file, "wb") as output:
    output.write(pem)

def random_key(length, form='base64'):
  r_bytes = os.urandom(length)

  if form == 'base64':
    output = b64encode(r_bytes).decode()
  elif form == 'hex':
    output = r_bytes.hex()
  else: #raw
    output = r_bytes

  return output

