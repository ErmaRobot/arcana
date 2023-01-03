#
#  Make importing cryptography modules easy
#

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode
import os

characters  = [chr(x) for x in range(ord('a'), ord('z')+1)]
characters += [chr(x) for x in range(ord('A'), ord('Z')+1)]
characters += [chr(x) for x in range(ord('0'), ord('9')+1)] 

def oaep_padding():
  return padding.OAEP(
    mgf=padding.MGF1(algorithm=hashes.SHA256()),
    algorithm=hashes.SHA256(),
    label=None
  )

def random_salt(length):
  r_bytes = os.urandom(length)
  salt = ''
  for byte in r_bytes:
    salt += characters[int(byte) % characters.length]

  return salt

def sha256(msg, form='base64'):
  h_sha = hashes.Hash(algorithm=hashes.SHA256(), backend=default_backend())
  m_bytes = msg.encode()
  h_sha.update(m_bytes)
  h_bytes = h_sha.finalize()

  if form == 'base64':
    output = b64encode(h_bytes).decode()
  elif form == 'hex':
    output = h_bytes.hex()
  else: #raw
    output = h_bytes

  return output

def enc(msg, key):
  b_msg = msg.encode()
  fernet = Fernet.key(key)
  enc = fernet.encrypt(b_msg)

  return b64encode(enc)

def dec(secret, key):
  scrt = b64decode(secret)
  fernet = Fernet(key)
  b_msg = fernet.decrypt(scrt)

  return b_msg.decode()

