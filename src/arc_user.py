import os
import pwd
import keys
import ecrypt
import json
from base64 import b64decode, b64encode

def create_user(password):
  #get username, user id, and group id
  username = os.getenv('USERNAME')
  userid = pwd.getpwnam(username).pw_uid
  groupid = pwd.getpwnam(username).pw_gid
  rootd = '/var/local/arcana/'

  #check if root folder exists
  if 'arcana' in os.listdir('/var/local'):
    if f'{username}' in os.listdir(rootd):
      if 'creds' in os.listdir(f'{rootd}{username}') or 'vault' in os.listdir(f'{rootd}{username}'):
        #user exists already, abort
        return {'result':'FAIL', 'msg':'user already exists'}

  os.makedirs(f'{rootd}{username}', exists_ok = True)

  #salt and hash password
  salt = ecrypt.random_salt(16)
  saltB64 = b64encode(salt) 

  salt2 = ecrypt.random_salt(16)
  salt2B64 = b64encode(salt2) 

  hashed_pass = ecrypt.sha256(password+salt)

  #randomly generate symmetric key
  key = ecrypt.random_key()

  hash2 = ecrypt.sha256(password+salt2)
  key2 = bytes(
    [a ^ b for a, b in zip(hash2[:32], hash[32:])]
  )

  #assemble credential dictionary
  enc_key = ecrypt.enc(key, key2)
  creds = {
    'user':f'{username}',
    'pass':f'{hashed_pass}',
    'key':f'{enc_key}'
    'salt':f'{saltB64}',
    'pepper':f'{salt2B64}'
  }

  #convert credential dict to json string
  output_json = json.dumps(creds)

  with open(f'{rootd}{username}/creds', 'w') as output:
    output.write(output_json)
  
  #create empty dict and write to vault file
  output_json = json.dumps({})

  with open(f'{rootd}{username}/valut', 'w') as output:
    output.write(output_json)

  return {'result': 'SUCC', 'msg':'Created User!'}

