import os
from typing import List, Dict, Union
import pickle
import hashlib
from Crypto.Cipher import AES


def get_settings() -> Dict:
    
    settings = {
        'database_path': None,
        'cypher_algorythm': None
    }

    with open('settings.txt') as settings_file:
        for line in settings_file.readlines():
            if not ( line.startswith('#') or line.startswith(' ') ):
                if line.startswith('database_path'):
                    settings['database_path'] = line[ line.index('[') + 1 : -2 ]
                if line.startswith('cypher_algorythm'):
                    settings['cypher_algorythm'] = line[ line.index('[') + 1 : -2 ]
                    if settings['cypher_algorythm'] == '':
                        settings['cypher_algorythm'] = None


    return settings


#----------------- чтение из базы данных / запись в базу данных


def write_to_db(users: List, data: Dict):
    '''
    write to database your files
    '''
    with open(get_path(), 'wb') as file:
        pickle.dump(users, file)
        pickle.dump(data, file)

def read_db()-> List:
    '''
    returns list of users and data dictionary in list
    [users: list, data: dict]
    '''
    try:
        with open(get_path(), 'rb') as file:
            return [pickle.load(file), pickle.load(file)]
    except:
        return [[], {}]


#----- реализации функций симметричного шифрования

# добавление нескольких пробелов в конец байтовой строки чтобы ее длина была кратна 16
transform_password = lambda password_str : password_str + b' ' * (16 - len(password_str) % 16)


# шифрование обычной строки симметричным шифром
encrypt_str = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).encrypt(message.encode())


# шифрование байтовой строки симметричным шифром
symmetric_encrypt_bytes = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).encrypt(message)



# дешифрование обычной строки симметричным шифром
decrypt_str = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).decrypt(message.encode())

# дешифрование байтовой строки симметричным шифром
symmetric_decrypt_bytes = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).decrypt(message)





# хеширование пароля  100 раз просто для дополнительной безопасности
def hash_100(password: str) -> str:
    for i in range(100):
        password = hashlib.sha3_256(password.encode()).hexdigest()
    return password


#----- импортирование пользовательской функции шифрования

def get_cyphering_function():

    from user_functions import transform_password, symmetric_encrypt_str, symmetric_encrypt_bytes, symmetric_decrypt_str, symmetric_decrypt_bytes


    





