import click
import os
from typing import List, Dict, Union
import pickle
import hashlib
from Crypto.Cipher import AES
import colorama

from fn import *


#--- базовая функция для создания всех команд 
@click.group()
def commands():
    pass

#--- команды

# команда записи в базу одного пароля, с сохранением предыдущих
@click.command()
@click.argument('db_adress')
@click.argument('password')
@click.argument('name')
@click.argument('description', default='')
def write(db_adress: str, password: str, name: str, description: str):
    # password for db is key

    hashed_username, password_for_db, db = authentication(db_adress)
    
    encrypted_password = symmetric_encrypt_bytes(password.encode(), password_for_db)

    if description:
        encrypted_description = symmetric_encrypt_bytes(description.encode(), password_for_db)
    else:
        encrypted_description = b''

    db[1][hashlib.sha3_256(name.encode()).hexdigest()] = [encrypted_password, encrypted_description]

    write_to_db(
        db_adress,
        db[0],
        db[1]
    )

    message_success('database writed')


@click.command()
@click.argument('db_adress')
@click.argument('name')
def read(db_adress: str, name: str):
    hashed_username, password_for_db, db = authentication(db_adress)

    hashed_name = hashlib.sha3_256(name.encode()).hexdigest()

    decrypted_password = symmetric_decrypt_bytes(
        db[1][hashed_name][0],
        password_for_db
    ).decode()

    if db[1][hashed_name][1]:
        decrypted_description = symmetric_decrypt_bytes(
            db[1][hashed_name][1],
            password_for_db
        ).decode()
    else:
        decrypted_description = ''

    if decrypted_description:
        print(
            colorama.Fore.LIGHTGREEN_EX + 'password: ' + colorama.Fore.LIGHTBLUE_EX + decrypted_password,
            colorama.Fore.LIGHTGREEN_EX + 'description: ' + colorama.Fore.LIGHTBLUE_EX + decrypted_description
        )
    else:
        print(
            colorama.Fore.LIGHTGREEN_EX + 'password: ' + colorama.Fore.LIGHTBLUE_EX + decrypted_password
        )

#--- добавление команд в общую группу
commands.add_command(write)
commands.add_command(read)


#--- запуск команд по вызову
if __name__ == '__main__':
    get_cyphering_function()
    commands()