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
        encrypted_description = symmetric_encrypt_bytes(description, password_for_db)
    else:
        encrypted_description = b''

    db[1][hashlib.sha3_256(name.encode()).hexdigest()] = [encrypted_password, encrypted_description]

    write_to_db(
        db_adress,
        db[0],
        db[1]
    )

    message_success('database writed')

#--- добавление команд в общую группу
commands.add_command(write)


#--- запуск команд по вызову
if __name__ == '__main__':
    commands()