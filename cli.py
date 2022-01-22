import click
import os
from typing import List, Dict, Union
import pickle
import hashlib
from Crypto.Cipher import AES
import colorama
import clipboard

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
@click.option('--username', prompt=True)
@click.option(
    "--user-password", prompt=True, hide_input=True
)
def write(db_adress: str, password: str, name: str, description: str, username: str, user_password):
    # пароль от базы данных это и есть ключ шифрования

    if os.path.exists(db_adress):
    
        hashed_username, password_for_db, db = authentication(db_adress, username, user_password)
        
        encrypted_password = symmetric_encrypt_bytes(password.encode(), password_for_db)


        # проверяем описание на пустоту, ведь если зашифровать его путой строкой, то может быть ошибка
        if description:
            encrypted_description = symmetric_encrypt_bytes(description.encode(), password_for_db)
        else:
            encrypted_description = b''


        # меняем в базе нужные параметры
        db[1][hashlib.sha3_256(name.encode()).hexdigest()] = [encrypted_password, encrypted_description]


        # записываем все в базу и дело с концом
        write_to_db(
            db_adress,
            db[0],
            db[1]
        )

        message_success('database writed')

    else:
        
        hashed_username, password_for_db, db = authentication_first_time(db_adress, username, user_password)

        encrypted_password = symmetric_encrypt_bytes(password.encode(), password_for_db)


        # проверяем описание на пустоту, ведь если зашифровать его путой строкой, то может быть ошибка
        if description:
            encrypted_description = symmetric_encrypt_bytes(description.encode(), password_for_db)
        else:
            encrypted_description = b''


        # меняем в базе нужные параметры
        db[1][hashlib.sha3_256(name.encode()).hexdigest()] = [encrypted_password, encrypted_description]


        # записываем все в базу и дело с концом
        write_to_db(
            db_adress,
            db[0],
            db[1]
        )

        message_success('database writed')


# команда чтения из базы одного пароля и вывода на экран
@click.command()
@click.argument('db_adress')
@click.argument('name')
@click.option('--hidden')
@click.option('--username', prompt=True)
@click.option(
    "--password", prompt=True, hide_input=True
)
def read(hidden, db_adress: str, name: str, username : str, password : str):

    # получаем некоторые данные и проверяем доступ
    hashed_username, password_for_db, db = authentication(db_adress, username, password)

    hashed_name = hashlib.sha3_256(name.encode()).hexdigest()


    # os.system('clear')

    # шифруем
    decrypted_password = symmetric_decrypt_bytes(
        db[1][hashed_name][0],
        password_for_db
    ).decode()


    # хитро расшифровываем описание
    if db[1][hashed_name][1]:
        decrypted_description = symmetric_decrypt_bytes(
            db[1][hashed_name][1],
            password_for_db
        ).decode()
    else:
        decrypted_description = ''

    if hidden != 'True':
        # красиво выводим
        if decrypted_description:
            print(
                colorama.Fore.LIGHTYELLOW_EX, 'password:\n', colorama.Fore.LIGHTMAGENTA_EX, decrypted_password,
                colorama.Fore.LIGHTYELLOW_EX, '\ndescription:\n', colorama.Fore.LIGHTMAGENTA_EX, decrypted_description
            )
        else:
            print(
                colorama.Fore.LIGHTGREEN_EX + 'password: ' + colorama.Fore.LIGHTBLUE_EX + decrypted_password
            )
        
        print('#' * 40)
    else:
        clipboard.copy(decrypted_password)


# команда для чтения из базы всех паролей
@click.command()
@click.argument('db_adress')
@click.option('--username', prompt=True)
@click.option(
    "--password", prompt=True, hide_input=True
)
def read_all(db_adress: str, username: str, password : str):

    hashed_username, password_for_db, db = authentication(db_adress, username, password)

    for password in db[1]:
        if not password == 'auth':
            # print(password, db[1][password])

            # шифруем
            decrypted_password = symmetric_decrypt_bytes(
                db[1][password][0],
                password_for_db
            ).decode()


            # хитро расшифровываем описание
            if db[1][password][1]:
                decrypted_description = symmetric_decrypt_bytes(
                    db[1][password][1],
                    password_for_db
                ).decode()
            else:
                decrypted_description = ''


            # красиво выводим
            if decrypted_description:
                print(
                    colorama.Fore.LIGHTYELLOW_EX, 'password:\n', colorama.Fore.LIGHTMAGENTA_EX, decrypted_password,
                    colorama.Fore.LIGHTYELLOW_EX, '\ndescription:\n', colorama.Fore.LIGHTMAGENTA_EX, decrypted_description
                )
            else:
                print(
                    colorama.Fore.LIGHTGREEN_EX + 'password: ' + colorama.Fore.LIGHTBLUE_EX + decrypted_password
                )
            
            print('#' * 40)

@click.command()
@click.argument('db_adress')
@click.argument('name')
@click.option('--username', prompt=True)
@click.option(
    "--password", prompt=True, hide_input=True
)
def remove(db_adress: str, name: str, username: str, password: str):
    
    hashed_username, password_for_db, db = authentication(db_adress, username, password)

    if not os.path.exists(db_adress):
        message_errors('database is not exists')
        return
    
    try:
        db[1].pop(
            hashlib.sha3_256(name.encode()).hexdigest()
        )
    except:
        message_errors('no password with this name')
        return 
    

    try:
        write_to_db(
            db_adress,
            db[0],
            db[1]
        )
    except Exception as exc:
        message_errors(str(exc))
        return
    

    message_success('password succesfully removed from the database')





#--- добавление команд в общую группу
commands.add_command(write)
commands.add_command(read)
commands.add_command(read_all)
commands.add_command(remove)


#--- запуск команд по вызову
if __name__ == '__main__':
    commands()
