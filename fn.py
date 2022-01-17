import os
from typing import List, Dict, Union
import pickle
import hashlib
from Crypto.Cipher import AES
import colorama


''' 
менять кодовое слово можно только перед созданием новой базы данных, иначе замена
приведет к утере изначального слова и утере возможности входа в базу данных и как следствие потере данных

кто понял тот понял
'''
KODE_WORD = 'never_existed'



# #--- получение настроек в виде словаря со всем нужным
# def get_settings() -> Dict:
    
#     settings = {
#         'database_path': None,
#         'cypher_algorythm': None
#     }

#     with open('settings.txt') as settings_file:
#         for line in settings_file.readlines():
#             if not ( line.startswith('#') or line.startswith(' ') ):
#                 if line.startswith('database_path'):
#                     settings['database_path'] = line[ line.index('[') + 1 : -2 ]
#                 if line.startswith('cypher_algorythm'):
#                     settings['cypher_algorythm'] = line[ line.index('[') + 1 : -2 ]
#                     if settings['cypher_algorythm'] == '':
#                         settings['cypher_algorythm'] = None


#     return settings


#----------------- чтение из базы данных / запись в базу данных


def write_to_db(adress: str, users: List, data: Dict):
    '''
    write to database your files
    '''
    with open(adress, 'wb') as file:
        pickle.dump(users, file)
        pickle.dump(data, file)

def read_db(adress : str) -> List:
    '''
    returns list of users and data dictionary in list
    [users: list, data: dict]
    '''
    try:
        with open(adress, 'rb') as file:
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


#--- всякое барахло для того чтобы войти и разблокировать бд

# красивый ввод имени пользователя
def get_username() -> str:
    # не знаю почему, но я хочу чтобы тут был светло-синий
    return input(
        colorama.Fore.LIGHTBLUE_EX + 'enter username : ' + colorama.Fore.LIGHTCYAN_EX
    )

# красивый ввод пароля пользователя и хеширование
def get_hashed_password() -> str:
    # ну а тут пусть будет светло-желтый

    # тут просто хешируем пароль сразу, ибо аче
    return hash_100(
        input(
            colorama.Fore.LIGHTBLUE_EX + 'enter the password : ' + colorama.Fore.LIGHTCYAN_EX
        )
    )

# функция для вывода зеленым текстом
def message_success(text):
    print(colorama.Fore.GREEN + str(text))

# функция для вывода сообщения красным цветом
def message_errors(text):
    print(  colorama.Fore.RED + str(text))

# функция для вывода сообщений желтым цветом
def message(text):
    print(colorama.Fore.YELLOW + str(text))


# вход в базу данных
'''
теоретически, расшифровать базу можно любым паролем, но от правильности пароля будет зависеть правильность расшифровки
то есть если расшифровывать неправильным паролем будет беспорядочная последовательность байт и следовательно нечитаемый текст

'''
def authentication(adress : str):
    
    db = read_db(adress)

    # получение данных для входа
    username, password = get_username(), get_hashed_password()
    
    # если результат от шифровки кодового слова хешем полученного пароля совпадает со
    # словом в начале файла (оно по идее зашифровано верным паролем) то мы проверяем правильность
    # имени пользователя и впускаем этого черта
    if symmetric_encrypt_bytes(KODE_WORD, password) == db[1]['auth'] and hashlib.sha3_256(username.encode()).hexdigest() in db[0]:
        message_success('authentication passed')
        return True
    return False
        

# вот это надо активировать если запускаем приложение первый раз, оно создаст и запишет данные для входа, по типу пароля и списка имен пользователей
# ну или создаем новую базу данных
def authentication_first_time(adress : str):
    
    # читаем базу данных, чтобы удостовериться в том, что мы ненароком не перезапишем уже существующуу базу
    # то есть просто проверяем базу на пустоту

    db = read_db(adress)

    if not len(db[1]) == 0:
        return
    
    
    message('new database process creation started')
    
    # получаем данные пользователя для последующего входа
    username, password = get_username(), get_hashed_password()

    message('now i will encrypt the database and write data')


    # шифрование кодового слова для последующей проверки
    encrypted_auth = symmetric_encrypt_bytes(KODE_WORD.encode(), password)

    write_to_db(
        [username],
        {
            'auth' : [encrypted_auth]
        }
    )

    message_success('database encrypted and successfully writed')
    

    
'''
структура данных в базе:

[список с именами пользователей],
{
    'auth' : зашифрованное кодовое слово # первая строчка уникальна

    хешированное имя пароля: [зашифрованное название пароля, сам пароль] # вся база хранится в виде таких строчек
    остальные пароли по тому же примеру
}
'''
