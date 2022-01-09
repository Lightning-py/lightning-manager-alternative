'''

для примера приведены функции, уже использующиеся в программе
функции можно записывать в любом виде и они не обязательно должны быть лямдами
как шифровать - воля ваша...

'''



# добавление нескольких пробелов в конец байтовой строки чтобы ее длина была кратна 16
transform_password = lambda password_str : password_str + b' ' * (16 - len(password_str) % 16)


# шифрование обычной строки симметричным шифром
symmetric_encrypt_str = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).encrypt(message.encode())


# шифрование байтовой строки симметричным шифром
symmetric_encrypt_bytes = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).encrypt(message)



# дешифрование обычной строки симметричным шифром
symmetric_decrypt_str = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).decrypt(message.encode())

# дешифрование байтовой строки симметричным шифром
symmetric_decrypt_bytes = lambda message, key : AES.new(transform_password(key.encode())[  :16], AES.MODE_CTR, nonce=b'0' * 8).decrypt(message)
