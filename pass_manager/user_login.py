import sqlite3
import os
import re
import argon2
from dbConnection import Database
import cryptoHandler

db_instance = None

# Permite imprimir informacion para debugging en la terminal.
DEBUG = False

class login_auth():
    DIRECTORY = 'files'

    '''
    Crea la base de datos en DIRECTORY/users.db si no existe
    '''
    def __init__(self):
        filename = os.path.join(self.DIRECTORY, 'users.db')
        if not os.path.isfile(filename):
            if not os.path.exists(self.DIRECTORY):
                os.makedirs(self.DIRECTORY)
            self.createUserDB(filename)

    '''
    Recibe un nombre de usuario y contraseña para iniciar sesión.
    Busca la informacion del usuario en la db y obtiene la salt, 
    el agoritmo de cifrado utilizado por el usuario y su db cifrada.

    Deriva una clave secreta para el usuario e inicia una instancia de la 
    clase db_wrapper, la cual intenta descifrar la db utilizando la clave
    derivada.

    Retorna True si se pudo descifrar la base de datos.
    Retorna Falso en caso contrario.
    '''
    def tryLogin(self, username, passwd):
        global db_instance
        username = username
        with Database('users.db') as db:
            rows = db.getUserInfo(username)
            if rows is not None:
                salt = rows[1]
                cipher = rows[2]
                encrypted = rows[3]

                hash = argon2.low_level.hash_secret(str.encode(
                    passwd), salt, time_cost=500, memory_cost=1024, parallelism=2, hash_len=64, type=argon2.low_level.Type.ID)
                    
                derivated_key = hash.split(b'$')[-1][:32]

                if DEBUG:
                    print(f"DEBUG: Clave derivada es {derivated_key}")

                db_instance = cryptoHandler.db_wrapper(username, derivated_key, cipher, encrypted)
                if db_instance.valid:
                    return True
        return False

    '''
    Crea un nuevo usuario e inicia instancia de la clase db_wrapper

    Retorna una tupla (boolean, string), donde el primer elemento es True si
    se pudo crear el usuario, caso contrario, el segundo elemento informa el error.
    
    cipher: 0 = AES, 1 = ChaCha20
    '''
    def createUser(self, name, username, passwd, cipher):
        global db_instance
        username = username
        if self.existUser(username):
            return (False, 'User already exists!')
        if not self.isValidUsername(username):
            return (False, 'Username is invalid!')
        if not self.isStrongPasswd(passwd):
            return (False, 'Password is invalid!')

        # Generate argon2 hash
        salt = os.urandom(16)

        hash = argon2.low_level.hash_secret(str.encode(
            passwd), salt, time_cost=500, memory_cost=1024, parallelism=2, hash_len=64, type=argon2.low_level.Type.ID)

        derivated_key = hash.split(b'$')[-1][:32]

        if DEBUG:
            print(f"DEBUG: Clave derivada es {derivated_key}")

        with Database('users.db') as db:
            db.addUser(name, username, salt, cipher, "")

        db_instance = cryptoHandler.db_wrapper(username, derivated_key, cipher, "")

        return (True, '')

    def isValidUsername(self, user):
        length_error = len(user) < 6

        return not (length_error)


    """
    Comprueba que la contraseña elegida cumpla los requisitos mínimos.

    A password is considered strong if it has at least:
        8 characters length
        1 digit
        1 symbol
        1 uppercase letter
        1 lowercase letter
    """
    def isStrongPasswd(self, passwd):


        length_error = len(passwd) < 8
        digit_error = re.search(r"\d", passwd) is None
        uppercase_error = re.search(r"[A-Z]", passwd) is None
        lowercase_error = re.search(r"[a-z]", passwd) is None
        symbol_error = re.compile('^(?=.*[.@$!%*#?&])').search(passwd) is None

        return not (length_error or digit_error or uppercase_error or lowercase_error or symbol_error)

    def existUser(self, user_name):
        user_name = user_name
        with Database('users.db') as db:
            rows = db.getUserInfo(user_name)
        if rows:
            return True
        return False

    def getUserName(self, user_name):
        user_name = user_name
        with Database('users.db') as db:
            rows = db.getUserInfo(user_name)
        if rows:
            return rows[0]
        return None

    def createUserDB(self, filename):
        conn = sqlite3.connect(filename)
        c = conn.cursor()
        c.execute(
            '''CREATE TABLE users (name_surname TEXT, user_name TEXT, salt TEXT, cipher INT, encrypted TEXT)''')
        conn.commit()
        c.close()
        conn.close()