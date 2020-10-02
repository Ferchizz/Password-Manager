import sqlite3
import os
from dbConnection import Database

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.backends import default_backend

# Permite imprimir informacion para debugging en la terminal.
DEBUG = False

class db_wrapper():
    conn = None
    c = None
    valid = False

    '''
    Recibe la clave derivada y la db cifrada.

    Crea base de datos en memoria para cargar los datos luego de descifrarla.
    '''
    def __init__(self, username, derivated_key, cipher, db_encrypted):
        self.derivated_key = derivated_key
        self.username = username
        self.cipher = cipher

        # Creacion base de datos en memoria
        self.conn = sqlite3.connect(':memory:')
        self.c = self.conn.cursor()
        
        if db_encrypted != "":
            # desencriptar base de datos y cargar a memoria
            if DEBUG:
                print(
                    "DEBUG: Ya existe una base de datos, desencriptando y cargando a memoria")
            plaintext_database = self.decrypt(db_encrypted)
            if plaintext_database is not None:
                self.valid = True
                self.loadDatabase(plaintext_database)
            else:
                if DEBUG:
                    print("DEBUG: Contraseña incorrecta")
                self.close()
        else:
            # inicializar base de datos
            if DEBUG:
                print("DEBUG: No existe una base de datos, creando una")
            self.initUserTable()

    def close(self):
        self.c.close()
        self.conn.close()

    def initUserTable(self):
        self.c.execute(
            'CREATE TABLE accounts (id INTEGER PRIMARY KEY, title TEXT, url TEXT, login_name TEXT, password TEXT, comment TEXT)')
        self.conn.commit()
        self.encript_and_save()

    '''
    Recibe la base de datos descifrada en formato bytes, la cual consiste 
    de una coleccion de operaciones SQL que son ejecutadas para recrear 
    la base de datos que fue previamente inicializada en memoria.
    '''
    def loadDatabase(self, database):
        db = database.decode('UTF-8')
        operaciones = db.split('\n')
        for op in operaciones:
            if op not in ('BEGIN TRANSACTION;', 'COMMIT;'):
                self.c.execute(op)
                self.conn.commit()

    '''
    Obtiene un volcado de la base de datos en memoria y se lo encripta 
    utilizando el algoritmo de cifrado elegido por el usuario. 

    Se contatena parametros necesarios utilizados por los algoritmos.
    '''
    def encript_and_save(self):
        database = "\n".join(self.conn.iterdump())
        database = str.encode(database)

        # 0 = AES, 1= ChaCha20
        if self.cipher == 0:
            iv, ciphertext, tag = self.encryptAES(database, str.encode(self.username))

            # Store encrypted db and append IV + tag
            with Database('users.db') as db:
                db.updateEncrypted(self.username, ciphertext + iv + tag)
        else:
            nonce, ciphertext = self.encryptChaCha20(
                database, str.encode(self.username))

            # Store encrypted db and append nonce
            with Database('users.db') as db:
                db.updateEncrypted(self.username, ciphertext + nonce)

    def decrypt(self, db_encrypted):
        if self.cipher == 0:
            return self.decryptAES(db_encrypted)
        else:
            return self.decryptChaCha20(db_encrypted)

    def decryptChaCha20(self, db_encrypted):

        length = len(db_encrypted)

        ct = db_encrypted[:length - 12]

        # nonce es de 12 bytes
        nonce = db_encrypted[length - 12:]

        # Construct an ChaCha20Poly1305 Cipher object with the given key and a nonce.
        chacha = ChaCha20Poly1305(self.derivated_key)

        plaintext = None
        try:
            # Decrypt the cyphertext and get the associated plaintext.
            plaintext = chacha.decrypt(nonce, ct, str.encode(self.username))
        except:
            pass

        return plaintext

    def encryptChaCha20(self, plaintext, associated_data):
        # Generate a random 96-bit nonce.
        nonce = os.urandom(12)

        # Construct an ChaCha20Poly1305 Cipher object with the given key and a randomly generated nonce.
        chacha = ChaCha20Poly1305(self.derivated_key)

        # Encrypt the plaintext and get the associated ciphertext.
        ct = chacha.encrypt(nonce, plaintext, associated_data)

        return (nonce, ct)

    def encryptAES(self, plaintext, associated_data):
        # Generate a random 96-bit IV.
        iv = os.urandom(12)

        # Construct an AES-GCM Cipher object with the given key and a randomly generated IV.
        encryptor = Cipher(
            algorithms.AES(self.derivated_key),
            modes.GCM(iv),
            backend=default_backend()
        ).encryptor()

        # associated_data will be authenticated but not encrypted, it must also be passed in on decryption.
        encryptor.authenticate_additional_data(associated_data)

        # Encrypt the plaintext and get the associated ciphertext.
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()

        return (iv, ciphertext, encryptor.tag)

    def decryptAES(self, db_encrypted):

        length = len(db_encrypted)

        ciphertext = db_encrypted[:length - 28]

        # iv es de 12 bytes
        iv = db_encrypted[length - 28:length - 16]

        # tag es de 16 bytes
        tag = db_encrypted[length - 16:]

        # Construct a Cipher object, with the key, iv, and additionally the GCM tag used for authenticating the message.
        decryptor = Cipher(
            algorithms.AES(self.derivated_key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()

        # We put associated_data back in or the tag will fail to verify when we finalize the decryptor.
        decryptor.authenticate_additional_data(str.encode(self.username))

        plaintext_database = None
        try:
            # Decryption gets us the authenticated plaintext.
            plaintext_database = decryptor.update(
                ciphertext) + decryptor.finalize()
        except:
            pass

        return plaintext_database

    def addAccount(self, title, url, login_name, passwd, comment):
        input = (title, url, login_name, passwd, comment,)
        self.c.execute('INSERT INTO accounts VALUES (NULL,?,?,?,?,?)', input)
        self.conn.commit()
        if DEBUG:
            print(f"DEBUG: Entrada agregada: {input}")
        self.encript_and_save()

    def removeAccount(self, id):
        input = (id,)
        self.c.execute('DELETE FROM accounts WHERE id = ? ', input)
        self.conn.commit()
        if DEBUG:
            print(f"DEBUG: Entrada con id = {id} eliminada")
        self.encript_and_save()

    def getAllAccounts(self):
        try:
            self.c.execute('SELECT * FROM accounts')
        except sqlite3.OperationalError:
            return None
        return self.c.fetchall()

    def debug_info(self):
        with Database('users.db') as db:
            rows = db.getUserInfo(self.username)
            encrypted = rows[3]
            
        length = len(encrypted)

        if self.cipher == 0:
            ciphertext = encrypted[:length - 28]

            # tag es de 12 bytes
            iv = encrypted[length - 28:length - 16]

            # tag es de 16 bytes
            tag = encrypted[length - 16:]

            print(
                f"\nArchivo encriptado:\n{encrypted}\n\nBase de dato encriptada:\n{ciphertext}\n\niv:\n{iv}\n\ntag:\n{tag}\n\n")
        else:
            ciphertext = encrypted[:length - 12]

            nonce = encrypted[length - 12:]

            print(
                f"\nArchivo encriptado:\n{encrypted}\n\nBase de dato encriptada:\n{ciphertext}\n\nNonce:\n{nonce}\n\n")
