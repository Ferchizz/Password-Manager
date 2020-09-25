import sqlite3
import os


class Database():
    DIRECTORY = 'files'

    def __init__(self, db_name):
        filename = os.path.join(self.DIRECTORY, db_name)
        self.conn = sqlite3.connect(filename)
        self.c = self.conn.cursor()

    def close(self):
        if self.conn:
            self.conn.commit()
            self.c.close()
            self.conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def getUserInfo(self, user_name):
        input = (user_name,)
        try:
            self.c.execute(
                'SELECT name_surname, salt, cipher, encrypted FROM users WHERE user_name=?', input)
        except sqlite3.OperationalError:
            return None
        return self.c.fetchone()

    def updateEncrypted(self, user_name, encrypted):
        input = (encrypted, user_name)
        self.c.execute(
            'UPDATE users SET encrypted=? WHERE user_name=?', input)

    def addUser(self, name, user_name, salt, cipher, encrypted):
        input = (name, user_name, salt, cipher, encrypted)
        self.c.execute("INSERT INTO users VALUES (?,?,?,?,?)", input)
