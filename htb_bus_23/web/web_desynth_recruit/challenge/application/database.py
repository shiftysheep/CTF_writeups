from application.util import create_JWT
from flask_mysqldb import MySQL
import MySQLdb.cursors

mysql = MySQL()

def query(query, args=(), one=False):
    cursor = mysql.connection.cursor()
    cursor.execute(query, args)
    rv = [dict((cursor.description[idx][0], value)
        for idx, value in enumerate(row)) for row in cursor.fetchall()]
    return (rv[0] if rv else None) if one else rv


def login_user_db(username, password):
    user = query('SELECT username FROM users WHERE username = %s AND password = %s', (username, password,), one=True)
    
    if user:
        token = create_JWT(user['username'])
        return token
    else:
        return False

def register_user_db(username, password):
    check_user = query('SELECT username FROM users WHERE username = %s', (username,), one=True)

    if not check_user:
        query('INSERT INTO users(username, password) VALUES(%s, %s)', (username, password,))
        mysql.connection.commit()
        
        return True
    
    return False

def get_profile_db(uid):
    return query('SELECT * from users WHERE id=%s', (uid,), one=True)

def get_all_profiles_db():
    return query('SELECT * from users WHERE is_public=1')

def get_user_db(username):
    return query('SELECT * from users where username=%s', (username,), one=True)

def update_profile_db(username, data):
    data['bots'] = f'{data["bots"]}'

    query('''UPDATE users SET
        full_name=%s,
        issn=%s,
        qualification=%s, 
        bio=%s, 
        iexp=%s, 
        meta_desc=%s, 
        is_public=1, 
        meta_keywords=%s, 
        bots=%s
        WHERE username=%s''', 
        (
            data['full_name'],
            data['issn'],
            data['qualification'],
            data['bio'],
            data['iexp'],
            data['meta_desc'],
            data['meta_keywords'],
            data['bots'],
            username
        ))
    
    mysql.connection.commit()

    return True

def update_ipc_db(username):
    query('UPDATE users SET ipc_submitted=1 WHERE username=%s', (username,))

    mysql.connection.commit()

def get_all_users_db():
    return query('SELECT * from users')