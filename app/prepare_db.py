import sqlite3

db = sqlite3.connect('users.db')
db.execute('DROP TABLE IF EXISTS users')
db.execute('CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT, password TEXT, otp_secret TEXT)')
db.execute('DROP TABLE IF EXISTS comments')
db.execute('CREATE TABLE comments (id INTEGER PRIMARY KEY, comment TEXT)')
db.execute('INSERT INTO users (username,password,otp_secret) VALUES ("user1","simple","")')
db.execute('INSERT INTO users (username,password,otp_secret) VALUES ("user2","hardtoguess","")')
db.execute('INSERT INTO users (username,password,otp_secret) VALUES ("user3","C0mpl3xP@ssw0rd","")')
db.commit()
db.close()
