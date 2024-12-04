from flask import Flask, g, render_template, request, redirect, url_for, session
import sqlite3
import pyotp
import pyqrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'secret'

def get_db():
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect('users.db')
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

@app.route('/', methods=['GET', 'POST'])
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('SELECT comment FROM comments')
    comments = cur.fetchall()
    if request.method == 'POST':
        c = request.form.get('comment','')
        db.execute('INSERT INTO comments (comment) VALUES (?)',[c])
        db.commit()
        return redirect(url_for('index'))
    return render_template('index.html', username=session['username'], comments=comments)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username','')
        password = request.form.get('password','')
        db = get_db()
        cur = db.execute('SELECT id,password,otp_secret FROM users WHERE username=?',[username])
        row = cur.fetchone()
        if row and row[1] == password:
            if row[2]:
                session['pre_otp_user'] = username
                return redirect(url_for('otp'))
            session['username'] = username
            return redirect(url_for('index'))
    return render_template('login.html')

@app.route('/otp', methods=['GET', 'POST'])
def otp():
    if 'pre_otp_user' not in session:
        return redirect(url_for('login'))
    if request.method == 'POST':
        db = get_db()
        cur = db.execute('SELECT otp_secret FROM users WHERE username=?',[session['pre_otp_user']])
        row = cur.fetchone()
        if row and pyotp.TOTP(row[0]).verify(request.form.get('otp','')):
            session['username'] = session.pop('pre_otp_user')
            return redirect(url_for('index'))
    return render_template('otp.html')

@app.route('/enroll', methods=['GET','POST'])
def enroll():
    if 'username' not in session:
        return redirect(url_for('login'))
    db = get_db()
    cur = db.execute('SELECT otp_secret FROM users WHERE username=?',[session['username']])
    row = cur.fetchone()
    if not row[0]:
        secret = pyotp.random_base32()
        db.execute('UPDATE users SET otp_secret=? WHERE username=?',[secret, session['username']])
        db.commit()
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(session['username'], issuer_name="MyFlaskApp")
        qr = pyqrcode.create(totp_uri)
        buffer = io.BytesIO()
        qr.png(buffer, scale=5)
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        return render_template('enroll_otp.html', secret=secret, qr_code_data=qr_code_data)
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True)
