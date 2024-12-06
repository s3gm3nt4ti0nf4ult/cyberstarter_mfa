from flask import Flask, g, render_template, request, redirect, url_for, session, send_file, flash
import sqlite3
import pyotp
import pyqrcode
import io
import base64

app = Flask(__name__)
app.secret_key = 'secret1234@'
app.config['SESSION_COOKIE_NAME'] = 'cookie'

def get_db():
    if not hasattr(g, 'db'):
        g.db = sqlite3.connect('users.db')
    return g.db

@app.teardown_appcontext
def close_db(exception):
    db = getattr(g, 'db', None)
    if db is not None:
        db.close()

def login_required(route_func):
    def wrapper(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('login'))
        return route_func(*args, **kwargs)
    wrapper.__name__ = route_func.__name__
    return wrapper

@app.route('/', methods=['GET', 'POST'])
@login_required
def index():
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
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '').strip()
        db = get_db()
        cur = db.execute('SELECT id, password, otp_secret FROM users WHERE username = ?', [username])
        row = cur.fetchone()

        if row and row[1] == password:
            if row[2]:
                # User has OTP enabled; proceed to OTP verification
                session['pre_otp_user'] = username
                response = redirect(url_for('otp'))
            else:
                # User does not have OTP; set the session and redirect to index
                session['username'] = username
                response = redirect(url_for('index'))

            # **Extract and Print the Session Token**
            session_cookie = response.headers.get('Set-Cookie')
            if session_cookie:
                # Assuming the cookie name is 'cookie' as per your configuration
                cookie_name = app.config.get('SESSION_COOKIE_NAME', 'cookie')
                # Split the 'Set-Cookie' header to parse individual cookie attributes
                cookie_parts = session_cookie.split(';')
                for part in cookie_parts:
                    part = part.strip()
                    if part.startswith(f"{cookie_name}="):
                        # Extract the cookie value
                        cookie_value = part[len(f"{cookie_name}="):]
                        print(f"Session Token Set for user '{username}': {cookie_value}")
                        break
            else:
                print(f"No 'Set-Cookie' header found in the response for user '{username}'.")

            return response
        else:
            flash("Bad username or password. Please try again.")

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
        else:
            flash("bad otp")
    return render_template('otp.html')

@app.route('/enroll', methods=['GET','POST'])
@login_required
def enroll():
    if request.method == 'POST':
        db = get_db()
        secret = session.get('pending_otp_secret')
        if secret:
            submitted_otp = request.form.get('otp','')
            if pyotp.TOTP(secret).verify(submitted_otp):
                db.execute('UPDATE users SET otp_secret=? WHERE username=?',[secret, session['username']])
                db.commit()
                session.pop('pending_otp_secret',None)
                session.pop('pending_totp_uri',None)
                return redirect(url_for('index'))
            else:
                flash("bad otp")
    else:
        secret = pyotp.random_base32()
        session['pending_otp_secret'] = secret
        totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(session['username'], issuer_name="MyFlaskApp")
        session['pending_totp_uri'] = totp_uri
    # Generate QR code data on GET or after form failure
    qr_data = None
    if 'pending_totp_uri' in session:
        qr = pyqrcode.create(session['pending_totp_uri'])
        buffer = io.BytesIO()
        qr.png(buffer, scale=5)
        qr_code_data = base64.b64encode(buffer.getvalue()).decode()
        qr_data = "data:image/png;base64," + qr_code_data
    return render_template('enroll_otp.html', qr_data=qr_data)

@app.route('/download_qr')
@login_required
def download_qr():
    if 'pending_totp_uri' not in session:
        return redirect(url_for('enroll'))
    qr = pyqrcode.create(session['pending_totp_uri'])
    buffer = io.BytesIO()
    qr.png(buffer, scale=5)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name="otp_qr.png", mimetype='image/png')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)