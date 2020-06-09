from flask import render_template, request, url_for, redirect, flash, escape
from flask_login import login_user, login_required, logout_user, current_user
from app import app, db
from models import User


@app.route('/', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
# @login_required
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        print(request.form['dest'])
        if not username or not password:
            flash('Invalid input.')
            return redirect(url_for('login'))

        user = User.query.first()

        if username == user.username and user.validate_password(password):
            login_user(user)
            flash('Login success.')
            return redirect(url_for('index'))

        flash('Invalid username or password.')
        return redirect(url_for('login'))

    return render_template('login.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Goodbye.')
    return redirect(url_for('index'))


from exp.base import *


@app.route('/encode/<tag>', methods=['GET', 'POST'])
def encode(tag):
    if tag == 'Base16encode':
        fun, table = b16encode, b16table
    elif tag == 'Base32encode':
        fun, table = b32encode, b32table
    elif tag == 'Base58encode':
        fun, table = b58encode, b58table
    elif tag == 'Base64encode':
        fun, table = b64encode, b64table
    elif tag == 'Base85encode':
        fun, table = b85encode, b85table
    elif tag == 'Base91encode':
        fun, table = b91encode, b91table
    else:
        return redirect(url_for('index'))

    if request.method == 'POST':
        src = request.form['src']
        table = request.form['table']
        dest = fun(src, table)
        return render_template('encode.html',
                               src=escape(src),
                               dest=escape(dest),
                               table=escape(table),
                               tag=escape(tag))
    else:
        return render_template('encode.html', table=table, tag=escape(tag))


@app.route('/decode/<tag>', methods=['GET', 'POST'])
def decode(tag):
    if tag == 'Base16decode':
        fun, table = b16decode, b16table
    elif tag == 'Base32decode':
        fun, table = b32decode, b32table
    elif tag == 'Base58decode':
        fun, table = b58decode, b58table
    elif tag == 'Base64decode':
        fun, table = b64decode, b64table
    elif tag == 'Baseb85decode':
        fun, table = b85decode, b85table
    elif tag == 'Base91decode':
        fun, table = b91decode, b91table
    else:
        return redirect(url_for('index'))

    if request.method == 'POST':
        src = request.form['src']
        table = request.form['table']
        dest = fun(src, table)
        return render_template('decode.html',
                               src=escape(src),
                               dest=escape(dest),
                               table=escape(table),
                               tag=escape(tag))
    else:
        return render_template('decode.html', table=table, tag=escape(tag))


from hashlib import *
@app.route('/hash/<tag>', methods=['GET', 'POST'])
def hash(tag):
    if tag == 'MD5':
        fun, table = b16decode, b16table
    elif tag == 'SHA1':
        fun, table = b32decode, b32table
    elif tag == 'SHA224':
        fun, table = b58decode, b58table
    elif tag == 'SHA256':
        fun, table = b64decode, b64table
    elif tag == 'SHA384':
        fun, table = b85decode, b85table
    elif tag == 'SHA512':
        fun, table = b91decode, b91table
    else:
        return redirect(url_for('index'))

    if request.method == 'POST':
        src = request.form['src']
        dest = md5(src.encode()).hexdigest()
        return render_template('hash.html',
                               src=escape(src),
                               dest=escape(dest),
                               tag=escape(tag))
    else:
        return render_template('hash.html',  tag=escape(tag))
