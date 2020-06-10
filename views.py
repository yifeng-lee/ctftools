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
        return render_template('hash.html', tag=escape(tag))


from base64 import b16decode
from capstone import *

ARCH = {
    'ARM': CS_ARCH_ARM,
    'ARM64': CS_ARCH_ARM64,
    'MIPS': CS_ARCH_MIPS,
    'X86': CS_ARCH_X86,
    'PPC': CS_ARCH_PPC,
    'SPARC': CS_ARCH_SPARC
}

MODE = {
    'ARM': CS_MODE_ARM,
    'THUMB': CS_MODE_THUMB,
    'MCLASS': CS_MODE_MCLASS,
    'V8': CS_MODE_V8,
    'MICRO': CS_MODE_MICRO,
    'MIPS2': CS_MODE_MIPS2,
    'MIPS3': CS_MODE_MIPS3,
    'MIPS32R6': CS_MODE_MIPS32R6,
    'MIPS32': CS_MODE_MIPS32,
    'MIPS64': CS_MODE_MIPS64,
    '16': CS_MODE_16,
    '32': CS_MODE_32,
    '64': CS_MODE_64,
    'QPX': CS_MODE_QPX,
    'V9': CS_MODE_V9
}


@app.route('/disassembly', methods=['GET', 'POST'])
@login_required
def disassembly():

    if request.method == 'POST':
        base = request.form['base']
        arch = request.form['arch']
        mode = request.form['mode']
        tmp = src = request.form['src']
        src = src.replace(r'\x', '')
        src = src.strip(r'b')
        src = src.strip("'")

        try:
            src = b16decode(src)
        except Exception as e:
            return render_template('disassembly.html')

        try:
            if base.startswith('0x'):
                base = int(base, 16)
            else:
                base = int(base)
        except Exception as e:
            base = 0

        try:
            dest = ''
            md = Cs(ARCH[arch], MODE[mode])
            for i in md.disasm(src, base):
                dest += "0x%x:\t%s\t%s\n" % (i.address, i.mnemonic, i.op_str)
        except Exception as e:
            dest = e

        return render_template(
            'disassembly.html',
            src=tmp,
            dest=escape(dest) if dest != '' else 'Invalid arch or mode')
    return render_template('disassembly.html')


from Crypto.Cipher import AES, ARC4, Blowfish, DES, DES3, ARC2, XOR
import Padding

block = {
    'AES': AES,
    'DES': DES,
    'DES3': DES3,
    'RC4': ARC4,
    'Blowfish': Blowfish,
    'RC2': ARC2,
    'XOR': XOR
}
cipherMode = {
    'ECB': AES.MODE_ECB,
    'CBC': AES.MODE_CBC,
    'CFB': AES.MODE_CFB,
    'OFB': AES.MODE_OFB,
    'CTR': AES.MODE_CTR
}


@app.route('/decrypt/block/<tag>', methods=['GET', 'POST'])
@app.route('/encrypt/block/<tag>', methods=['GET', 'POST'])
def cipherBlock(tag):

    if tag not in block.keys():
        return redirect(url_for('index'))

    from base64 import b64encode, b64decode
    tmp, src, dest, key, iv = '', '', '', b'', b''

    if request.method == 'POST':
        tmp = src = request.form['src']
        key = request.form['key'].encode()
        iv = request.form['iv'].encode()
        mode = request.form['mode']
        padding = request.form['padding']
        c = block[str(tag)]

        try:
            if mode == 'ECB' or mode == 'CBC' or mode == 'CFB':
                src = Padding.appendPadding(src, c.block_size, padding)
            cipher = c.new(key, cipherMode[mode], iv)
            if 'encrypt' in request.url:
                dest = cipher.encrypt(src.encode())
                dest = b64encode(dest).decode()
            else:
                src = b64decode(src.encode())
                dest = cipher.decrypt(src).decode()
                dest = Padding.removePadding(dest)
        except Exception as e:
            dest = e

    if 'encrypt' in request.url:
        return render_template('cipherBlock.html',
                               tag=escape(tag.upper()),
                               flag='Encrypt',
                               src=escape(tmp),
                               dest=escape(dest),
                               key=escape(key.decode()),
                               iv=escape(iv.decode()))

    else:
        return render_template('cipherBlock.html',
                               tag=escape(tag.upper()),
                               flag='Decrypt',
                               src=escape(tmp),
                               dest=escape(dest),
                               key=escape(key.decode()),
                               iv=escape(iv.decode()))


stream = {'RC4': ARC4, 'XOR': XOR}


@app.route('/decrypt/stream/<tag>', methods=['GET', 'POST'])
@app.route('/encrypt/stream/<tag>', methods=['GET', 'POST'])
def cipherStream(tag):

    if tag not in block.keys():
        return redirect(url_for('index'))

    from base64 import b64encode, b64decode
    tmp, src, dest, key = '', '', '', b''

    if request.method == 'POST':
        tmp = src = request.form['src']
        key = request.form['key'].encode()
        c = stream[str(tag)]
        try:
            cipher = c.new(key)
            if 'encrypt' in request.url:
                dest = cipher.encrypt(src.encode())
                dest = b64encode(dest).decode()
            else:
                src = b64decode(src.encode())
                dest = cipher.decrypt(src).decode()
        except Exception as e:
            dest = e

    if 'encrypt' in request.url:
        return render_template('cipherStream.html',
                               tag=escape(tag.upper()),
                               flag='Encrypt',
                               src=escape(tmp),
                               dest=escape(dest),
                               key=escape(key.decode()))
    else:
        return render_template('cipherStream.html',
                               tag=escape(tag.upper()),
                               flag='Decrypt',
                               src=escape(tmp),
                               dest=escape(dest),
                               key=escape(key.decode()))
