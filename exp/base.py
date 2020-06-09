import base64
import base58
import base91

b16table = '0123456789ABCDEF'
b32table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
b58table = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
b64table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
b85table = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
b91table = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,./:;<=>?@[]^_`{|}~"'


def b16encode(src, table):
    return base64.b16encode(src.encode()).decode().translate(
        str.maketrans(b16table, table))


def b32encode(src, table):
    return base64.b32encode(src.encode()).decode().translate(
        str.maketrans(b32table, table))


def b58encode(src, table):
    return base58.b58encode(src.encode()).decode().translate(
        str.maketrans(b58table, table))


def b64encode(src, table):
    return base64.b64encode(src.encode()).decode().translate(
        str.maketrans(b64table, table))


def b85encode(src, table):
    return base64.b85encode(src.encode()).decode().translate(
        str.maketrans(b85table, table))


def b91encode(src, table):
    return base91.encode(src.encode()).translate(str.maketrans(
        b91table, table))


def b16decode(src, table):
    dest = base64.b16decode(
        src.translate(str.maketrans(table, b16table)).encode())
    try:
        dest = dest.decode()
    except UnicodeDecodeError as identifier:
        pass
    return dest


def b32decode(src, table):
    dest = base64.b32decode(
        src.translate(str.maketrans(table, b32table)).encode())
    try:
        dest = dest.decode()
    except UnicodeDecodeError as identifier:
        pass
    return dest


def b58decode(src, table):
    dest = base58.b58decode(
        src.translate(str.maketrans(table, b58table)).encode())
    try:
        dest = dest.decode()
    except UnicodeDecodeError as identifier:
        pass
    return dest


def b64decode(src, table):
    dest = base64.b64decode(
        src.translate(str.maketrans(table, b64table)).encode())
    try:
        dest = dest.decode()
    except UnicodeDecodeError as identifier:
        pass
    return dest


def b85decode(src, table):
    dest = base64.b85decode(
        src.translate(str.maketrans(table, b85table)).encode())
    try:
        dest = dest.decode()
    except UnicodeDecodeError as identifier:
        pass
    return dest


def b91decode(src, table):
    dest = base91.decode(src.translate(str.maketrans(table, b91table)))
    try:
        dest = dest.decode()
    except UnicodeDecodeError as identifier:
        pass
    return dest