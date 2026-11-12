"""Consultas parametrizadas e senhas com hashes fornecidos pelo operador."""
import os
import sqlite3
from threading import Lock

_lock = Lock()


def conectar():
    con = sqlite3.connect(os.environ.get('LOJA_DB', '/tmp/ct-market.db'))
    con.row_factory = sqlite3.Row
    with _lock:
        con.execute('CREATE TABLE IF NOT EXISTS produtos (id INTEGER PRIMARY KEY, nome TEXT, preco REAL)')
        con.execute('CREATE TABLE IF NOT EXISTS usuarios (id INTEGER PRIMARY KEY, usuario TEXT UNIQUE, senha TEXT, papel TEXT)')
        con.execute('CREATE TABLE IF NOT EXISTS pedidos (id INTEGER PRIMARY KEY, mes TEXT, total REAL)')
        con.executemany('INSERT OR IGNORE INTO produtos (id,nome,preco) VALUES (?,?,?)',
                        [(1,'Segunda via de documento',19.9),(2,'Agendamento prioritário',9.5),(3,'Certidão digital',35.0)])
        username, hashed = os.environ.get('ADMIN_USERNAME'), os.environ.get('ADMIN_PASSWORD_HASH')
        if username and hashed and hashed.startswith(('scrypt:', 'pbkdf2:')):
            con.execute('INSERT OR IGNORE INTO usuarios (usuario,senha,papel) VALUES (?,?,?)',(username, hashed, 'admin'))
        con.commit()
    return con


def produto_por_id(pid):
    try:
        product_id = int(pid)
    except (ValueError, TypeError):
        raise ValueError('Identificador inválido.') from None
    if not 1 <= product_id <= 9223372036854775807:
        raise ValueError('Identificador fora do intervalo permitido.')
    con = conectar()
    try:
        row = con.execute('SELECT id,nome,preco FROM produtos WHERE id=?', (product_id,)).fetchone()
        return {'produto': dict(row) if row else None}
    finally:
        con.close()


def usuario_por_nome(username):
    con = conectar()
    try:
        row = con.execute('SELECT usuario,senha,papel FROM usuarios WHERE usuario=?', (username,)).fetchone()
        return dict(row) if row else None
    finally:
        con.close()
