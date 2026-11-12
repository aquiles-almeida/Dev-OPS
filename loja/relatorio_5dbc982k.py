"""Relatórios com parâmetros vinculados."""
from loja import db


def gerar_relatorio(mes):
    if mes not in {f'{n:02}' for n in range(1,13)}:
        raise ValueError('Mês inválido.')
    con = db.conectar()
    try:
        row = con.execute('SELECT COUNT(*),COALESCE(SUM(total),0) FROM pedidos WHERE mes=?', (mes,)).fetchone()
        return {'mes':mes, 'pedidos':row[0], 'total':row[1]}
    finally:
        con.close()
