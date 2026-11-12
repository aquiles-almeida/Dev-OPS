"""Autenticação JWT e análise defensiva de XML."""
import os
from datetime import datetime, timedelta, timezone

import jwt
from defusedxml import ElementTree
from defusedxml.common import DefusedXmlException


def emitir_token(usuario, papel):
    now = datetime.now(timezone.utc)
    return jwt.encode({'sub': usuario, 'papel': papel, 'iat': now, 'exp': now + timedelta(minutes=15),
                       'iss': 'ctmarket', 'aud': 'ctmarket-api'}, os.environ['APP_SECRET'], algorithm='HS256')


def dados_do_token(cabecalho):
    if not cabecalho.startswith('Bearer '):
        return {}
    try:
        return jwt.decode(cabecalho[7:], os.environ['APP_SECRET'], algorithms=['HS256'],
                          issuer='ctmarket', audience='ctmarket-api', options={'require': ['sub','iat','exp','iss','aud']})
    except jwt.InvalidTokenError:
        return {}


def ler_nfe(dados):
    if len(dados) > 16384:
        raise ValueError('Documento muito grande.')
    try:
        raiz = ElementTree.fromstring(dados)
    except (DefusedXmlException, ElementTree.ParseError):
        raise ValueError('XML inválido.') from None
    if raiz.tag != 'nfe':
        raise ValueError('Formato de nota inválido.')
    return {'emitente': raiz.findtext('emitente'), 'valor': raiz.findtext('valor')}
