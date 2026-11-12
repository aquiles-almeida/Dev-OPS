"""Autenticação JWT e análise defensiva de XML."""
import os
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

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
    if len(raiz)!=2 or {child.tag for child in raiz} != {'emitente','valor'}:
        raise ValueError('Campos de nota inválidos.')
    if raiz.attrib or any(child.attrib or len(child) for child in raiz):
        raise ValueError('Estrutura de nota inválida.')
    emitente=(raiz.findtext('emitente') or '').strip()
    if not 1 <= len(emitente) <= 120:
        raise ValueError('Emitente inválido.')
    try:
        valor=Decimal((raiz.findtext('valor') or '').strip())
    except InvalidOperation:
        raise ValueError('Valor de nota inválido.') from None
    if not valor.is_finite() or not Decimal('0') <= valor <= Decimal('1000000'):
        raise ValueError('Valor de nota fora do limite.')
    return {'emitente':emitente,'valor':str(valor)}
