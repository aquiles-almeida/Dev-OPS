"""Regressões das vulnerabilidades demonstradas no ambiente original."""
import importlib
import secrets

import jwt
import pytest
from werkzeug.security import generate_password_hash


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv('APP_SECRET', secrets.token_hex(32))
    monkeypatch.setenv('LOJA_DB', str(tmp_path/'market.db'))
    monkeypatch.setenv('ADMIN_USERNAME', 'test-operator')
    password = secrets.token_urlsafe(24)
    monkeypatch.setenv('ADMIN_PASSWORD_HASH', generate_password_hash(password))
    module = importlib.import_module('app')
    app = module.create_app()
    app.config['TESTING'] = True
    result = app.test_client()
    result.test_password = password
    return result


def token(client):
    response = client.post('/login', data={'usuario':'test-operator','senha':client.test_password})
    assert response.status_code == 200
    return {'Authorization':'Bearer ' + response.json['token']}


def test_health_and_product(client):
    assert client.get('/health').json == {'status':'ok'}
    assert client.get('/produto?id=1').json['produto']['id'] == 1


@pytest.mark.parametrize('path', ['/?nome=<script>alert(1)</script>', '/busca?q=<script>alert(1)</script>', '/saudacao?nome={{7*7}}<script>alert(1)</script>'])
def test_xss_and_template_injection(client, path):
    response = client.get(path)
    assert b'<script>' not in response.data
    assert b'49' not in response.data


def test_sql_injection(client):
    assert client.get('/produto', query_string={'id':"1' OR 1=1--"}).status_code == 400
    assert client.post('/login',data={'usuario':"' OR 1=1--",'senha':'invalid'}).status_code == 401


@pytest.mark.parametrize('path', ['/admin/painel','/admin/relatorio?mes=01','/diagnostico?host=127.0.0.1'])
def test_admin_requires_authentication(client, path):
    assert client.get(path).status_code == 403


def test_signed_jwt_and_forged_token(client):
    assert client.get('/admin/painel', headers=token(client)).status_code == 200
    forged = jwt.encode({'sub':'attacker','papel':'admin'},secrets.token_hex(32),algorithm='HS256')
    assert client.get('/admin/painel',headers={'Authorization':'Bearer '+forged}).status_code == 403


def test_path_and_redirect_and_ssrf(client):
    assert client.get('/arquivo?nome=../../etc/passwd').status_code == 404
    assert client.get('/ir?url=https://example.org').status_code == 400
    assert client.get('/ir?url=//example.org').status_code == 400
    assert client.get('/consulta-externa?url=http://127.0.0.1').status_code == 400


@pytest.mark.parametrize('expression', ["__import__('os').getcwd()",'9**9999999','1/0','[1]*999999','1000001'])
def test_calculator_rejects_code_and_resource_exhaustion(client, expression):
    assert client.get('/calc',query_string={'expr':expression}).status_code == 400


def test_calculator(client):
    assert client.get('/calc?expr=2%2B2').json['resultado'] == 4


def test_parsers(client):
    headers=token(client)
    assert client.post('/importar',json={'itens':[{'id':1,'quantidade':2}]},headers=headers).status_code == 200
    assert client.post('/importar',data=b'not-json',headers=headers).status_code == 400
    assert client.post('/config',data='!!python/object/apply:os.system [id]',headers=headers).status_code == 400
    xml=b'<!DOCTYPE nfe [<!ENTITY x SYSTEM "file:///etc/passwd">]><nfe><emitente>&x;</emitente></nfe>'
    assert client.post('/admin/nfe',data=xml,headers=headers).status_code == 400


def test_login_rate_limit(client):
    for _ in range(10):
        assert client.post('/login', data={'usuario':'unknown','senha':'invalid'}).status_code == 401
    assert client.post('/login').status_code == 429


def test_security_headers(client):
    response=client.get('/')
    assert response.headers['X-Content-Type-Options']=='nosniff'
    assert "frame-ancestors 'none'" in response.headers['Content-Security-Policy']
    cookie=response.headers['Set-Cookie']
    assert 'HttpOnly' in cookie and 'Secure' in cookie and 'SameSite=Strict' in cookie


def test_worker_rejects_untrusted_data():
    from worker.tarefas import processar, miniatura
    assert processar('{"tipo":"emitir_nfe"}') == 'emitir_nfe'
    with pytest.raises(ValueError):
        processar('{"tipo":"execute"}')
    with pytest.raises(ValueError):
        miniatura('../../etc/passwd')
