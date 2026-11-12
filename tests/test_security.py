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


@pytest.mark.parametrize('identifier',['9223372036854775808','-1','0','9'*5000])
def test_product_identifier_limits(client, identifier):
    assert client.get('/produto',query_string={'id':identifier}).status_code == 400


@pytest.mark.parametrize('changes',[{'exp':1},{'iss':'other'},{'aud':'other'},{'papel':'usuario'}])
def test_invalid_jwt_claims_and_user_role(client, monkeypatch, changes):
    import os
    valid = token(client)['Authorization'][7:]
    claims = jwt.decode(valid,os.environ['APP_SECRET'],algorithms=['HS256'],audience='ctmarket-api',issuer='ctmarket')
    invalid = jwt.encode({**claims,**changes},os.environ['APP_SECRET'],algorithm='HS256')
    assert client.get('/admin/painel',headers={'Authorization':'Bearer '+invalid}).status_code == 403


def test_worker_does_not_follow_output_symlink(tmp_path):
    from PIL import Image
    from worker.tarefas import miniatura
    root=tmp_path/'allowed'
    root.mkdir()
    marker=tmp_path/'outside'
    marker.write_bytes(b'audit-marker')
    Image.new('RGB',(2,2)).save(root/'input.png')
    (root/'miniatura.png').symlink_to(marker)
    result=miniatura('input.png',base=str(root))
    assert marker.read_bytes()==b'audit-marker'
    assert not (root/'miniatura.png').is_symlink()
    with Image.open(result) as image:
        assert image.size==(2,2)


def test_zap_hook_authenticates_all_typed_endpoints(client, monkeypatch, tmp_path):
    import json
    from types import SimpleNamespace
    from urllib.parse import urlsplit
    from ci import zap_seed
    state={}
    def add_rule(_description,_enabled,_kind,_regex,_header,replacement,**_kwargs):
        state['Authorization']=replacement
    def send_request(raw,**_kwargs):
        head,body=raw.split('\r\n\r\n',1)
        first,*lines=head.split('\r\n')
        method,url,_version=first.split(' ',2)
        headers=dict(line.split(': ',1) for line in lines)
        headers.update(state)
        response=client.open(urlsplit(url).path+('?' + urlsplit(url).query if urlsplit(url).query else ''),
                             method=method,headers=headers,data=body)
        return [{'responseHeader':'HTTP/1.1 '+response.status+'\r\n',
                 'responseBody':response.get_data(as_text=True)}]
    monkeypatch.setenv('GS_ZAP_USERNAME','test-operator')
    monkeypatch.setenv('GS_ZAP_PASSWORD',client.test_password)
    destination=tmp_path/'coverage.json'
    monkeypatch.setenv('GS_ZAP_COVERAGE_PATH',str(destination))
    zap=SimpleNamespace(core=SimpleNamespace(send_request=send_request),
                        replacer=SimpleNamespace(add_rule=add_rule))
    zap_seed.zap_started(zap,'http://127.0.0.1:8231')
    report=json.loads(destination.read_text())
    protected=[r for r in report['requests'] if r.get('requires_authentication')]
    assert len(protected)==6 and all(r['status']==200 for r in protected)
    assert {r['content_type'] for r in protected if r['method']=='POST'}=={'application/json','application/yaml','application/xml'}


@pytest.mark.parametrize('document',[
    '<nfe><emitente>teste</emitente></nfe>',
    '<nfe><emitente>teste</emitente><valor>nfe</valor></nfe>',
    '<nfe><emitente>teste</emitente><valor>NaN</valor></nfe>',
    '<nfe><emitente>teste</emitente><valor>Infinity</valor></nfe>',
    '<nfe><emitente>teste</emitente><valor>-1</valor></nfe>',
    '<nfe><emitente>teste</emitente><valor>1000001</valor></nfe>',
    '<nfe><emitente>teste</emitente><valor>1</valor><valor>2</valor></nfe>',
])
def test_nfe_requires_schema_and_numeric_value(client,document):
    assert client.post('/admin/nfe',data=document,headers=token(client)).status_code==400


def test_nfe_ack_does_not_reflect_user_input(client):
    response=client.post('/admin/nfe',data='<nfe><emitente>qa-name</emitente><valor>10</valor></nfe>',headers=token(client))
    assert response.json=={'status':'validada'}
