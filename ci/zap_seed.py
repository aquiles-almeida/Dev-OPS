"""Authenticate before scanning protected endpoints with valid typed bodies."""
import json
import os
from pathlib import Path
import re
from urllib.parse import urlencode, urlsplit


def send(zap, target, method, path, body='', content_type=None, token=None):
    headers=[f'{method} {target}{path} HTTP/1.1',f'Host: {urlsplit(target).netloc}','Connection: close']
    if content_type:
        headers.append('Content-Type: '+content_type)
    if token:
        headers.append('Authorization: Bearer '+token)
    headers.append(f'Content-Length: {len(body.encode())}')
    messages=zap.core.send_request('\r\n'.join(headers)+'\r\n\r\n'+body,followredirects=False)
    if not isinstance(messages,list) or not messages:
        raise RuntimeError('ZAP did not record the seed request.')
    message=messages[0]
    status=int(message['responseHeader'].splitlines()[0].split()[1])
    return status,message.get('responseBody','')


def zap_started(zap, target):
    target=target.rstrip('/')
    parsed=urlsplit(target)
    if parsed.scheme!='http' or parsed.hostname!='127.0.0.1':
        raise ValueError('This hook accepts only the local test target.')
    coverage=[]
    status,_=send(zap,target,'GET','/admin/painel')
    if status!=403:
        raise RuntimeError('Anonymous administrative access must be denied.')
    coverage.append({'method':'GET','path':'/admin/painel','authenticated':False,'status':status})
    body=urlencode({'usuario':os.environ['GS_ZAP_USERNAME'],'senha':os.environ['GS_ZAP_PASSWORD']})
    status,response=send(zap,target,'POST','/login',body,'application/x-www-form-urlencoded')
    if status!=200:
        raise RuntimeError('Test authentication failed.')
    coverage.append({'method':'POST','path':'/login','authenticated':False,'status':status})
    token=json.loads(response)['token']
    zap.replacer.add_rule('GS authenticated scan',True,'REQ_HEADER',False,'Authorization',
                          'Bearer '+token,url=re.escape(target)+r'/.*')
    cases=[
        ('GET','/?nome=cidadao','',None,False,200),
        ('GET','/busca?q=certidao','',None,False,200),
        ('GET','/produto?id=1','',None,False,200),
        ('GET','/saudacao?nome=cidadao','',None,False,200),
        ('GET','/ir?url=/busca','',None,False,302),
        ('GET','/arquivo?nome=termos.txt','',None,False,200),
        ('GET','/calc?expr=2%2B2','',None,False,200),
        ('GET','/consulta-externa?url=http://127.0.0.1','',None,False,400),
        ('GET','/diagnostico?host=127.0.0.1','',None,True,200),
        ('GET','/admin/painel','',None,True,200),
        ('GET','/admin/relatorio?mes=01','',None,True,200),
        ('POST','/config','tema: claro','application/yaml',True,200),
        ('POST','/importar','{"itens":[{"id":1,"quantidade":2}]}','application/json',True,200),
        ('POST','/admin/nfe','<nfe><emitente>teste</emitente><valor>10</valor></nfe>','application/xml',True,200),
    ]
    for method,path,body,content_type,authenticated,expected in cases:
        status,_=send(zap,target,method,path,body,content_type,token if authenticated else None)
        coverage.append({'method':method,'path':path,'requires_authentication':authenticated,'authenticated':True,
                         'content_type':content_type,'status':status})
        if status!=expected:
            raise RuntimeError(f'Unexpected seed response: {method} {path}: {status}')
    Path(os.environ.get('GS_ZAP_COVERAGE_PATH','/zap/wrk/dast-coverage.json')).write_text(json.dumps({'authenticated_endpoints':6,'requests':coverage},indent=2)+'\n')
