"""Populate ZAP's history with every application endpoint before active scan."""
from urllib.parse import urlsplit


def zap_started(zap, target):
    target=target.rstrip('/')
    authority=urlsplit(target).netloc
    seeds=[('GET','/?nome=cidadao',''),('GET','/busca?q=certidao',''),('GET','/produto?id=1',''),
           ('GET','/saudacao?nome=cidadao',''),('GET','/ir?url=/busca',''),('GET','/arquivo?nome=termos.txt',''),
           ('GET','/diagnostico?host=127.0.0.1',''),('GET','/calc?expr=2%2B2',''),
           ('GET','/consulta-externa?url=http://127.0.0.1',''),('GET','/admin/painel',''),
           ('GET','/admin/relatorio?mes=01',''),('POST','/login','usuario=invalid&senha=invalid'),
           ('POST','/config','tema=claro'),('POST','/importar','itens=[]'),('POST','/admin/nfe','documento=teste')]
    for method,path,body in seeds:
        raw=f'{method} {target}{path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n'
        if method=='POST':
            raw+=f'Content-Type: application/x-www-form-urlencoded\r\nContent-Length: {len(body)}\r\n'
        zap.core.send_request(raw+'\r\n'+body, followredirects=False)
