# Citizen Tech Market - DevSecOps

**Aquiles Fonseca de Almeida - RM 564289 - 2TDCPF**

Entrega da Global Solution, executada no Ubuntu do WSL 2. O código original e os
relatórios da análise permanecem em `/opt/gs/app` e `/opt/gs/reports`. Este
repositório tem histórico novo e contém somente a cópia corrigida e a esteira.
Não contém os segredos plantados, a chave privada ou os relatórios com seus valores.

## Executar localmente

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt -r worker/requirements.txt
export APP_SECRET="$(openssl rand -hex 48)"
.venv/bin/gunicorn --bind 127.0.0.1:8231 --workers 1 --threads 4 app:app
```

`APP_SECRET` deve ser aleatório e ter pelo menos 32 caracteres. Não há senha ou
usuário administrador padrão. Para habilitar um operador, configure
`ADMIN_USERNAME` e `ADMIN_PASSWORD_HASH` com um hash scrypt ou PBKDF2 produzido
por `werkzeug.security.generate_password_hash`. Não versione arquivos de ambiente.
Em produção, termine HTTPS no proxy e forneça um banco persistente em `LOJA_DB`.
Os cookies exigem HTTPS. O limite de login é local ao processo; múltiplas réplicas
exigem um limitador compartilhado. A integração externa está desativada até existir
um provedor confiável configurado; a API deixou de aceitar URLs arbitrárias.

## Correções e testes

Consultas SQL parametrizadas; templates com escape; remoção de execução Python e
shell controlada por entrada; JSON com validação no lugar de pickle; YAML seguro;
XML com defusedxml; JWT assinado com expiração, emissor e audiência; autorização
administrativa; caminhos e redirects limitados; hash de senha moderno; cabeçalhos
de segurança; dependências atualizadas; contêiner sem root e imagem-base por digest.
`/importar` agora recebe JSON: `{"itens":[{"id":1,"quantidade":2}]}`.

```bash
python -m pip install pytest==9.2.0
python -m pytest -q
```

Os testes verificam comportamento funcional e rejeição de SQL injection, XSS,
SSTI, path traversal, open redirect, SSRF, JWT forjado, desserialização insegura,
XML com entidades e expressões de custo excessivo.

## Oito jobs e bloqueios

1. `build`: instala os dois manifestos e verifica compilação.
2. `sast`: Semgrep, incluindo regras Python, Flask, OWASP e regras locais.
3. `segredos`: Gitleaks em todo o histórico e na árvore atual.
4. `sca`: Trivy nos dois manifestos; HIGH e CRITICAL reprovam.
5. `testes`: pytest, com relatório JUnit.
6. `imagem`: constrói a imagem, analisa Dockerfile e vulnerabilidades HIGH/CRITICAL.
7. `dast`: ZAP full scan ativo; risco alto reprova. O código 2 do ZAP significa
   alertas configurados como WARN e é interpretado com a severidade do JSON; erros
   de ferramenta ou relatórios ausentes reprovam.
8. `deploy`: depende explicitamente dos sete jobs, só executa em push de `main`,
   usa o ambiente protegido `producao` e publica a imagem aprovada no GHCR. Este
   passo publica a imagem para implantação; não cria hospedagem externa do Flask.

As actions são fixadas por SHA. O token tem somente leitura por padrão; apenas o
deploy recebe `packages: write`. Os relatórios são publicados mesmo em falha por
`if: always()`, sem ignorar o resultado dos gates. O relatório de segredos do CI
é redigido para impedir exposição de credenciais em artefatos.

O ambiente `producao` exige aprovação manual configurada no GitHub. Uma aprovação
é necessária para publicar uma imagem; uma execução verde dos gates não publica
automaticamente sem essa aprovação. Atualize regularmente digests, regras,
ferramentas e dependências com revisão dos novos relatórios.
