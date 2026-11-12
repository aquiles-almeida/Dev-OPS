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
8. `deploy`: depende explicitamente dos sete jobs, só executa em push de `main`
   e usa o ambiente protegido `producao`. Publica um pedido com o SHA256 do
   arquivo de imagem e o ID imutável da imagem já analisada. O agente local do
   WSL verifica o run, o commit, os sete gates, a liberação do job protegido e
   os digests dos artefatos, o digest canônico da configuração, as camadas e
   os parâmetros de execução. A verificação funciona com Docker clássico e
   containerd, que podem apresentar IDs internos diferentes. O agente executa
   o ID local imutável já conferido, implanta exatamente essa imagem e confirma o
   HTTP `/health` e o HEALTHCHECK do Docker. O job só passa após essa confirmação.

As actions são fixadas por SHA. O token tem somente leitura por padrão; apenas o
deploy recebe adicionalmente `deployments: read`. Os relatórios são publicados mesmo em falha por
`if: always()`, sem ignorar o resultado dos gates. O relatório de segredos do CI
é redigido para impedir exposição de credenciais em artefatos.

O ambiente `producao` exige aprovação manual configurada no GitHub. O DAST cria
uma conta efêmera, autentica e verifica seis endpoints protegidos com JSON,
YAML e XML válidos antes da varredura ativa. `dast-coverage.json` registra os
status, sem senha ou token. A aprovação do deploy e a confirmação da máquina
local são condições distintas e ambas são exigidas.

## Deploy na única instalação WSL

Depois que os sete gates passarem, aprove `producao` na execução e inicie o agente
para o run e o commit exatos, no PowerShell:

```powershell
wsl -d Ubuntu -u root -- python3 /opt/gs/esteira/ci/deploy_wsl.py --run ID_EXECUCAO --sha SHA_COMMIT
```

O agente usa a autenticação local já existente do GitHub CLI. Não precisa de
SSH de entrada nem de um runner permanente no computador. A imagem é baixada
como artefato da mesma execução; o job não reconstrói a imagem no deploy.
O destino é a porta 8232 no localhost e no IP real da interface WSL.
O banco persiste em `/opt/gs/deploy/data`; os segredos ficam em
`/opt/gs/deploy/app.env` e o acesso administrativo inicial em
`/opt/gs/deploy/acesso-local.txt`, ambos fora do Git e com acesso restrito.
Uma instância candidata é testada antes da troca; falha na subida restaura o
contêiner anterior. `deployment.json` registra commit, imagem e saúde, sem segredo.
O job reprova se não receber confirmação de saúde dentro do prazo.

Atualize regularmente digests, regras, ferramentas e dependências com revisão
dos novos relatórios. O corretor oficial ainda depende do envio do professor;
não há nota automática estimada neste repositório.
