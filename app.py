"""Citizen Tech Market, versão para a esteira de DevSecOps do RM 564289."""
import ipaddress
import os
import secrets
import time
from collections import defaultdict, deque
from functools import wraps
from threading import Lock

from flask import Flask, abort, jsonify, redirect, render_template, request, send_from_directory, session
from werkzeug.security import check_password_hash

from loja import admin, db, util
from loja.relatorio_5dbc982k import gerar_relatorio


def create_app():
    app = Flask(__name__)
    secret = os.environ.get('APP_SECRET', '')
    if len(secret) < 32:
        raise RuntimeError('Configure APP_SECRET com pelo menos 32 caracteres aleatórios.')
    app.config.update(SECRET_KEY=secret, MAX_CONTENT_LENGTH=64 * 1024,
                      SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SECURE=True,
                      SESSION_COOKIE_SAMESITE='Strict', TESTING=False)
    attempts = defaultdict(deque)
    attempt_lock = Lock()

    def authenticated(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            claims = admin.dados_do_token(request.headers.get('Authorization', ''))
            if claims.get('papel') != 'admin':
                abort(403)
            return view(*args, **kwargs)
        return wrapped

    @app.after_request
    def headers(response):
        response.headers.update({
            'Content-Security-Policy': "default-src 'none'; style-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
            'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY',
            'Referrer-Policy': 'no-referrer', 'Cache-Control': 'no-store',
            'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        })
        return response

    @app.errorhandler(ValueError)
    def invalid(_error):
        return jsonify(erro='Entrada inválida.'), 400

    @app.route('/health')
    def health():
        return jsonify(status='ok')

    @app.route('/')
    def index():
        session['visitor'] = secrets.token_urlsafe(24)
        return render_template('index.html', nome=request.args.get('nome', 'cidadão')[:120])

    @app.route('/busca')
    def busca():
        return render_template('busca.html', q=request.args.get('q', '')[:200])

    @app.route('/produto')
    def produto():
        return jsonify(db.produto_por_id(request.args.get('id', '1')))

    @app.route('/login', methods=['POST'])
    def login():
        # Limite local de laboratório; implantações com réplicas devem usar Redis.
        key = request.remote_addr or 'local'
        with attempt_lock:
            now = time.monotonic()
            recent = attempts[key]
            while recent and recent[0] < now - 60:
                recent.popleft()
            if len(recent) >= 10:
                return jsonify(erro='Tente novamente mais tarde.'), 429
            recent.append(now)
        username = request.form.get('usuario', '')[:100]
        password = request.form.get('senha', '')[:256]
        user = db.usuario_por_nome(username)
        if user and check_password_hash(user['senha'], password):
            return jsonify(autenticado=True, token=admin.emitir_token(user['usuario'], user['papel']))
        return jsonify(autenticado=False), 401

    @app.route('/saudacao')
    def saudacao():
        return render_template('saudacao.html', nome=request.args.get('nome', 'cidadão')[:120])

    @app.route('/ir')
    def ir():
        destination = request.args.get('url', '/')
        if destination not in {'/', '/busca', '/produto', '/saudacao'}:
            abort(400)
        return redirect(destination)

    @app.route('/arquivo')
    def arquivo():
        return send_from_directory(os.path.join(app.root_path, 'arquivos'), request.args.get('nome', 'termos.txt'), mimetype='text/plain')

    @app.route('/diagnostico')
    @authenticated
    def diagnostico():
        host = str(ipaddress.ip_address(request.args.get('host', '127.0.0.1')))
        if not ipaddress.ip_address(host).is_loopback:
            abort(400)
        return jsonify(host=host, status='endereço local válido')

    @app.route('/calc')
    def calc():
        return jsonify(resultado=util.calcular(request.args.get('expr', '1+1')))

    @app.route('/importar', methods=['POST'])
    @authenticated
    def importar():
        return jsonify(util.importar_carrinho(request.get_data()))

    @app.route('/config', methods=['POST'])
    @authenticated
    def config():
        return jsonify(util.ler_config(request.get_data(as_text=True)))

    @app.route('/consulta-externa')
    def consulta_externa():
        # O destino passa a ser configuração do servidor, sem proxy de URL do usuário.
        if 'url' in request.args:
            abort(400)
        return jsonify(erro='Integração externa não configurada neste laboratório.'), 503

    @app.route('/admin/painel')
    @authenticated
    def painel():
        return jsonify(status='autorizado')

    @app.route('/admin/nfe', methods=['POST'])
    @authenticated
    def nfe():
        admin.ler_nfe(request.get_data())
        return jsonify(status='validada')

    @app.route('/admin/relatorio')
    @authenticated
    def relatorio():
        return jsonify(gerar_relatorio(request.args.get('mes', '01')))

    return app


app = create_app()
