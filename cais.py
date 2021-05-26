import subprocess
import python_jwt as jwt, jwcrypto.jwk as jwk, datetime
import sqlite3
import os

from flask import Flask
from flask import request
from flask import render_template
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from hashlib import pbkdf2_hmac

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/aes', methods=['GET', 'POST'])
def aes_post(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='aes', title='AES', desc="Entre com a mensagem")
    else:
        key = get_random_bytes(24)
        message = request.form.get('output').encode("utf8")
        cipher = AES.new(key, AES.MODE_CCM)
        otp = cipher.encrypt(message)
        return render_template('input.html', otp=otp.hex(), title='AES')

@app.route('/ping', methods=['GET', 'POST'])
def ping(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='ping', title='Ping', desc="Entre com o IP")
    else:
        address = request.form.get('output')
        args = ["ping", "-c1", address]
        response = subprocess.Popen(args)
        response.wait()
        if response.poll() == 0:
            otp = "Host ativo!"
        else:
            otp = "Host inativo!"
    return render_template('input.html', otp=otp, title='Ping')

@app.route('/rsakey', methods=['GET', 'POST'])
def rsakey(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='rsakey', title='Gerar chave RSA', desc="Escreva \"GERAR\" para gerar uma nova chave RSA")
    elif request.method == 'POST' and str(request.form.get('output')) != "GERAR":
        return render_template('input.html', otp=otp, title='Gerar chave RSA', desc="Escreva \"GERAR\" para gerar uma nova chave RSA")
    else: 
        key = RSA.generate(2048)
        f = open('rsa-key.pem','wb')
        f.write(key.export_key('PEM'))
        f.close()
        f = open('rsa-key.pem','r')
        otp = f.read()
        f.close()
        return render_template('input.html', otp=otp, title='Gerar chave RSA')

@app.route('/gerachave', methods=['GET', 'POST'])
def gerasenha(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='gerachave', title='Gerador de chave', desc="Entre com a string para gerar a chave")
    else: 
        password = str.encode(request.form.get('output'))
        salt = os.urandom(32)
        otp = pbkdf2_hmac('sha256', password, salt, 100000)
    return render_template('input.html', otp=otp.hex(), title='Gerador de chave')

@app.route('/geratoken', methods=['GET', 'POST'])
def geratoken(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='geratoken', title='Gerador de tokens JWT', desc="Entre com o payload")
    else: 
        key = jwk.JWK.generate(kty='RSA', size=2048)
        payload = { 'payload': ''+str(request.form.get('output'))+''};
        token = jwt.generate_jwt(payload, key, 'PS256', datetime.timedelta(minutes=5))
        header, claims = jwt.verify_jwt(token, key, ['PS256'])
        otp = "TOKEN: {0} | CLAIMS: {2}".format(token, header, claims)
    return render_template('input.html', otp=otp, title='Gerador de tokens JWT')

@app.route('/consulta', methods=['GET', 'POST'])
def consulta(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='consulta', title='Exemplo de Consulta', desc="Procure por um telefone fornecendo o nome")
    else: 
        conn = sqlite3.connect('cais.db')
        query = "SELECT name, phone FROM users WHERE name = '"+str(request.form.get('output'))+"';"
        result = conn.execute(query)
        otp = result.fetchall()
        return render_template('input.html', otp=otp, title='Exemplo de Consulta')