import subprocess
import python_jwt as jwt, jwcrypto.jwk as jwk
import sqlite3

from flask import Flask
from flask import request
from flask import render_template
from Cryptodome.Cipher import DES3
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA
from hashlib import pbkdf2_hmac

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/3des', methods=['GET', 'POST'])
def des3(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='3des', title='3DES', desc="Entre com a mensagem")
    else:
        key = DES3.adjust_key_parity(get_random_bytes(24))
        cipher = DES3.new(key, DES3.MODE_CFB)
        plaintext = str.encode(request.form.get('output'))
        otp = cipher.iv + cipher.encrypt(plaintext)
        return render_template('input.html', otp=otp.hex(), title='3DES')

@app.route('/ping', methods=['GET', 'POST'])
def ping(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='ping', title='Ping', desc="Entre com o IP")
    else:
        address = request.form.get('output')
        cmd = "ping -c 1 %s" % address
        response = subprocess.Popen(cmd, shell=True)
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
        key = RSA.generate(1024)
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
        otp = pbkdf2_hmac('sha256', password, b'D8VxSmTZt2E2YV454mkqAY5e', 100000)
        return render_template('input.html', otp=otp.hex(), title='Gerador de chave')

@app.route('/geratoken', methods=['GET', 'POST'])
def geratoken(otp=None):
    if request.method == 'GET':
        return render_template('input.html', otp=otp, path='geratoken', title='Gerador de tokens JWT', desc="Entre com o payload")
    else: 
        payload = { 'payload': ''+str(request.form.get('output'))+''};
        key = jwk.JWK.generate(kty='RSA', size=1024)
        token = jwt.generate_jwt(payload, key, 'PS256')
        otp = jwt.process_jwt(token)
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