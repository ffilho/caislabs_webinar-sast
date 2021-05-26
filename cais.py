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
from flask_wtf.csrf import CSRFProtect
from hashlib import pbkdf2_hmac

app = Flask(__name__)
SECRET_KEY = os.urandom(32)
app.config['SECRET_KEY'] = SECRET_KEY
csrf = CSRFProtect()
csrf.init_app(app)

getpage = 'input.html'
otp=None

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/aes', methods=['GET'])
def aes():
    
    return render_template(getpage, otp=otp, path='aes', title='AES', desc="Entre com a mensagem")

@app.route('/aes', methods=['POST'])
def aes_post():
    key = get_random_bytes(24)
    message = request.form.get('output').encode("utf8")
    cipher = AES.new(key, AES.MODE_CCM)
    otp = cipher.encrypt(message)
    return render_template(getpage, otp=otp.hex(), title='AES')

@app.route('/ping', methods=['GET'])
def ping():
    return render_template(getpage, otp=otp, path='ping', title='Ping', desc="Entre com o IP")

@app.route('/ping', methods=['POST'])
def ping_post():
    address = request.form.get('output')
    args = ["ping", "-c1", address]
    response = subprocess.Popen(args)
    response.wait()
    if response.poll() == 0:
        otp = "Host ativo!"
    else:
        otp = "Host inativo!"
    return render_template(getpage, otp=otp, title='Ping')

@app.route('/rsakey', methods=['GET'])
def rsakey():
    return render_template(getpage, otp=otp, path='rsakey', title='Gerar chave RSA', desc="Escreva \"GERAR\" para gerar uma nova chave RSA")

@app.route('/rsakey', methods=['POST'])
def rsakey_post():
    otp=None
    title='Gerar chave RSA'
    if str(request.form.get('output')) != "GERAR":
        return render_template(getpage, otp=otp, title=title, desc="Escreva \"GERAR\" para gerar uma nova chave RSA")
    else: 
        key = RSA.generate(2048)
        f = open('rsa-key.pem','wb')
        f.write(key.export_key('PEM'))
        f.close()
        f = open('rsa-key.pem','r')
        otp = f.read()
        f.close()
        return render_template(getpage, otp=otp, title=title)

@app.route('/gerachave', methods=['GET'])
def gerasenha():
    return render_template(getpage, otp=otp, path='gerachave', title='Gerador de chave', desc="Entre com a string para gerar a chave")

@app.route('/gerachave', methods=['POST'])
def gerasenha_post():
    password = str.encode(request.form.get('output'))
    salt = os.urandom(32)
    otp = pbkdf2_hmac('sha256', password, salt, 100000)
    return render_template(getpage, otp=otp.hex(), title='Gerador de chave')

@app.route('/geratoken', methods=['GET'])
def geratoken():
    return render_template(getpage, otp=otp, path='geratoken', title='Gerador de tokens JWT', desc="Entre com o payload")

@app.route('/geratoken', methods=['POST'])
def geratoken_post():
    key = jwk.JWK.generate(kty='RSA', size=2048)
    payload = { 'payload': ''+str(request.form.get('output'))+''};
    token = jwt.generate_jwt(payload, key, 'PS256', datetime.timedelta(minutes=5))
    header, claims = jwt.verify_jwt(token, key, ['PS256'])
    otp = "TOKEN: {0} | CLAIMS: {2}".format(token, header, claims)
    return render_template(getpage, otp=otp, title='Gerador de tokens JWT')

@app.route('/consulta', methods=['GET'])
def consulta():
    return render_template(getpage, otp=otp, path='consulta', title='Exemplo de Consulta', desc="Procure por um telefone fornecendo o nome")

@app.route('/consulta', methods=['POST'])
def consulta_post():
    conn = sqlite3.connect('cais.db')
    query = "SELECT name, phone FROM users WHERE name = '"+str(request.form.get('output'))+"';"
    result = conn.execute(query)
    otp = result.fetchall()
    return render_template(getpage, otp=otp, title='Exemplo de Consulta')