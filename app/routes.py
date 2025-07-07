from flask import Blueprint, request, jsonify, current_app
import fdb
import bcrypt
import jwt
import datetime
from functools import wraps
import re

rotas = Blueprint('rotas', __name__)

SECRET_KEY = 'sua_chave_secreta'  # Use uma chave forte e guarde em local seguro

def senha_segura(senha):
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,}$', senha))

def gerar_token(usuario_id):
    payload = {
        'usuario_id': usuario_id,
        'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=2)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    return token

def token_obrigatorio(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            return jsonify({'erro': 'Token ausente!'}), 401
        token = auth_header.split(" ")[1]
        try:
            dados = jwt.decode(token, SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return jsonify({'erro': 'Token expirado!'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'erro': 'Token inválido!'}), 401
        return f(*args, **kwargs)
    return decorated

@rotas.route("/usuario", methods=["POST"])
def cadastrar_usuario():
    dados = request.json
    nome_usuario = dados.get("nome_usuario")
    email = dados.get("email")
    senha = dados.get("senha")
    tipo_usuario = dados.get("tipo_usuario", "aluno")

    if not nome_usuario or not email or not senha:
        return jsonify({"erro": "Nome de usuário, email e senha são obrigatórios."}), 400

    if not senha_segura(senha):
        return jsonify({"erro": "A senha deve ter pelo menos 8 caracteres, incluir letras maiúsculas, minúsculas, números e símbolos."}), 400

    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        cur.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,))
        if cur.fetchone():
            return jsonify({"erro": "Email já cadastrado."}), 409

        cur.execute("SELECT 1 FROM usuarios WHERE nome_usuario = ?", (nome_usuario,))
        if cur.fetchone():
            return jsonify({"erro": "Nome de usuário já cadastrado."}), 409

        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

        campos_completos = [
            "nome_completo", "curso", "data_nascimento", "data_vigencia", "codigo_aluno",
            "telefone", "sexo", "cpf", "cep", "endereco"
        ]
        dados_completos = all(dados.get(campo) for campo in campos_completos)

        if dados_completos:
            cur.execute("""
                INSERT INTO usuarios (
                    nome_usuario, senha, nome_completo, email, curso, data_nascimento, data_vigencia,
                    codigo_aluno, telefone, sexo, cpf, cep, endereco, tipo_usuario
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                nome_usuario, senha_hash, dados["nome_completo"], email, dados["curso"], dados["data_nascimento"],
                dados["data_vigencia"], dados["codigo_aluno"], dados["telefone"], dados["sexo"], dados["cpf"],
                dados["cep"], dados["endereco"], tipo_usuario
            ))
        else:
            cur.execute("""
                INSERT INTO usuarios (nome_usuario, senha, email, tipo_usuario)
                VALUES (?, ?, ?, ?)
            """, (nome_usuario, senha_hash, email, tipo_usuario))

        con.commit()
        return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201

    except Exception as e:
        return jsonify({"erro": str(e)}), 500

    finally:
        try:
            if cur:
                cur.close()
            if con:
                con.close()
        except:
            pass

@rotas.route("/login", methods=["POST"])
def login():
    dados = request.json
    email = dados.get("email")
    senha = dados.get("senha")

    if not email or not senha:
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400

    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        cur.execute("SELECT id, senha FROM usuarios WHERE email = ?", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"erro": "Usuário não encontrado."}), 404

        usuario_id, senha_hash = usuario

        if not bcrypt.checkpw(senha.encode(), senha_hash.encode()):
            return jsonify({"erro": "Senha incorreta."}), 401

        token = gerar_token(usuario_id)
        return jsonify({"token": token}), 200

    except Exception as e:
        return jsonify({"erro": str(e)}), 500

    finally:
        try:
            if cur:
                cur.close()
            if con:
                con.close()
        except:
            pass

@rotas.route("/protegido", methods=["GET"])
@token_obrigatorio
def rota_protegida():
    return jsonify({'mensagem': 'Acesso autorizado!'})
