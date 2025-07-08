from flask import Blueprint, request, jsonify, current_app
import fdb
import bcrypt
import re
import jwt
from datetime import datetime, timedelta
from functools import wraps

rotas = Blueprint('rotas', __name__)

# Validação de senha segura
def senha_segura(senha):
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,}$', senha))

# Geração do token
def gerar_token(usuario):
    payload = {
        "id": usuario["id"],
        "nome_usuario": usuario["nome_usuario"],
        "tipo_usuario": usuario["tipo_usuario"],
        "exp": datetime.utcnow() + timedelta(hours=4)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")

# Decorator para proteger rotas com token JWT
def token_requerido(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({"erro": "Token ausente."}), 401

        try:
            if token.startswith("Bearer "):
                token = token.split(" ")[1]
            dados = jwt.decode(token, current_app.config['SECRET_KEY'], algorithms=["HS256"])
            request.usuario = dados
        except jwt.ExpiredSignatureError:
            return jsonify({"erro": "Token expirado."}), 401
        except jwt.InvalidTokenError:
            return jsonify({"erro": "Token inválido."}), 401

        return f(*args, **kwargs)
    return decorator

# Rota de login
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

        cur.execute("SELECT id, nome_usuario, senha, tipo_usuario FROM usuarios WHERE email = ?", (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"erro": "Email ou senha inválidos."}), 401

        id_usuario, nome_usuario, senha_hash_db, tipo_usuario = usuario

        if not bcrypt.checkpw(senha.encode(), senha_hash_db.encode()):
            return jsonify({"erro": "Email ou senha inválidos."}), 401

        token = gerar_token({
            "id": id_usuario,
            "nome_usuario": nome_usuario,
            "tipo_usuario": tipo_usuario
        })

        return jsonify({
            "mensagem": "Login realizado com sucesso!",
            "usuario": {
                "id": id_usuario,
                "nome_usuario": nome_usuario,
                "email": email,
                "tipo_usuario": tipo_usuario
            },
            "token": token
        }), 200

    except Exception as e:
        return jsonify({"erro": str(e)}), 500

    finally:
        try:
            if cur: cur.close()
            if con: con.close()
        except:
            pass

# Rota de cadastro
@rotas.route("/cadastro", methods=["POST"])
def cadastrar_usuario():
    dados = request.json
    nome_usuario = dados.get("nome_usuario")
    email = dados.get("email")
    senha = dados.get("senha")
    tipo_usuario = dados.get("tipo_usuario")

    # Validação dos campos obrigatórios
    if not nome_usuario or not email or not senha or not tipo_usuario:
        return jsonify({"erro": "Nome de usuário, email, senha e tipo de usuário são obrigatórios."}), 400

    # Validação de senha forte
    if not senha_segura(senha):
        return jsonify({
            "erro": "A senha deve ter pelo menos 8 caracteres, incluir letras maiúsculas, minúsculas, números e símbolos."
        }), 400

    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        # Verificar duplicidade de email e nome_usuario
        cur.execute("SELECT 1 FROM usuarios WHERE email = ?", (email,))
        if cur.fetchone():
            return jsonify({"erro": "Email já cadastrado."}), 409

        cur.execute("SELECT 1 FROM usuarios WHERE nome_usuario = ?", (nome_usuario,))
        if cur.fetchone():
            return jsonify({"erro": "Nome de usuário já cadastrado."}), 409

        # Criptografar senha
        senha_hash = bcrypt.hashpw(senha.encode(), bcrypt.gensalt()).decode()

        # Verificar se é cadastro completo
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
            if cur: cur.close()
            if con: con.close()
        except:
            pass

# Rota protegida de exemplo
@rotas.route("/usuario/perfil", methods=["GET"])
@token_requerido
def perfil_usuario():
    return jsonify({
        "mensagem": "Perfil acessado com sucesso!",
        "usuario": request.usuario
    }), 200


#Rota de logout
@rotas.route("/logout", methods=["POST"])
@token_requerido
def logout():
    return jsonify({"mensagem": "Logout realizado com sucesso."}), 200