from flask import Blueprint, request, jsonify, current_app
import fdb
import bcrypt
import re
import jwt
from datetime import datetime, timedelta
from functools import wraps

rotas = Blueprint('rotas', __name__)


# ===================== FUNÇÕES AUXILIARES =====================

def senha_segura(senha):
    """Validação de senha forte"""
    return bool(re.match(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*#?&])[A-Za-z\d@$!#%*?&]{8,}$', senha))


def validar_email(email):
    """Validação de formato de email"""
    padrao = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(padrao, email) is not None


def gerar_token(usuario):
    """Geração do token JWT"""
    payload = {
        "id": usuario["id"],
        "nome_usuario": usuario["nome_usuario"],
        "tipo_usuario": usuario["tipo_usuario"],
        "exp": datetime.utcnow() + timedelta(hours=4)
    }
    return jwt.encode(payload, current_app.config['SECRET_KEY'], algorithm="HS256")


def token_requerido(f):
    """Decorator para proteger rotas com token JWT"""

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


# ===================== ROTAS PÚBLICAS =====================

@rotas.route("/login", methods=["POST"])
def login():
    """Rota de autenticação de usuário"""
    dados = request.json
    email = dados.get("email")
    senha = dados.get("senha")

    if not email or not senha:
        return jsonify({"erro": "Email e senha são obrigatórios."}), 400

    if not validar_email(email):
        return jsonify({"erro": "Formato de email inválido."}), 400

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


@rotas.route("/cadastro", methods=["POST"])
def cadastrar_usuario():
    """Rota para cadastro de novos usuários (simples ou completo)"""
    dados = request.json
    nome_usuario = dados.get("nome_usuario")
    email = dados.get("email")
    senha = dados.get("senha")
    tipo_usuario = dados.get("tipo_usuario")
    data_vigencia = dados.get("data_vigencia")

    # Validações básicas
    if not nome_usuario or not email or not senha or not tipo_usuario or not data_vigencia:
        return jsonify(
            {"erro": "Nome de usuário, email, senha, tipo de usuário e data de vigência são obrigatórios."}), 400

    if not validar_email(email):
        return jsonify({"erro": "Formato de email inválido."}), 400

    if not senha_segura(senha):
        return jsonify({
            "erro": "A senha deve ter pelo menos 8 caracteres, incluir letras maiúsculas, minúsculas, números e símbolos."
        }), 400

    con = None
    cur = None
    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        # Verificar duplicidade
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
            "nome_completo", "curso", "data_nascimento", "codigo_aluno",
            "telefone", "sexo", "cpf", "cep", "endereco"
        ]
        dados_completos = all(dados.get(campo) for campo in campos_completos)

        if dados_completos:
            # Cadastro completo
            cur.execute("""
                INSERT INTO usuarios (
                    nome_usuario, senha, nome_completo, email, curso, data_nascimento, data_vigencia,
                    codigo_aluno, telefone, sexo, cpf, cep, endereco, tipo_usuario
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                nome_usuario, senha_hash, dados["nome_completo"], email, dados["curso"],
                dados["data_nascimento"], data_vigencia, dados["codigo_aluno"],
                dados["telefone"], dados["sexo"], dados["cpf"], dados["cep"],
                dados["endereco"], tipo_usuario
            ))
        else:
            # Cadastro simples
            cur.execute("""
                INSERT INTO usuarios (nome_usuario, senha, email, tipo_usuario, data_vigencia)
                VALUES (?, ?, ?, ?, ?)
            """, (nome_usuario, senha_hash, email, tipo_usuario, data_vigencia))

        con.commit()
        return jsonify({"mensagem": "Usuário cadastrado com sucesso!"}), 201

    except Exception as e:
        if con:
            con.rollback()
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500

    finally:
        if cur:
            cur.close()
        if con:
            con.close()


# ===================== ROTAS PROTEGIDAS =====================

@rotas.route("/usuario/me", methods=["GET"])
@token_requerido
def buscar_dados_usuario():
    """Buscar dados completos do usuário logado"""
    con = None
    cur = None
    try:
        usuario_id = request.usuario.get('id')

        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        cur.execute("""
            SELECT 
                id, nome_usuario, nome_completo, email, curso, data_nascimento, 
                data_vigencia, codigo_aluno, telefone, sexo, cpf, cep, endereco, 
                tipo_usuario
            FROM usuarios 
            WHERE id = ?
        """, (usuario_id,))

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({"erro": "Usuário não encontrado."}), 404

        colunas = [
            'id', 'nome_usuario', 'nome_completo', 'email', 'curso', 'data_nascimento',
            'data_vigencia', 'codigo_aluno', 'telefone', 'sexo', 'cpf', 'cep',
            'endereco', 'tipo_usuario'
        ]

        dados_usuario = {}
        for i, coluna in enumerate(colunas):
            if i < len(resultado) and resultado[i] is not None:
                valor = resultado[i]

                # Formatar datas
                if coluna in ['data_nascimento', 'data_vigencia']:
                    if hasattr(valor, 'isoformat'):
                        dados_usuario[coluna] = valor.isoformat()
                    elif hasattr(valor, 'strftime'):
                        dados_usuario[coluna] = valor.strftime('%Y-%m-%d')
                    else:
                        dados_usuario[coluna] = str(valor)
                else:
                    dados_usuario[coluna] = valor

        # Remover ID por segurança
        dados_usuario.pop('id', None)

        return jsonify({
            "mensagem": "Dados do usuário obtidos com sucesso!",
            "usuario": dados_usuario
        }), 200

    except Exception as e:
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500

    finally:
        if cur:
            cur.close()
        if con:
            con.close()


@rotas.route("/logout", methods=["POST"])
@token_requerido
def logout():
    """Rota de logout (invalidação do token no cliente)"""
    return jsonify({"mensagem": "Logout realizado com sucesso."}), 200


# ===================== ROTAS ADMINISTRATIVAS =====================

@rotas.route("/usuarios", methods=["GET"])
@token_requerido
def listar_usuarios():
    """Listar todos os usuários (apenas para administradores)"""
    # Verificar se é administrador
    if request.usuario.get('tipo_usuario') != 'administrador':
        return jsonify({"erro": "Acesso negado. Apenas administradores podem listar usuários."}), 403

    con = None
    cur = None
    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        cur.execute("""
            SELECT id, nome_usuario, nome_completo, email, tipo_usuario, data_vigencia
            FROM usuarios 
            ORDER BY nome_usuario
        """)

        resultados = cur.fetchall()
        usuarios = []

        for linha in resultados:
            usuario = {
                'id': linha[0],
                'nome_usuario': linha[1],
                'nome_completo': linha[2] if linha[2] else '',
                'email': linha[3],
                'tipo_usuario': linha[4],
                'data_vigencia': linha[5].strftime('%Y-%m-%d') if linha[5] else ''
            }
            usuarios.append(usuario)

        return jsonify({
            "mensagem": "Usuários listados com sucesso!",
            "usuarios": usuarios,
            "total": len(usuarios)
        }), 200

    except Exception as e:
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500

    finally:
        if cur:
            cur.close()
        if con:
            con.close()


@rotas.route("/usuarios/<int:usuario_id>", methods=["DELETE"])
@token_requerido
def deletar_usuario(usuario_id):
    """Deletar usuário (apenas para administradores)"""
    # Verificar se é administrador
    if request.usuario.get('tipo_usuario') != 'administrador':
        return jsonify({"erro": "Acesso negado. Apenas administradores podem deletar usuários."}), 403

    # Impedir auto-exclusão
    if request.usuario.get('id') == usuario_id:
        return jsonify({"erro": "Você não pode deletar sua própria conta."}), 400

    con = None
    cur = None
    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        # Verificar se usuário existe
        cur.execute("SELECT nome_usuario FROM usuarios WHERE id = ?", (usuario_id,))
        usuario_existe = cur.fetchone()

        if not usuario_existe:
            return jsonify({"erro": "Usuário não encontrado."}), 404

        # Deletar usuário
        cur.execute("DELETE FROM usuarios WHERE id = ?", (usuario_id,))
        con.commit()

        return jsonify({"mensagem": f"Usuário {usuario_existe[0]} deletado com sucesso!"}), 200

    except Exception as e:
        if con:
            con.rollback()
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500

    finally:
        if cur:
            cur.close()
        if con:
            con.close()
