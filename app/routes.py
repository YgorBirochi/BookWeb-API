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
    """Rota de login"""
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

        cur.execute("SELECT id, nome_usuario, senha, tipo_usuario, data_vigencia, status FROM usuarios WHERE email = ?",
                    (email,))
        usuario = cur.fetchone()

        if not usuario:
            return jsonify({"erro": "Email ou senha inválidos."}), 401

        id_usuario, nome_usuario, senha_hash_db, tipo_usuario, data_vigencia, status = usuario

        # Verificar se o usuário está inativo ou suspenso
        if status == "inativo":
            return jsonify({"erro": "Conta desativada. Entre em contato com o administrador."}), 401

        if status == "suspenso":
            return jsonify({"erro": "Conta suspensa. Entre em contato com o administrador."}), 401

        # Verificar se a senha está correta primeiro
        if not bcrypt.checkpw(senha.encode(), senha_hash_db.encode()):
            return jsonify({"erro": "Email ou senha inválidos."}), 401

        aviso_expiracao = None
        dias_restantes = None

        if data_vigencia:
            data_vigencia_obj = data_vigencia
            if hasattr(data_vigencia, 'date'):
                data_vigencia_obj = data_vigencia.date()

            data_atual = datetime.now().date()
            dias_restantes = (data_vigencia_obj - data_atual).days

            # Se já expirou
            if dias_restantes <= 0:
                cur.execute("UPDATE usuarios SET status = 'inativo' WHERE id = ?", (id_usuario,))
                con.commit()

                return jsonify({
                    "erro": "Sua conta expirou em {}. Entre em contato com o bibliotecário.".format(
                        data_vigencia_obj.strftime('%d/%m/%Y')
                    )
                }), 401

            # Se expira em 3 dias ou menos (mas ainda não expirou)
            elif 1 <= dias_restantes <= 3:
                if dias_restantes == 1:
                    aviso_expiracao = "ATENÇÃO: Sua conta será desativada AMANHÃ! Procure o bibliotecário urgentemente para renovar seu acesso."
                else:
                    aviso_expiracao = f"AVISO: Sua conta será desativada em {dias_restantes} dias ({data_vigencia_obj.strftime('%d/%m/%Y')}). Procure o bibliotecário para aumentar o prazo."

        token = gerar_token({
            "id": id_usuario,
            "nome_usuario": nome_usuario,
            "tipo_usuario": tipo_usuario
        })

        resposta = {
            "mensagem": "Login realizado com sucesso!",
            "usuario": {
                "id": id_usuario,
                "nome_usuario": nome_usuario,
                "email": email,
                "tipo_usuario": tipo_usuario
            },
            "token": token
        }
        if aviso_expiracao:
            resposta["aviso_expiracao"] = {
                "mensagem": aviso_expiracao,
                "dias_restantes": dias_restantes,
                "data_expiracao": data_vigencia_obj.strftime('%d/%m/%Y')
            }

        return jsonify(resposta), 200

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
    """Buscar dados completos do usuário"""
    con = None
    cur = None
    try:
        usuario_id = request.usuario.get('id')

        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        # IMPORTANTE: Manter a ordem das colunas consistente
        cur.execute("""
            SELECT 
                id, nome_usuario, nome_completo, email, curso, data_nascimento, 
                data_vigencia, codigo_aluno, telefone, sexo, cpf, cep, endereco, 
                tipo_usuario, biografia
            FROM usuarios 
            WHERE id = ?
        """, (usuario_id,))

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({"erro": "Usuário não encontrado."}), 404

        # ORDEM DEVE SER EXATAMENTE A MESMA DA QUERY
        colunas = [
            'id', 'nome_usuario', 'nome_completo', 'email', 'curso', 'data_nascimento',
            'data_vigencia', 'codigo_aluno', 'telefone', 'sexo', 'cpf', 'cep',
            'endereco', 'tipo_usuario', 'biografia'
        ]

        dados_usuario = {}
        for i, coluna in enumerate(colunas):
            if i < len(resultado):
                valor = resultado[i]

                # Só adicionar se não for None
                if valor is not None:
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
                # Se for None, não adicionar ao dicionário (campo vazio)

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


@rotas.route("/usuarios/<int:usuario_id>", methods=["PUT"])
@token_requerido
def atualizar_usuario(usuario_id):
    """Atualizar dados do usuário (seções separadas)"""
    dados = request.json
    secao = dados.get("secao")  # conta, usuario, curso, contato

    # Verificar se o usuário pode editar
    usuario_logado_id = request.usuario.get('id')
    tipo_usuario_logado = request.usuario.get('tipo_usuario')

    # Usuários só podem editar seus próprios dados, administradores podem editar qualquer usuário
    if usuario_logado_id != usuario_id and tipo_usuario_logado not in ['administrador', 'bibliotecario']:
        return jsonify({"erro": "Acesso negado. Você só pode editar seus próprios dados."}), 403

    if not secao:
        return jsonify({"erro": "Seção é obrigatória (conta, usuario, curso, contato)."}), 400

    con = None
    cur = None
    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        # Verificar se usuário existe
        cur.execute("SELECT id, tipo_usuario FROM usuarios WHERE id = ?", (usuario_id,))
        usuario_existe = cur.fetchone()

        if not usuario_existe:
            return jsonify({"erro": "Usuário não encontrado."}), 404

        # Processar cada seção separadamente
        if secao == "conta":
            return atualizar_informacoes_conta(cur, con, usuario_id, dados)
        elif secao == "usuario":
            return atualizar_informacoes_usuario(cur, con, usuario_id, dados)
        elif secao == "curso":
            return atualizar_informacoes_curso(cur, con, usuario_id, dados, tipo_usuario_logado)
        elif secao == "contato":
            return atualizar_informacoes_contato(cur, con, usuario_id, dados)
        else:
            return jsonify({"erro": "Seção inválida. Use: conta, usuario, curso ou contato."}), 400

    except Exception as e:
        if con:
            con.rollback()
        return jsonify({"erro": f"Erro interno do servidor: {str(e)}"}), 500

    finally:
        if cur:
            cur.close()
        if con:
            con.close()


# ===================== FUNÇÕES AUXILIARES PARA CADA SEÇÃO =====================
def atualizar_informacoes_conta(cur, con, usuario_id, dados):
    """Atualizar informações da conta"""
    nome_usuario = dados.get("nome_usuario")
    biografia = dados.get("biografia")

    # ADICIONAR VALIDAÇÃO OBRIGATÓRIA
    # Nome de usuário é obrigatório
    if not nome_usuario or not nome_usuario.strip():
        return jsonify({"erro": "Nome de usuário é obrigatório."}), 400

    # Verificar duplicidade de nome de usuário
    cur.execute("SELECT 1 FROM usuarios WHERE nome_usuario = ? AND id != ?", (nome_usuario.strip(), usuario_id))
    if cur.fetchone():
        return jsonify({"erro": "Nome de usuário já está em uso."}), 409

    campos_atualizacao = []
    valores = []

    # Nome usuário (obrigatório)
    campos_atualizacao.append("nome_usuario = ?")
    valores.append(nome_usuario.strip())

    # Biografia (opcional)
    campos_atualizacao.append("biografia = ?")
    valores.append(biografia.strip() if biografia and biografia.strip() else None)

    # Executar atualização
    valores.append(usuario_id)
    query = f"UPDATE usuarios SET {', '.join(campos_atualizacao)} WHERE id = ?"
    cur.execute(query, valores)
    con.commit()

    return jsonify({"mensagem": "Informações da conta atualizadas com sucesso!"}), 200

def atualizar_informacoes_curso(cur, con, usuario_id, dados, tipo_usuario_logado):
    """Atualizar informações do curso"""
    curso = dados.get("curso")
    periodo = dados.get("periodo")
    codigo_aluno = dados.get("codigo_aluno")
    data_vigencia = dados.get("data_vigencia")

    # ADICIONAR VALIDAÇÕES OBRIGATÓRIAS
    # Curso é obrigatório
    if not curso or not curso.strip():
        return jsonify({"erro": "Curso é obrigatório."}), 400

    # Código do aluno é obrigatório
    if not codigo_aluno or not codigo_aluno.strip():
        return jsonify({"erro": "Código de aluno é obrigatório."}), 400

    # Verificar se usuário comum está tentando alterar data de vigência
    if data_vigencia is not None and tipo_usuario_logado not in ['administrador', 'bibliotecario']:
        return jsonify({"erro": "Apenas administradores podem alterar a data de vigência."}), 403

    # Validações de formato
    if data_vigencia and data_vigencia.strip():
        try:
            datetime.strptime(data_vigencia, '%Y-%m-%d')
        except ValueError:
            return jsonify({"erro": "Formato de data de vigência inválido. Use YYYY-MM-DD."}), 400

    # Verificar duplicidade de código de aluno
    if codigo_aluno and codigo_aluno.strip():
        cur.execute("SELECT 1 FROM usuarios WHERE codigo_aluno = ? AND id != ?", (codigo_aluno, usuario_id))
        if cur.fetchone():
            return jsonify({"erro": "Código de aluno já está em uso."}), 409

    campos_atualizacao = []
    valores = []

    # Curso (obrigatório)
    campos_atualizacao.append("curso = ?")
    valores.append(curso.strip())

    # Período (opcional)
    campos_atualizacao.append("periodo = ?")
    valores.append(periodo.strip() if periodo and periodo.strip() else None)

    # Código aluno (obrigatório)
    campos_atualizacao.append("codigo_aluno = ?")
    valores.append(codigo_aluno.strip())

    # Data vigência (opcional, apenas para admins)
    if tipo_usuario_logado in ['bibliotecario']:
        campos_atualizacao.append("data_vigencia = ?")
        valores.append(data_vigencia.strip() if data_vigencia and data_vigencia.strip() else None)

    # Executar atualização
    valores.append(usuario_id)
    query = f"UPDATE usuarios SET {', '.join(campos_atualizacao)} WHERE id = ?"
    cur.execute(query, valores)
    con.commit()

    return jsonify({"mensagem": "Informações do curso atualizadas com sucesso!"}), 200

def atualizar_informacoes_usuario(cur, con, usuario_id, dados):
    """Atualizar informações pessoais do usuário"""
    nome_completo = dados.get("nome_completo")
    cpf = dados.get("cpf")
    sexo = dados.get("sexo")
    data_nascimento = dados.get("data_nascimento")

    # ADICIONAR VALIDAÇÕES OBRIGATÓRIAS
    # Nome completo é obrigatório
    if not nome_completo or not nome_completo.strip():
        return jsonify({"erro": "Nome completo é obrigatório."}), 400

    # Data de nascimento é obrigatória
    if not data_nascimento or not data_nascimento.strip():
        return jsonify({"erro": "Data de nascimento é obrigatória."}), 400

    # Validações existentes
    if sexo is not None and sexo not in ['masculino', 'feminino','']:
        return jsonify({"erro": "Sexo deve ser 'masculino' ou 'feminino'."}), 400

    if data_nascimento:
        try:
            datetime.strptime(data_nascimento, '%Y-%m-%d')
        except ValueError:
            return jsonify({"erro": "Formato de data de nascimento inválido. Use YYYY-MM-DD."}), 400

    # Verificar duplicidade de CPF apenas se fornecido
    if cpf and cpf.strip():
        cur.execute("SELECT 1 FROM usuarios WHERE cpf = ? AND id != ?", (cpf, usuario_id))
        if cur.fetchone():
            return jsonify({"erro": "CPF já está cadastrado para outro usuário."}), 409

    campos_atualizacao = []
    valores = []

    # Nome completo (obrigatório)
    campos_atualizacao.append("nome_completo = ?")
    valores.append(nome_completo.strip())

    # CPF (opcional)
    campos_atualizacao.append("cpf = ?")
    valores.append(cpf.strip() if cpf and cpf.strip() else None)

    # Sexo (opcional)
    campos_atualizacao.append("sexo = ?")
    valores.append(sexo.strip() if sexo and sexo.strip() else None)

    # Data nascimento (obrigatório)
    campos_atualizacao.append("data_nascimento = ?")
    valores.append(data_nascimento.strip())

    # Executar atualização
    valores.append(usuario_id)
    query = f"UPDATE usuarios SET {', '.join(campos_atualizacao)} WHERE id = ?"
    cur.execute(query, valores)
    con.commit()

    return jsonify({"mensagem": "Informações pessoais atualizadas com sucesso!"}), 200

def atualizar_informacoes_contato(cur, con, usuario_id, dados):
    """Atualizar informações de contato"""
    email = dados.get("email")
    telefone = dados.get("telefone")
    cep = dados.get("cep")
    endereco = dados.get("endereco")

    # ADICIONAR VALIDAÇÕES OBRIGATÓRIAS
    # Email é obrigatório
    if not email or not email.strip():
        return jsonify({"erro": "Email é obrigatório."}), 400

    # Telefone é obrigatório
    if not telefone or not telefone.strip():
        return jsonify({"erro": "Telefone é obrigatório."}), 400

    # Validações de formato
    if not validar_email(email):
        return jsonify({"erro": "Formato de email inválido."}), 400

    # Verificar duplicidade de email
    cur.execute("SELECT 1 FROM usuarios WHERE email = ? AND id != ?", (email, usuario_id))
    if cur.fetchone():
        return jsonify({"erro": "Email já está em uso."}), 409

    campos_atualizacao = []
    valores = []

    # Email (obrigatório)
    campos_atualizacao.append("email = ?")
    valores.append(email.strip())

    # Telefone (obrigatório)
    campos_atualizacao.append("telefone = ?")
    valores.append(telefone.strip())

    # CEP (opcional)
    campos_atualizacao.append("cep = ?")
    valores.append(cep.strip() if cep and cep.strip() else None)

    # Endereço (opcional)
    campos_atualizacao.append("endereco = ?")
    valores.append(endereco.strip() if endereco and endereco.strip() else None)

    # Executar atualização
    valores.append(usuario_id)
    query = f"UPDATE usuarios SET {', '.join(campos_atualizacao)} WHERE id = ?"
    cur.execute(query, valores)
    con.commit()

    return jsonify({"mensagem": "Informações de contato atualizadas com sucesso!"}), 200


# ===================== ROTA ADICIONAL PARA BUSCAR USUÁRIO ESPECÍFICO =====================

@rotas.route("/usuarios/<int:usuario_id>", methods=["GET"])
@token_requerido
def buscar_usuario_especifico(usuario_id):
    """Buscar dados de um usuário específico"""
    usuario_logado_id = request.usuario.get('id')
    tipo_usuario_logado = request.usuario.get('tipo_usuario')

    # Usuários só podem ver seus próprios dados, administradores podem ver qualquer usuário
    if usuario_logado_id != usuario_id and tipo_usuario_logado not in ['administrador', 'bibliotecario']:
        return jsonify({"erro": "Acesso negado."}), 403

    con = None
    cur = None
    try:
        con = fdb.connect(**current_app.config['DB_CONFIG'])
        cur = con.cursor()

        cur.execute("""
            SELECT 
                id, nome_usuario, biografia, nome_completo, cpf, sexo, data_nascimento,
                curso, periodo, codigo_aluno, data_vigencia, email, telefone, cep, endereco,
                tipo_usuario
            FROM usuarios 
            WHERE id = ?
        """, (usuario_id,))

        resultado = cur.fetchone()

        if not resultado:
            return jsonify({"erro": "Usuário não encontrado."}), 404

        colunas = [
            'id', 'nome_usuario', 'biografia', 'nome_completo', 'cpf', 'sexo', 'data_nascimento',
            'curso', 'periodo', 'codigo_aluno', 'data_vigencia', 'email', 'telefone', 'cep',
            'endereco', 'tipo_usuario'
        ]

        dados_usuario = {}
        for i, coluna in enumerate(colunas):
            if i < len(resultado):
                valor = resultado[i]

                # Formatar datas
                if coluna in ['data_nascimento', 'data_vigencia'] and valor:
                    if hasattr(valor, 'strftime'):
                        dados_usuario[coluna] = valor.strftime('%Y-%m-%d')
                    else:
                        dados_usuario[coluna] = str(valor)
                else:
                    dados_usuario[coluna] = valor

        # Remover ID por segurança se não for admin
        if tipo_usuario_logado not in ['administrador', 'bibliotecario']:
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