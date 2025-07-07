class Usuario:
    def __init__(
        self,
        id,
        nome_usuario,
        senha,
        nome_completo,
        email,
        curso,
        data_nascimento,
        data_cadastro,
        data_vigencia,
        codigo_aluno,
        telefone,
        sexo,
        cpf,
        cep,
        endereco,
        status,
        tipo_usuario
    ):
        self.id = id
        self.nome_usuario = nome_usuario
        self.senha = senha
        self.nome_completo = nome_completo
        self.email = email
        self.curso = curso
        self.data_nascimento = data_nascimento
        self.data_cadastro = data_cadastro
        self.data_vigencia = data_vigencia
        self.codigo_aluno = codigo_aluno
        self.telefone = telefone
        self.sexo = sexo
        self.cpf = cpf
        self.cep = cep
        self.endereco = endereco
        self.status = status
        self.tipo_usuario = tipo_usuario
