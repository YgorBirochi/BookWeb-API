import os

# Diretório base do projeto
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Segurança da aplicação Flask
SECRET_KEY = '101907yb@'
DEBUG = True

# Banco de dados Firebird
DB_HOST = 'localhost'
DB_NAME = os.path.join(BASE_DIR, 'Banco', 'BOOKWEB.FDB')
DB_USER = 'SYSDBA'
DB_PASSWORD = 'sysdba'

# Configuração do driver fdb
DB_CONFIG = {
    "dsn": f"{DB_HOST}:{DB_NAME}",
    "user": DB_USER,
    "password": DB_PASSWORD
}

# Pasta de uploads (relativa ao projeto)
UPLOAD_FOLDER = os.path.join(BASE_DIR, 'upload')

# Senha de app para envio de e-mails (Gmail, por exemplo)
SENHA_APP_EMAIL = ''  # senha que será gerada furturamente para envio de emails
