from flask import Flask
from flask_cors import CORS

def create_app():
    app = Flask(__name__)

    # Carregar configurações de config.py, se houver
    from app import config
    app.config.from_object(config)

    # Inicializar CORS apenas para origens específicas
    CORS(app, origins=['http://127.0.0.1:5500', 'http://localhost:5500'])

    # Registrar rotas (Blueprint)
    from app.routes import rotas
    app.register_blueprint(rotas)

    return app