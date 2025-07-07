from flask import Flask

def create_app():
    app = Flask(__name__)

    # Carregar configurações de config.py, se houver
    from app import config
    app.config.from_object(config)

    # Registrar rotas (Blueprint)
    from app.routes import rotas
    app.register_blueprint(rotas)

    return app
