from application.util import generate

class Config(object):
    SECRET_KEY = generate(50)
    MYSQL_HOST = 'localhost'
    MYSQL_USER = 'user'
    MYSQL_PASSWORD = 'xClow3n123'
    MYSQL_DB = 'web_desynth_recruit'
    UPLOAD_FOLDER = 'documents/'

class ProductionConfig(Config):
    pass

class DevelopmentConfig(Config):
    DEBUG = True

class TestingConfig(Config):
    TESTING = True