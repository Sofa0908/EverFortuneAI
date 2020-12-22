class MyConfig(object):
  SECRET_KEY = 't;6ru8 54s/6'
  SQLALCHEMY_DATABASE_URI = 'mysql+pymysql://root:Nocompl3x!@localhost/sys'
  SQLALCHEMY_TRACK_MODIFICATIONS = False
  JWT_SECRET_KEY = 'everfortuneai'
  JWT_BLACKLIST_ENABLED = True
  JWT_BLACKLIST_TOKEN_CHECKS = ['access', 'refresh']