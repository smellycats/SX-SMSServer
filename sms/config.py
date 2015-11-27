# -*- coding: utf-8 -*-

class Config(object):
    # 密码 string
    SECRET_KEY = 'hellokitty'
    # 服务器名称 string
    HEADER_SERVER = 'SX-SMSServer'
    # 加密次数 int
    ROUNDS = 123456
    # token生存周期，默认2小时 int
    EXPIRES = 7200
    # 数据库连接 string
    SQLALCHEMY_DATABASE_URI = 'mysql://root:root@localhost:3306/sms'
    # 数据库连接 dict
    SQLALCHEMY_BINDS = {}
    # 连接池大小 int
    SQLALCHEMY_POOL_SIZE = 20
    # 用户权限范围 dict
    SCOPE_USER = {}
    # 命牌是否开启 bool
    TOKEN_OPEN = False
    # 白名单启用 bool
    WHITE_LIST_OPEN = False
    # 白名单列表 set
    WHITE_LIST = set(['127.0.0.1'])
    # webservice短信平台参数 dict
    SMS_WSDL_PARAMS = {
        'url': '',
        'db_ip': '',
        'db_name': '',
        'db_port': '',
        'user': '',
        'pwd': ''
    }

class Develop(Config):
    DEBUG = True

class Production(Config):
    DEBUG = False
