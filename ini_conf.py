#-*- encoding: utf-8 -*-
import ConfigParser

class MyIni:
    def __init__(self, confpath = 'my_ini.conf'):
        self.cf = ConfigParser.ConfigParser()
        self.cf.read(confpath)

    def get_mysql(self):
        conf = {}
        conf['host'] = self.cf.get('MYSQL', 'host')
        conf['port'] = self.cf.getint('MYSQL', 'port')
        conf['user'] = self.cf.get('MYSQL', 'user')
        conf['pwd']  = self.cf.get('MYSQL', 'pwd')
        conf['db']   = self.cf.get('MYSQL', 'db')
        return conf

    def get_sys(self):
        conf = {}
        conf['secret_key'] = self.cf.get('SYS', 'secret_key')
        conf['host']       = self.cf.get('SYS', 'host')
        conf['port']       = self.cf.getint('SYS', 'port')
        conf['while_list_open'] = self.cf.getboolean('SYS', 'while_list_open')
        conf['while_list']      = self.cf.get('SYS', 'while_list')
        return conf

    def get_webservice(self):
        conf = {}
        conf['url']     = self.cf.get('WEBSERVICE', 'url')
        conf['db_ip']   = self.cf.get('WEBSERVICE', 'db_ip')
        conf['db_name'] = self.cf.get('WEBSERVICE', 'db_name')
        conf['db_port'] = self.cf.get('WEBSERVICE', 'db_port')
        conf['user']    = self.cf.get('WEBSERVICE', 'user')
        conf['pwd']     = self.cf.get('WEBSERVICE', 'pwd')
        return conf

    def __del__(self):
        del self.cf


