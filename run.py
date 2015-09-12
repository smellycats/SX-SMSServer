from sms import app, views
from sms import debug_logging, online_logging, access_logging
from ini_conf import MyIni

if __name__ == '__main__':
    debug_logging(u'logs/error.log')
    access_logging(u'logs/access.log')

    my_ini = MyIni()
    mysql_ini = my_ini.get_mysql()
    sys_ini = my_ini.get_sys()

    app.config['SECRET_KEY'] = sys_ini['secret_key']
    app.config['WHITE_LIST_OPEN'] = sys_ini['while_list_open']
    app.config['WHITE_LIST'] = sys_ini['while_list'].split(',')
    app.config['SQLALCHEMY_BINDS']['sms'] = 'mysql://%s:%s@%s:%s/%s' % (mysql_ini['user'], mysql_ini['pwd'], mysql_ini['host'], str(mysql_ini['port']), mysql_ini['db'])
    app.config['SMS_WSDL_PARAMS'] = my_ini.get_webservice()
    del my_ini
    app.run(host=sys_ini['host'], port=sys_ini['port'], threaded=True)
