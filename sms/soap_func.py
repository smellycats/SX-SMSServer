# -*- coding: utf-8 -*-
from suds.client import Client


class SMSClient:
    def __init__(self, url='http://10.44.237.88/axis/services/SMsg?wsdl'):
        self.client = Client(url)

    
    def sms_init(self, db_ip, db_name, db_port, user, pwd):
        result = client.service.init(dbIp=db_ip, dbName=db_name,
                                     dbPort=db_port, user=user, pwd=pwd)
        return result

    def sms_send(self, api_code, login_name, login_pwd, mobiles, content,
                 sm_id):
        return client.service.sendSM(apiCode=api_code, loginName=login_name,
                                     loginPwd=login_pwd, mobiles=mobiles,
                                     content=content, smID=sm_id)

