# -*- coding: utf-8 -*-
from suds.client import Client


class SMSClient(object):
    def __init__(self, **kwargs):
        self.ini = kwargs
        self.client = Client(self.ini['url'])

    def sms_init(self):
        return self.client.service.init(
            dbIp=self.ini['db_ip'], dbName=self.ini['db_name'],
            dbPort=self.ini['db_port'], user=self.ini['user'],
            pwd=self.ini['pwd'])

    def sms_send(self, mobiles, content, sm_id):
        return self.client.service.sendSM(
            apiCode=self.ini['user'], loginName=self.ini['user'],
            loginPwd=self.ini['pwd'], mobiles=mobiles, content=content,
            smID=sm_id)

    def __del__(self):
        self.client.service.release()
