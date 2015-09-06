# -*- coding: utf-8 -*-
from sms.soap_func import SMSClient


def sms_test():
    url = 'http://10.44.237.88/axis/services/SMsg?wsdl'
    sms = SMSClient(url)
    sms.sms_init('10.44.237.88', 'mas', '3306', 'kkxt', 'kkxt')
    r = sms.sms_send('kkxt', 'kkxt', 'kkxt', ['15819851862', '13556222300'],
                     u'1234567', 2)
    print type(r)
    del sms


if __name__ == '__main__':  # pragma nocover
    sms_test()
