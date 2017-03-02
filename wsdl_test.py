# -*- coding: utf-8 -*-
from sms.soap_func import SMSClient


def sms_test():
    url = 'http://10.44.237.123/axis/services/SMsg?wsdl'
    sms = SMSClient(url)
    sms.sms_init('10.44.237.123', 'mas', '3306', 'kkxt', 'kkxt')
    print help(sms)
    r = sms.sms_send('kkxt', 'kkxt', 'kkxt', ['15819851862', '13556222300'],
                     u'1234567', 2)
    help(sms)
    del sms


if __name__ == '__main__':  # pragma nocover
    sms_test()
