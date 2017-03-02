# -*- coding: utf-8 -*-
import datetime
import json

import arrow
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

IP = '127.0.0.1'
PORT = 5000

def auth_test(url):
    headers = {'Authorization': 'Digest kakou="pingworker"',
               'content-type': 'application/json'}
    r = requests.get(url, headers=headers)

    return r

def user_get(token):
    url = 'http://localhost:8098/user/1'
    headers = {'content-type': 'application/json',
               'access_token': token}
    r = requests.get(url, headers=headers)
    return r

def user_post():
    headers = {'content-type': 'application/json'}
    url = 'http://{0}:{1}/user'.format(IP, PORT)
    data = {'username': 'union_kakou', 'password': 'unionkakousms',
            'scope': 'sms_post'}
    r = requests.post(url, headers=headers,data=json.dumps(data),
                      auth=HTTPBasicAuth('admin', 'sx2767722'))

    return r

def user_put(token):
    headers = {'content-type': 'application/json', 'access_token': token}
    url = 'http://127.0.0.1:8098/user/4'
    data = {'scope': 'scope_get,user_get'}
    r = requests.put(url, headers=headers, data=json.dumps(data))

    return r

def token_test():
    headers = {'content-type': 'application/json'}
    url = 'http://127.0.0.1:5000/token'
    data = {'username': 'smstest', 'password': 'showmethemoney'}
    r = requests.post(url, headers=headers, data=json.dumps(data))

    return r

def scope_get(token):
    url = 'http://localhost:8098/scope'
    headers = {'content-type': 'application/json', 'access_token': token}
    r = requests.get(url, headers=headers)
    return r

def sms_post(token):
    headers = {'content-type': 'application/json', 'access_token': token}
    url = 'http://%s:%s/sms' % (IP, PORT)
    data = {'mobiles': ['709394','888'], 'content': '死肥仔'}
    r = requests.post(url, headers=headers, data=json.dumps(data))

    return r

if __name__ == '__main__':  # pragma nocover
    token = 'eyJhbGciOiJIUzI1NiIsImV4cCI6MTQ0MTM4NzkyNSwiaWF0IjoxNDQxMzg0MzI1fQ.eyJzY29wZSI6WyJhbGwiXSwidWlkIjoxfQ.Eoas-we-VZeiXqZuLvMEGbLTih1nJ-moAS0LmZFnKpc'
    #token_test = 'eyJhbGciOiJIUzI1NiIsImV4cCI6MTQ0MTM4ODY0MSwiaWF0IjoxNDQxMzg1MDQxfQ.eyJzY29wZSI6WyJzbXNfcG9zdCJdLCJ1aWQiOjJ9.ItdF1WtLKA9vpEjiyER-eI01-te9w9EZ2F1Z9bwY0bE'
    #r = user_post(token)
    #r = token_test()
    #r = sms_post(token_test)
    #r = sms_post(token)
    r = user_post()
    print r.headers
    print r.status_code
    print r.text
