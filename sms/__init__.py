# -*- coding: utf-8 -*-
import logging

import arrow
from flask import Flask, request, jsonify
from flask_restful import Api
from flask_httpauth import HTTPBasicAuth, HTTPDigestAuth
#from flask_limiter import Limiter, HEADERS
from flask.ext.sqlalchemy import SQLAlchemy
# from flask.ext.cache import Cache

from config import Production
from my_logger import debug_logging, online_logging, access_logging


# create a flask application - this ``app`` object will be used to handle
app = Flask(__name__)
app.config.from_object(Production())
api = Api(app)

db = SQLAlchemy(app)

auth = HTTPBasicAuth()

debug_logging(u'logs/error.log')
access_logging(u'logs/access.log')

logger = logging.getLogger('root')
access_logger = logging.getLogger('access')

##limiter = Limiter(app, headers_enabled=True, global_limits=["10/minute"])
##limiter.header_mapping = {
##    HEADERS.LIMIT: "X-RateLimit-Limit",
##    HEADERS.RESET: "X-RateLimit-Reset",
##    HEADERS.REMAINING: "X-RateLimit-Remaining"
##}

# cache = Cache(app, config={'CACHE_TYPE': 'simple'})

from sms import views


@app.after_request
def after_request(response):
    """访问信息写入日志"""
    access_logger.info('%s - - [%s] "%s %s HTTP/1.1" %s %s'
                       % (request.remote_addr,
                          arrow.now().format('DD/MMM/YYYY:HH:mm:ss ZZ'),
                          request.method, request.path, response.status_code,
                          response.content_length))
    response.headers['Server'] = app.config['HEADER_SERVER']
    response.headers['Content-Type'] = 'application/json; charset=utf-8'

    return response


@app.errorhandler(404)
def page_not_found(error):
    return jsonify({'message': 'Not Found'}), 404,
    {'Content-Type': 'application/json; charset=utf-8',
     'Server': app.config['HEADER_SERVER']}


@app.errorhandler(405)
def method_not_allow(error):
    return jsonify({'message': 'Method Not Allowed'}), 405,
    {'Content-Type': 'application/json; charset=utf-8',
     'Server': app.config['HEADER_SERVER']}


@app.errorhandler(500)
def internal_server_error(error):
    return jsonify({'message': 'Internal Server Error'}), 500,
    {'Content-Type': 'application/json; charset=utf-8',
     'Server': app.config['HEADER_SERVER']}
