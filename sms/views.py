# -*- coding: utf-8 -*-
import json
from functools import wraps

import arrow
from flask import g, request, make_response, jsonify
from flask_restful import reqparse, abort, Resource
from passlib.hash import sha256_crypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from sms import db, app, api, auth, limiter, logger, access_logger
from models import Users, Scope, SMS
from help_func import *
import helper
from soap_func import SMSClient


def verify_addr(f):
    """IP地址白名单"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config['WHITE_LIST_OPEN'] or request.remote_addr == '127.0.0.1' or request.remote_addr in app.config['WHITE_LIST']:
            pass
        else:
            return {'status': '403.6',
                    'message': u'禁止访问:客户端的 IP 地址被拒绝'}, 403
        return f(*args, **kwargs)
    return decorated_function


@auth.verify_password
def verify_password(username, password):
    if username.lower() == 'admin':
        user = Users.query.filter_by(username='admin').first()
    else:
        return False
    if user:
        return sha256_crypt.verify(password, user.password)
    return False


def verify_token(f):
    """token验证装饰器"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if app.config['TOKEN_OPEN']:
            g.uid = helper.ip2num(request.remote_addr)
            g.scope = set(['all'])
        else:
            if not request.headers.get('Access-Token'):
                return {'status': '401.6', 'message': 'missing token header'}, 401
            token_result = verify_auth_token(request.headers['Access-Token'],
                                             app.config['SECRET_KEY'])
            if not token_result:
                return {'status': '401.7', 'message': 'invalid token'}, 401
            elif token_result == 'expired':
                return {'status': '401.8', 'message': 'token expired'}, 401
            g.uid = token_result['uid']
            g.scope = set(token_result['scope'])

        return f(*args, **kwargs)
    return decorated_function


def verify_scope(scope):
    def scope(f):
        """权限范围验证装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'all' in g.scope or scope in g.scope:
                return f(*args, **kwargs)
            else:
                return {}, 405
        return decorated_function
    return scope


class Index(Resource):

    def get(self):
        return {
            'user_url': 'http://%suser{/user_id}' % (request.url_root),
            'scope_url': 'http://%sscope' % (request.url_root),
            'token_url': 'http://%stoken' % (request.url_root),
            'sms_url': 'http://%ssms/' % (request.url_root)
        }, 200, {'Cache-Control': 'public, max-age=60, s-maxage=60'}


class User(Resource):
    decorators = [limiter.limit("5000/hours")]

    @verify_addr
    @verify_token
    @verify_scope('user_get')
    def get(self, user_id):
        user = Users.query.filter_by(id=user_id, banned=0).first()
        if user:
            return {'id': user.id,
                    'username': user.username,
                    'scope': user.scope,
                    'date_created': str(user.date_created),
                    'date_modified': str(user.date_modified),
                    'banned': user.banned}, 200
        else:
            return {}, 404

    @verify_addr
    @verify_token
    @verify_scope('user_patch')
    def post(self, user_id):
        parser = reqparse.RequestParser()

        parser.add_argument('scope', type=unicode, required=True,
                            help='A scope field is require', location='json')
        args = parser.parse_args()

        # 所有权限范围
        all_scope = set()
        for i in Scope.query.all():
            all_scope.add(i.name)
        # 授予的权限范围
        request_scope = set(request.json.get('scope', u'null').split(','))
        # 求交集后的权限
        u_scope = ','.join(all_scope & request_scope)

        db.session.query(Users).filter_by(id=user_id).update(
            {'scope': u_scope, 'date_modified': arrow.now().datetime})
        db.session.commit()

        user = Users.query.filter_by(id=user_id).first()
        app.config['SCOPE_USER'][user.id] = set(user.scope.split(','))

        return {
            'id': user.id,
            'username': user.username,
            'scope': user.scope,
            'date_created': str(user.date_created),
            'date_modified': str(user.date_modified),
            'banned': user.banned
        }, 201


class UserList(Resource):
    decorators = [verify_token, limiter.limit("50/minute")]

    @verify_addr
    @verify_token
    @verify_scope('user_post')
    def post(self):
        if not request.json.get('username', None):
            error = {'resource': 'Token', 'field': 'username',
                     'code': 'missing_field'}
            return {'message': 'Validation Failed', 'errors': error}, 422
        if not request.json.get('password', None):
            error = {'resource': 'Token', 'field': 'username',
                     'code': 'missing_field'}
            return {'message': 'Validation Failed', 'errors': error}, 422

        user = Users.query.filter_by(username=request.json['username'],
                                     banned=0).first()
        if not user:
            password_hash = sha256_crypt.encrypt(request.json['password'],
                                                 rounds=app.config['ROUNDS'])
            # 所有权限范围
            all_scope = set()
            for i in Scope.query.all():
                all_scope.add(i.name)
            # 授予的权限范围
            request_scope = set(request.json.get('scope', u'null').split(','))
            # 求交集后的权限
            u_scope = ','.join(all_scope & request_scope)
            u = Users(username=request.json['username'],
                      password=password_hash, scope=u_scope, banned=0)
            db.session.add(u)
            db.session.commit()
            return {
                'id': u.id,
                'username': u.username,
                'scope': u.scope,
                'date_created': str(u.date_created),
                'date_modified': str(u.date_modified),
                'banned': u.banned
            }, 201
        else:
            return {'message': 'username is already esist'}, 422


class ScopeList(Resource):

    @verify_addr
    @verify_token
    @verify_scope('scope_get')
    def get(self):
        scope = Scope.query.all()
        items = []
        for i in scope:
            items.append(row2dict(i))
        return {'total_count': len(items), 'items': items}, 200

@app.route('/token', methods=['OPTIONS'])
@limiter.limit("5000/hour")
def token_options():
    return jsonify(), 200

@app.route('/token', methods=['POST'])
@limiter.limit("5/minute")
def token_post():
    print 'post'
    try:
        if request.json is None:
            return jsonify({'message': 'Problems parsing JSON'}), 400
        if not request.json.get('username', None):
            error = {'resource': 'Token', 'field': 'username',
                     'code': 'missing_field'}
            return jsonify({'message': 'Validation Failed', 'errors': error}), 422
        if not request.json.get('password', None):
            error = {'resource': 'Token', 'field': 'username',
                     'code': 'missing_field'}
            return jsonify({'message': 'Validation Failed', 'errors': error}), 422
        user = Users.query.filter_by(username=request.json.get('username'),
                                     banned=0).first()
        if not user:
            return jsonify({'message': 'username or password error'}), 422
        if not sha256_crypt.verify(request.json.get('password'), user.password):
            return jsonify({'message': 'username or password error'}), 422

        print 'post3'
        s = Serializer(app.config['SECRET_KEY'],
                       expires_in=app.config['EXPIRES'])
        print 'post4'
        token = s.dumps({'uid': user.id, 'scope': user.scope.split(',')})
    except Exception as e:
        print e

    return jsonify({
        'uid': user.id,
        'access_token': token,
        'token_type': 'self',
        'scope': user.scope,
        'expires_in': app.config['EXPIRES']
    }), 201


class SMSList(Resource):
    decorators = [limiter.limit("60/minute")]

    @verify_addr
    #@verify_token
    #@verify_scope('sms_get')
    def post(self):
        parser = reqparse.RequestParser()
        parser.add_argument('mobiles', type=list, required=True,
                            help='A mobiles list field is require',
                            location='json')
        parser.add_argument('content', type=unicode, required=True,
                            help='A content field is require', location='json')
        args = parser.parse_args()
        print request.json['mobiles']
        return {'returned_value': 2, 'success': True}, 201
        try:
            sms = SMS(mobiles=json.dumps(request.json['mobiles']),
                      content=request.json['content'],
                      returned_value=-99, user_id=g.uid)
            db.session.add(sms)
            db.session.commit()
            sms_ini = app.config['SMS_WSDL_PARAMS']
            sms_client = SMSClient(sms_ini['url'])
            sms_client.sms_init(sms_ini['db_ip'], sms_ini['db_name'],
                                sms_ini['db_port'], sms_ini['user'],
                                sms_ini['pwd'])
            if request.json.get('smid', None):
                smid = sms.id
            else:
                smid = g.uid
            r = sms_client.sms_send(sms_ini['user'], sms_ini['user'],
                                    sms_ini['pwd'],request.json['mobiles'],
                                    request.json['content'], smsid)
            sms.returned_value = r
            db.session.commit()
            del sms_client
        except Exception as e:
            logger.error(e)
            raise
        result = {
            'id': sms.id,
            'date_send': str(sms.date_send),
            'mobiles': json.loads(sms.mobiles),
            'content': sms.content,
            'user_id': sms.user_id,
            'returned_value': sms.returned_value
        }
        if sms.returned_value == 0:
            result['succeed'] = True
        else:
            result['succeed'] = False

        return result, 201

@app.route('/sms', methods=['OPTIONS'])
@limiter.limit("5000/hour")
def sms_options():
    return jsonify(), 200

@app.route('/sms', methods=['GET'])
@limiter.limit("5000/hour")
def sms_get():
    limit = request.args.get('limit', 20)
    offset = request.args.get('offset', 0)
    
    sms = SMS.query.order_by('date_send desc').limit(limit).offset(offset).all()
    total = SMS.query.count()
    items = []
    for i in sms:
        items.append({'id': i.id, 'date_send': str(i.date_send),
                      'mobiles': i.mobiles,
                      'content': i.content,
                      'returned_value': i.returned_value,
                      'user_id': i.user_id})
    return jsonify({'total_count': total, 'items': items}), 200


api.add_resource(Index, '/')
api.add_resource(User, '/user/<int:user_id>')
api.add_resource(UserList, '/user')
api.add_resource(ScopeList, '/user/scope')
#api.add_resource(TokenList, '/token')
api.add_resource(SMSList, '/sms')




