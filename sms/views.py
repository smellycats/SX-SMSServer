# -*- coding: utf-8 -*-
import json
from functools import wraps

import arrow
from flask import g, request, make_response, jsonify, abort
from flask_restful import reqparse, abort, Resource
from passlib.hash import sha256_crypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from . import db, app, api, auth, limiter, logger, access_logger
from models import *
import helper
from soap_func import SMSClient


def verify_addr(f):
    """IP地址白名单"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not app.config['WHITE_LIST_OPEN'] or \
           request.remote_addr in set(['127.0.0.1', 'localhost']) or \
           request.remote_addr in app.config['WHITE_LIST']:
            pass
        else:
            return jsonify({
                'status': '403.6',
                'message': u'禁止访问:客户端的 IP 地址被拒绝'}), 403
        return f(*args, **kwargs)
    return decorated_function


@auth.verify_password
def verify_pw(username, password):
    user = Users.query.filter_by(username=username).first()
    if user:
        g.uid = user.id
        g.scope = set(user.scope.split(','))
        return sha256_crypt.verify(password, user.password)
    return False


def verify_scope(scope):
    def scope(f):
        """权限范围验证装饰器"""
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'all' in g.scope or scope in g.scope:
                return f(*args, **kwargs)
            else:
                abort(405)
        return decorated_function
    return scope


@app.route('/')
@limiter.limit("5000/hour")
def index_get():
    result = {
        'user_url': '%suser{/user_id}' % (request.url_root),
        'scope_url': '%sscope' % (request.url_root),
        'sms_url': '%ssms/{sms_id}' % (request.url_root),
        'phone_url': '%sphone/{phone_id}' % (request.url_root)
    }
    header = {'Cache-Control': 'public, max-age=60, s-maxage=60'}
    return jsonify(result), 200, header


@app.route('/user/<int:user_id>', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def user_get(user_id):
    user = Users.query.filter_by(id=user_id, banned=0).first()
    if user is None:
        abort(404)
    result = {
        'id': user.id,
        'username': user.username,
        'scope': user.scope,
        'date_created': user.date_created.strftime('%Y-%m-%d %H:%M:%S'),
        'date_modified': user.date_modified.strftime('%Y-%m-%d %H:%M:%S'),
        'banned': user.banned
    }
    return jsonify(result), 200


@app.route('/user', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def user_list_get():
    try:
        limit = int(request.args.get('per_page', 20))
        offset = (int(request.args.get('page', 1)) - 1) * limit
        s = db.session.query(Users)
        q = request.args.get('q', None)
        if q is not None:
            s = s.filter(Users.username.like("%{0}%".format(q)))
        user = s.limit(limit).offset(offset).all()
        total = s.count()
        items = []
        for i in user:
            items.append({
                'id': i.id,
                'username': i.username,
                'scope': i.scope,
                'date_created': i.date_created.strftime('%Y-%m-%d %H:%M:%S'),
                'date_modified': i.date_modified.strftime('%Y-%m-%d %H:%M:%S'),
                'banned': i.banned})
    except Exception as e:
        logger.exception(e)
    return jsonify({'total_count': total, 'items': items}), 200


@app.route('/user/<int:user_id>', methods=['POST', 'PUT'])
@limiter.limit('5000/hour')
@auth.login_required
def user_put(user_id):
    if not request.json:
        return jsonify({'message': 'Problems parsing JSON'}), 415
    user = Users.query.filter_by(id=user_id).first()
    if user is None:
        abort(404)
    if request.json.get('scope', None) is not None:
        # 所有权限范围
        all_scope = set()
        for i in Scope.query.all():
            all_scope.add(i.name)
        # 授予的权限范围
        request_scope = set(request.json.get('scope', u'null').split(','))
        # 求交集后的权限
        u_scope = ','.join(all_scope & request_scope)

        user.scope = u_scope
    if request.json.get('password', None) is not None:
        user.password = sha256_crypt.encrypt(
            request.json['password'], rounds=app.config['ROUNDS'])
    if request.json.get('banned', None) is not None:
        user.banned = request.json['banned']
    user.date_modified = arrow.now('PRC').datetime.replace(tzinfo=None)
    db.session.commit()

    user = Users.query.filter_by(id=user_id).first()

    return jsonify(), 204


@app.route('/user', methods=['POST'])
@limiter.limit('5000/hour')
@auth.login_required
def user_post():
    if not request.json:
        return jsonify({'message': 'Problems parsing JSON'}), 415
    if not request.json.get('username', None):
        error = {
            'resource': 'user',
            'field': 'username',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    if not request.json.get('password', None):
        error = {
            'resource': 'user',
            'field': 'password',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    if not request.json.get('scope', None):
        error = {
            'resource': 'user',
            'field': 'scope',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    
    user = Users.query.filter_by(username=request.json['username'],
                                 banned=0).first()
    if user:
        return jsonify({'message': 'username is already esist'}), 422

    password_hash = sha256_crypt.encrypt(
        request.json['password'], rounds=app.config['ROUNDS'])
    # 所有权限范围
    all_scope = set()
    for i in Scope.query.all():
        all_scope.add(i.name)
    # 授予的权限范围
    request_scope = set(request.json.get('scope', u'null').split(','))
    # 求交集后的权限
    u_scope = ','.join(all_scope & request_scope)
    t = arrow.now('PRC').datetime.replace(tzinfo=None)
    u = Users(username=request.json['username'], password=password_hash,
              date_created=t, date_modified=t, scope=u_scope, banned=0)
    db.session.add(u)
    db.session.commit()
    result = {
        'id': u.id,
        'username': u.username,
        'scope': u.scope,
        'date_created': u.date_created.strftime('%Y-%m-%d %H:%M:%S'),
        'date_modified': u.date_modified.strftime('%Y-%m-%d %H:%M:%S'),
        'banned': u.banned
    }
    return jsonify(result), 201


@app.route('/scope', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def scope_list_get():
    items = map(helper.row2dict, Scope.query.all())
    return jsonify({'total_count': len(items), 'items': items}), 200


@app.route('/sms/<int:sms_id>', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def sms_get(sms_id):
    sms = SMS.query.filter_by(id=sms_id).first()
    if sms is None:
        abort(404)
    result = {
        'id': sms.id,
        'date_send': sms.date_send.strftime('%Y-%m-%d %H:%M:%S'),
        'mobiles': json.loads(sms.mobiles),
        'content': sms.content,
        'returned_value': sms.returned_value,
        'user_id': sms.user_id
    }
    return jsonify(result), 200


@app.route('/sms', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def sms_list_get():
    try:
        limit = int(request.args.get('per_page', 20))
        offset = (int(request.args.get('page', 1)) - 1) * limit
        st = request.args.get('st', None)
        et = request.args.get('et', None)
        s = db.session.query(SMS)
        if st is not None:
            st = arrow.get(st).datetime.replace(tzinfo=None)
            s = s.filter(SMS.date_send >= st)
            if et is not None:
                et = arrow.get(et).datetime.replace(tzinfo=None)
                s = s.filter(SMS.date_send <= et)
        q = request.args.get('q', None)
        if q is not None:
            s = s.filter(db.or_(SMS.mobiles.like("%{0}%".format(q)),
                         SMS.content.like("%{0}%".format(q))))
        user_id = request.args.get('user_id', None)
        if user_id is not None:
            s = s.filter(SMS.user_id == user_id)
        sms = s.order_by(SMS.date_send.desc()).limit(limit).offset(offset).all()
        total = s.count()
        items = []
        for i in sms:
            items.append({
                'id': i.id,
                'date_send': i.date_send.strftime('%Y-%m-%d %H:%M:%S'),
                'mobiles': json.loads(i.mobiles),
                'content': i.content,
                'returned_value': i.returned_value,
                'user_id': i.user_id})
    except Exception as e:
        logger.exception(e)
        raise
    return jsonify({'total_count': total, 'items': items}), 200


@app.route('/sms', methods=['POST'])
@limiter.limit('5000/hour')
@auth.login_required
def sms_post():
    if not request.json:
        return jsonify({'message': 'Problems parsing JSON'}), 415
    if not request.json.get('mobiles', None):
        error = {
            'resource': 'user',
            'field': 'mobiles',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    if not request.json.get('content', None):
        error = {
            'resource': 'user',
            'field': 'content',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    try:
        sms = SMS(mobiles=json.dumps(request.json['mobiles']), user_id=g.uid,
                  content=request.json['content'], returned_value=-99)
        db.session.add(sms)
        db.session.commit()

        if request.json.get('smid', None):
            smsid = sms.id
        else:
            smsid = g.uid % 10000
        sms_client = SMSClient(**app.config['SMS_WSDL_PARAMS'])
        sms_client.sms_init()
        r = sms_client.sms_send(
            request.json['mobiles'], request.json['content'], smsid)
        sms.returned_value = r
        db.session.commit()
        del sms_client
    except Exception as e:
        logger.exception(e)
        raise
    result = {
        'id': sms.id,
        'date_send': sms.date_send.strftime('%Y-%m-%d %H:%M:%S'),
        'mobiles': json.loads(sms.mobiles),
        'content': sms.content,
        'user_id': sms.user_id,
        'returned_value': sms.returned_value
    }
    if sms.returned_value == 0:
        result['succeed'] = True
    else:
        result['succeed'] = False

    return jsonify(result), 201


@app.route('/phone', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def phone_list_get():
    try:
        limit = int(request.args.get('per_page', 20))
        offset = (int(request.args.get('page', 1)) - 1) * limit
        s = Phone.query.filter_by(banned=0)
        p = s.limit(limit).offset(offset).all()
        total = s.count()
        items = []
        for i in p:
            items.append({
                'id': i.id,
                'user_id': i.user_id,
                'mobiles': json.loads(i.mobiles),
                'content': i.content,
                'date_created': i.date_created.strftime('%Y-%m-%d %H:%M:%S'),
                'date_modified': i.date_modified.strftime('%Y-%m-%d %H:%M:%S'),
                'banned': i.banned})
    except Exception as e:
        logger.exception(e)
        raise
    return jsonify({'total_count': total, 'items': items}), 200


@app.route('/phone/<int:phone_id>', methods=['GET'])
@limiter.limit('5000/hour')
@auth.login_required
def phone_get(phone_id):
    p = Phone.query.filter_by(id=phone_id).first()
    if p is None:
        abort(404)
    result = {
        'id': p.id,
        'user_id': p.user_id,
        'mobiles': json.loads(p.mobiles),
        'content': p.content,
        'date_created': p.date_created.strftime('%Y-%m-%d %H:%M:%S'),
        'date_modified': p.date_modified.strftime('%Y-%m-%d %H:%M:%S'),
        'banned': p.banned
    }
    return jsonify(result), 200


@app.route('/phone/<int:phone_id>', methods=['POST', 'PUT'])
@limiter.limit('5000/hour')
@auth.login_required
def phone_put(phone_id):
    if not request.json:
        return jsonify({'message': 'Problems parsing JSON'}), 415
    
    p = Phone.query.filter_by(id=phone_id).first()
    if p is None:
        abort(404)
    try:
        if request.json.get('mobiles', None) is not None:
            p.mobiles = json.dumps(request.json['mobiles'])
        if request.json.get('content', None) is not None:
            p.content = request.json['content']
        if request.json.get('banned', None) is not None:
            p.banned = request.json['banned']
        p.date_modified = arrow.now('PRC').datetime.replace(tzinfo=None)
        db.session.commit()
    except Exception as e:
        logger.exception(e)
    
    return jsonify(), 204


@app.route('/phone', methods=['POST'])
@limiter.limit('5000/hour')
@auth.login_required
def phone_post():
    if not request.json:
        return jsonify({'message': 'Problems parsing JSON'}), 415
    if not request.json.get('mobiles', None):
        error = {
            'resource': 'phone',
            'field': 'mobiles',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    if not request.json.get('mobiles', None):
        error = {
            'resource': 'phone',
            'field': 'content',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    
    t = arrow.now('PRC').datetime.replace(tzinfo=None)
    p = Phone(user_id=request.json.get('user_id', 1),
              mobiles=json.dumps(request.json['mobiles']),
              content=request.json['content'],
              date_created=t, date_modified=t, banned=0)
    db.session.add(p)
    db.session.commit()

    result = {
        'id': p.id,
        'user_id': p.user_id,
        'mobiles': json.loads(p.mobiles),
        'content': p.content,
        'date_created': p.date_created.strftime('%Y-%m-%d %H:%M:%S'),
        'date_modified': p.date_modified.strftime('%Y-%m-%d %H:%M:%S'),
        'banned': p.banned
    }
    return jsonify(result), 201
