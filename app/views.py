# -*- coding: utf-8 -*-
import json
from functools import wraps

import arrow
from flask import g, request, make_response, jsonify, abort
from flask_restful import reqparse, abort, Resource
from passlib.hash import sha256_crypt
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

from . import db, app, api, auth, limiter, cache, logger, access_logger
from models import *
from soap_func import SMSClient


@app.route('/')
@limiter.limit("5000/hour")
def index_get():
    result = {
        'user_url': '%suser{/user_id}' % (request.url_root),
        'scope_url': '%sscope' % (request.url_root),
        'sms_url': '%ssms/{sms_id}' % (request.url_root)
    }
    header = {'Cache-Control': 'public, max-age=60, s-maxage=60'}
    return jsonify(result), 200, header


@app.route('/sms/<int:sms_id>', methods=['GET'])
@limiter.limit('5000/hour')
def sms_get(sms_id):
    try:
        sms = SMS.query.filter_by(id=sms_id).first()
        if sms is None:
            abort(404)
        result = {
            'id': sms.id,
            'date_send': sms.date_send.strftime('%Y-%m-%d %H:%M:%S'),
            'mobiles': json.loads(sms.mobiles),
            'content': sms.content,
            'returned_value': sms.returned_value,
            'user_id': sms.user_id,
            'user_info': sms.user_info
        }
        return jsonify(result), 200
    except Exception as e:
        logger.exception(e)


@app.route('/sms', methods=['GET'])
@limiter.limit('5000/hour')
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
            item = {
                'id': i.id,
                'date_send': i.date_send.strftime('%Y-%m-%d %H:%M:%S'),
                'mobiles': json.loads(i.mobiles),
                'content': i.content,
                'returned_value': i.returned_value,
                'user_id': i.user_id,
                'user_info': i.user_info
            }
            items.append(item)
    except Exception as e:
        logger.exception(e)
        raise
    return jsonify({'total_count': total, 'items': items}), 200


@cache.memoize(60)
def get_user_dict():
    user_dict = {}
    user = Users.query.filter_by(banned=0).all()
    for i in user:
        user_dict[i.username] = i.id
    return user_dict


@app.route('/sms', methods=['POST'])
@limiter.limit('5000/hour')
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
    if not request.json.get('user_name', None):
        error = {
            'resource': 'user',
            'field': 'user_name',
            'code': 'missing_field'
        }
        return jsonify({'message': 'Validation Failed', 'errors': error}), 422
    try:
        sms_client = SMSClient(**app.config['SMS_WSDL_PARAMS'])
        sms_client.sms_init()
        user_id = get_user_dict().get(request.json['user_name'], 0)
        user_info = request.json.get('user_info', '')
        r = sms_client.sms_send(
            request.json['mobiles'], request.json['content'], user_id % 10000)
        sms = SMS(mobiles=json.dumps(request.json['mobiles']), user_id=user_id,
                  content=request.json['content'], user_info=user_info,
                  returned_value=r)
        db.session.add(sms)
        db.session.commit()
        del sms_client

        result = {
            'id': sms.id,
            'date_send': sms.date_send.strftime('%Y-%m-%d %H:%M:%S'),
            'mobiles': json.loads(sms.mobiles),
            'content': sms.content,
            'user_id': sms.user_id,
            'user_info': sms.user_info,
            'returned_value': sms.returned_value
        }
        if sms.returned_value == 0:
            result['succeed'] = True
        else:
            result['succeed'] = False
        return jsonify(result), 201
    except Exception as e:
        logger.exception(e)
        raise


