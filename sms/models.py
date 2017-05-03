# -*- coding: utf-8 -*-
import arrow

from . import db


class Users(db.Model):
    """用户"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), index=True)
    password = db.Column(db.String(255))
    scope = db.Column(db.String(255), default='')
    date_created = db.Column(
        db.DateTime, default=arrow.now('PRC').datetime.replace(tzinfo=None))
    date_modified = db.Column(
        db.DateTime, default=arrow.now('PRC').datetime.replace(tzinfo=None))
    banned = db.Column(db.Integer, default=0)

    def __init__(self, username, password, scope='', date_created=None,
                 date_modified=None, banned=0):
        self.username = username
        self.password = password
        self.scope = scope
        now = arrow.now('PRC').datetime.replace(tzinfo=None)
        if date_created is None:
            self.date_created = now
        else:
            self.date_created = date_created
        if date_modified is None:
            self.date_modified = now
        else:
            self.date_modified = date_modified
        self.banned = banned

    def __repr__(self):
        return '<Users %r>' % self.id


class Scope(db.Model):
    """权限范围"""
    __tablename__ = 'scope'

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(64), unique=True)

    def __init__(self, name):
        self.name = name

    def __repr__(self):
        return '<Scope %r>' % self.id


class SMS(db.Model):
    """短信记录"""
    __tablename__ = 'sms'

    id = db.Column(db.Integer, primary_key=True)
    date_send = db.Column(
        db.DateTime, default=arrow.now('PRC').datetime.replace(tzinfo=None))
    mobiles = db.Column(db.String(255), default='[]')
    content = db.Column(db.Text, default='')
    returned_value = db.Column(db.Integer, default=-99)
    user_id = db.Column(db.Integer, default=1)

    def __init__(self, date_send=None, mobiles='[]', content='',
                 returned_value=-99, user_id=0):
        if date_send is None:
            self.date_send = arrow.now('PRC').datetime.replace(tzinfo=None)
        else:
            self.date_send = date_send
        self.mobiles = mobiles
        self.content = content
        self.returned_value = returned_value
        self.user_id = user_id
        
    def __repr__(self):
        return '<SMS %r>' % self.id


class Phone(db.Model):
    """短信记录"""
    __tablename__ = 'phone'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, default=1)
    mobiles = db.Column(db.Text, default='[]')
    content = db.Column(db.Text, default='')
    date_created = db.Column(
        db.DateTime, default=arrow.now('PRC').datetime.replace(tzinfo=None))
    date_modified = db.Column(
        db.DateTime, default=arrow.now('PRC').datetime.replace(tzinfo=None))
    banned = db.Column(db.Integer, default=0)

    def __init__(self, user_id=1, mobiles='[]', content='', date_created=None,
                 date_modified=None, banned=0):
        self.user_id = user_id
        self.mobiles = mobiles
        self.content = content
        now = arrow.now('PRC').datetime.replace(tzinfo=None)
        if date_created is None:
            self.date_created = now
        else:
            self.date_created = date_created
        if date_modified is None:
            self.date_modified = now
        else:
            self.date_modified = date_modified
        self.banned = banned
        
    def __repr__(self):
        return '<Phone %r>' % self.id

