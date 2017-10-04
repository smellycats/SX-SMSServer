# -*- coding: utf-8 -*-
import arrow

from . import db


class Users(db.Model):
    """用户"""
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), index=True)
    banned = db.Column(db.Integer, default=0)

    def __init__(self, username, banned=0):
        self.username = username
        self.banned = banned

    def __repr__(self):
        return '<Users %r>' % self.id


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
    user_info = db.Column(db.String(32), default='')

    def __init__(self, date_send=None, mobiles='[]', content='',
                 returned_value=-99, user_id=0, user_info=''):
        if date_send is None:
            self.date_send = arrow.now('PRC').datetime.replace(tzinfo=None)
        else:
            self.date_send = date_send
        self.mobiles = mobiles
        self.content = content
        self.returned_value = returned_value
        self.user_id = user_id
        self.user_info = user_info
        
    def __repr__(self):
        return '<SMS %r>' % self.id


