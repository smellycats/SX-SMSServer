# -*- coding: utf-8 -*-
import json

import arrow

from sms import db
from sms.models import SMS


def sms_add():
    mobiles = ['709394', '178902']
    sms = SMS(date_send=arrow.now().datetime,
              mobiles=json.dumps(mobiles),
              content=u'死肥仔',
              returned_value=0,
              user_id=3)
    db.session.add(sms)
    db.session.commit()
    print sms.id

def sms_get():
    sms = SMS.query.all()
    for i in sms:
        print i.mobiles


if __name__ == '__main__':
    #sms_add()
    sms_get()
