# -*- coding: utf-8 -*-
"""
Settings for bruteforce_defender application
"""
from django.conf import settings

REDIS_HOST = getattr(settings, 'REDIS_HOST', 'localhost')
REDIS_PORT = getattr(settings, 'REDIS_PORT', 6379)
REDIS_PASSWORD = getattr(settings, 'REDIS_PASSWORD', '')
REDIS_DB = getattr(settings, 'DF_REDIS_DB', 0)

LOGIN_ATTEMPTS = getattr(settings, 'LOGIN_ATTEMPTS', 10)
BLOCKING_TIME = getattr(settings, 'BLOCKING_TIME', 10*60) # 10min = 600sec
