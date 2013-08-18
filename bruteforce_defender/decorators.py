# -*- coding: utf-8 -*-
"""
Decorator for bruteforce_defender application.
"""
from __future__ import unicode_literals
import redis

from django.contrib import messages
from django.contrib.auth import authenticate
from django.http import HttpResponseRedirect

from bruteforce_defender.settings import (REDIS_HOST, REDIS_PORT,
    REDIS_PASSWORD, REDIS_DB, LOGIN_ATTEMPTS, BLOCKING_TIME)


message = "You exceeded the maximum allowed number of login attempts. Try again later"

server = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB,
    password=REDIS_PASSWORD)


def protect(login):
    def wrapper(request):
        try:
            # get data from request
            ip = request.META['REMOTE_ADDR']
            username = request.POST['username']
            password = request.POST['password']
        except KeyError:
            return login(request)

        # key for redis
        key = "{ip}:{username}".format(ip=ip, username=username)

        login_attempts = server.get(key)

        if login_attempts is not None and \
                int(login_attempts) >= LOGIN_ATTEMPTS:
            # if the user has exceeded count of login attempts
            # show him the message and redirect to home page
            messages.error(request, message)
            return HttpResponseRedirect("/")
        else:
            # try to authenticate user with credentials
            user = authenticate(username=username, password=password)
            # if credentials are wrong, increment login attempts counter
            # otherwise delete key from redis
            if user is None:
                server.incr(key, 1)
                server.expire(key, BLOCKING_TIME)
            else:
                server.delete(key)

        return login(request)

    return wrapper
