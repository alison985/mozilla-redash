from functools import wraps
#from urllib.parse import urlparse
#from os import environ as env, path
import json

from auth0.v3.authentication import GetToken
from auth0.v3.authentication import Users
#from dotenv import load_dotenv

import logging
import requests
from flask import Flask, render_template, send_from_directory, redirect, url_for, Blueprint, flash, request, session
from flask_login import login_user
from flask_oauthlib.client import OAuth
from sqlalchemy.orm.exc import NoResultFound

from redash import models, settings
from redash.authentication.org_resolving import current_org
from redash.authentication.google_oauth import create_and_login_user

logger = logging.getLogger('auth0_oauth')

oauth = OAuth()
blueprint = Blueprint('auth0_oauth', __name__)

def auth0_remote_app():
    if 'auth0_oauth' not in oauth.remote_apps:
        oauth.remote_app('auth0_oauth',
                         base_url=settings.AUTH0_CALLBACK_URL,
                         authorize_url=settings.AUTH0_CALLBACK_URL,
                         #request_token_url=None,
                         #request_token_params={
                         #    'scope': 'https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile',
                         #},
                         access_token_url=settings.AUTH0_DOMAIN,
                         access_token_method='POST',
                         consumer_key=settings.AUTH0_CLIENT_ID,
                         consumer_secret=settings.AUTH0_CLIENT_SECRET
                         )

    return oauth.auth0_oauth

#def get_user_profile(access_token):
#    headers = {'Authorization': 'OAuth {}'.format(access_token)}
#    response = requests.get('https://www.googleapis.com/oauth2/v1/userinfo', headers=headers)
#
#    if response.status_code == 401:
#        logger.warning("Failed getting user profile (response code 401).")
#        return None
#
#    return response.json()

def verify_profile(org, profile):
    if org.is_public:
        return True

    email = profile['email']
    domain = email.split('@')[-1]

    #if domain in org.google_apps_domains:
    #    return True

    if org.has_user(email) == 1:
        return True

    return False


@blueprint.route('/<org_slug>/oauth/auth0', endpoint="authorize_org")
def org_login(org_slug):
    session['org_slug'] = current_org.slug
    return redirect(url_for(".authorize", next=request.args.get('next', None)))


@blueprint.route('/oauth/auth0', endpoint="authorize")
def login():
    callback = url_for('.callback', _external=True)
    next_path = request.args.get('next', url_for("redash.index", org_slug=session.get('org_slug')))
    logger.debug("Callback url: %s", callback)
    logger.debug("Next is: %s", next_path)
    return auth0_remote_app().authorize(callback=callback, state=next_path)


@blueprint.route('/oauth/auth0_callback', endpoint="callback")
def authorized():
    code = request.args.get(constants.CODE_KEY)
    get_token = GetToken(settings.AUTH0_DOMAIN)
    auth0_users = Users(settings.AUTH0_DOMAIN)
    token = get_token.authorization_code(settings.AUTH0_CLIENT_ID,
                                         settings.AUTH0_CLIENT_SECRET, code, settings.AUTH0_CALLBACK_URL)
    user_info = auth0_users.userinfo(token['access_token'])
    user_info_array = json.loads(user_info)
    create_and_login_user(org, user_info_array['name'], user_info_array['email'])

    next_path = request.args.get('state') or url_for("redash.index", org_slug=org.slug)

    return redirect(next_path)
