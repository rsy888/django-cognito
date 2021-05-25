#AWS COGNITO CREDENTIALS
import os,json
from django.core.exceptions import ImproperlyConfigured

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
secret_file = os.path.join(BASE_DIR, 'secret.json')

#secret key 가져옴
with open(secret_file) as f:
    secret = json.loads(f.read())

def get_secret(setting, secret=secret):
    try:
        return secret[setting]
    except KeyError:
        error_msg = "Set the {} environment variable".format(setting)
        raise ImproperlyConfigured(error_msg)

IDENTITYPOOLID = 'us-east-2:5a5986ad-f054-48c7-8337-0396e6fd3496'

ACCOUNTID = '567931695461'

AWS_ACCESS_KEY = 'AKIAYIO256FSWLO5VG7B'

AWS_SECRET_KEY = get_secret("SECRET_KEY")

DEFAULT_REGION_NAME = 'us-east-2'

DEFAULT_USER_POOL_ID = 'us-east-2_2PGVI8TUz'

DEFAULT_USER_POOL_APP_ID = '6kcc83isa7pkoj3ul3nk6lt7sm' #APP should not have any secret in AWS

DEFAULT_CONFIG = {'region_name':DEFAULT_REGION_NAME, 'aws_access_key_id':AWS_ACCESS_KEY, 'aws_secret_access_key':AWS_SECRET_KEY}

DEFAULT_USER_POOL_LOGIN_PROVIDER = 'cognito-idp.%s.amazonaws.com/%s' % (DEFAULT_REGION_NAME, DEFAULT_USER_POOL_ID)

ACCESS_TOKEN=''

USERNAME=''