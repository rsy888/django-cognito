#AWS COGNITO CREDENTIALS

IDENTITYPOOLID = 'us-east-2:5a5986ad-f054-48c7-8337-0396e6fd3496'

ACCOUNTID = '567931695461'

AWS_ACCESS_KEY = 'AKIAYIO256FSWLO5VG7B'

AWS_SECRET_KEY = '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'

DEFAULT_REGION_NAME = 'us-east-2'

DEFAULT_USER_POOL_ID = 'us-east-2_2PGVI8TUz'

DEFAULT_USER_POOL_APP_ID = '6kcc83isa7pkoj3ul3nk6lt7sm' #APP should not have any secret in AWS

DEFAULT_CONFIG = {'region_name':DEFAULT_REGION_NAME, 'aws_access_key_id':AWS_ACCESS_KEY, 'aws_secret_access_key':AWS_SECRET_KEY}

DEFAULT_USER_POOL_LOGIN_PROVIDER = 'cognito-idp.%s.amazonaws.com/%s' % (DEFAULT_REGION_NAME, DEFAULT_USER_POOL_ID)

ACCESS_TOKEN=''

USERNAME=''