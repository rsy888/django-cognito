import boto3
import botocore
import json
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from awscognito import settings
from rest_framework import exceptions
from django.http import HttpResponse

from .serializers import *
from .models import User

# 회원가입요청
class SignUp(APIView):
    def post(self, request, *ars, **kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)

            user = idp_client.sign_up(ClientId=settings.DEFAULT_USER_POOL_APP_ID,
                                    Username=request.data['user_id'],
                                    Password=request.data['user_password'],
                                    UserAttributes=[{'Name':'email','Value':request.data['user_email']},]
                                    )

            settings.USERNAME=request.data['user_id']
            if(request.data['user_email']==''):
                return HttpResponse("이메일을 입력해주세요")

            serializers=UserSerializer(data=request.data)
            if serializers.is_valid():
                serializers.save()
            return Response(serializers.data,content_type="application/json",status=status.HTTP_201_CREATED)

        except idp_client.exceptions.UsernameExistsException:
            return HttpResponse("이미 존재하는 id입니다.")
        except idp_client.exceptions.InvalidPasswordException:
            return HttpResponse("비밀번호는 최소 6자리, 특수문자, 대문자, 소문자, 숫자를 포함해야합니다.")
        except botocore.exceptions.ParamValidationError:
            return HttpResponse("비밀번호는 최소 6자리, 특수문자, 대문자, 소문자, 숫자를 포함해야합니다.")



# 회원가입 확인
class ConfirmSignUp(APIView):
    def post(self, request, *ars, **kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
            username=''
            if(settings.USERNAME==''):
                username=request.data['username']
            else:
                username=settings.USERNAME

            user = idp_client.confirm_sign_up(ClientId=settings.DEFAULT_USER_POOL_APP_ID,
                                    Username=username,
                                    ConfirmationCode=request.data['code']
                                    )

            return HttpResponse("가입이 완료되었습니다.")

        except botocore.exceptions.ParamValidationError:
            return HttpResponse("다시 시도해주세요")
        except idp_client.exceptions.ExpiredCodeException:
            return HttpResponse("유효하지 않은 코드입니다.")
        except idp_client.exceptions.CodeMismatchException:
            return HttpResponse("올바르지 않은 코드입니다.")

'''
# 이메일 확인
class ConfirmEmail(APIView):
    def post(self, request, *ars, **kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)

            user = idp_client.verify_user_attribute(AccessToken=settings.ACCESS_TOKEN,
                                    AttributeName='email',
                                    Code=request.data['code']
                                    )

            return HttpResponse("이메일이 전송되었습니다.")
        
        except idp_client.exceptions.InvalidParameterException:
            return HttpResponse("로그인이 필요합니다.")
        except idp_client.exceptions.ExpiredCodeException:
            return HttpResponse("유효하지 않은 코드입니다.")
        except idp_client.exceptions.CodeMismatchException:
            return HttpResponse("올바르지 않은 코드입니다.")
'''

# 회원가입 확인 코드 재발급
class GetEmailVerification(APIView):
    def get(self, request, *ars, **kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)

            user = idp_client.confirm_sign_up(ClientId=settings.DEFAULT_USER_POOL_APP_ID,
                                    Username=username
                                    )

            return HttpResponse('%s로 이메일을 보냈습니다'%user['CodeDeliveryDetails']['Destination'])
        except idp_client.exceptions.NotAuthorizedException:
            return HttpResponse("asdf")        


# 로그아웃
class SignOut(APIView):
    def get(self,request, *args, **kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)

            user=idp_client.global_sign_out(AccessToken=settings.ACCESS_TOKEN)

            return HttpResponse("로그아웃 되었습니다.")
        except idp_client.exceptions.NotAuthorizedException:
            return HttpResponse("로그아웃 상태입니다.")

        
# 로그인
class AdminInitiateAuth(APIView):
    def post(self, request, *args, **kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
            ci_client = boto3.client('cognito-identity', **settings.DEFAULT_CONFIG)

            user = idp_client.admin_initiate_auth(UserPoolId=settings.DEFAULT_USER_POOL_ID,
                                        AuthFlow='ADMIN_NO_SRP_AUTH', 
                                        ClientId=settings.DEFAULT_USER_POOL_APP_ID, 
                                        AuthParameters={'USERNAME':request.data['username'], 
                                                        'PASSWORD':request.data['password']}
                                        )

            settings.ACCESS_TOKEN=user["AuthenticationResult"]["AccessToken"]
            # get identity id
            res = ci_client.get_id(AccountId=settings.ACCOUNTID,
                                    IdentityPoolId=settings.IDENTITYPOOLID,
                                    Logins={
                                            settings.DEFAULT_USER_POOL_LOGIN_PROVIDER:user['AuthenticationResult']['IdToken']
                                            }
                                    )
            return Response(data={'user':user,
                                'res':res}, status=status.HTTP_201_CREATED)
        except idp_client.exceptions.NotAuthorizedException:
            return HttpResponse("아이디 또는 비밀번호가 일치하지 않습니다.")
        
'''    
class PublicProviderLogin(APIView):
    def post(self, request, *args, **kwargs):
        token = request.data['token']
        provider = request.data['provider']
        ci_client = boto3.client('cognito-identity', **settings.DEFAULT_CONFIG)
        # check the user if it exists in USER POOL
        
        # get identity id
        res = ci_client.get_id(AccountId=settings.ACCOUNTID,
                                IdentityPoolId=settings.IDENTITYPOOLID,
                                Logins={
                                        provider:token
                                        }
                                )
        return Response(data={'res':res}, status=status.HTTP_201_CREATED)
'''

# 비밀번호 변경        
class ChangePassword(APIView):
    def post(self,request,*args,**kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
            user=idp_client.change_password(PreviousPassword=request.data['OldPassword'],
                                    ProposedPassword=request.data['NewPassword'],
                                    AccessToken=settings.ACCESS_TOKEN
                                    )
            
            return Response(data={'user':user}, status=status.HTTP_201_CREATED)
        except idp_client.exceptions.NotAuthorizedException:
            return HttpResponse("현재 비밀번호가 일치하지 않습니다.")
        except idp_client.exceptions.InvalidPasswordException:
            return HttpResponse("Invalid password")
        except botocore.exceptions.ParamValidationError:
            return HttpResponse("비밀번호는 최소 6자리입니다.")
        except idp_client.exceptions.LimitExceededException:
            return HttpResponse("횟수 초과")
        except idp_client.exceptions.InvalidParameterException:
            return HttpResponse("로그인이 필요합니다.")


# 비밀번호 잊어버렸을 때        
class ForgotPassword(APIView):
    def post(self,request,*args,**kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
            user=idp_client.forgot_password(ClientId=settings.DEFAULT_USER_POOL_APP_ID,
                                    Username=request.data['username']
                                    )

            settings.USERNAME=request.data['username']
            
            return HttpResponse('%s로 이메일을 보냈습니다'%user['CodeDeliveryDetails']['Destination'])
        except idp_client.exceptions.NotAuthorizedException:
            return HttpResponse("asdf")


# 비밀번호 잊어버린 거 Confirm       
class ConfirmForgotPassword(APIView):
    def post(self,request,*args,**kwargs):
        try:
            idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
            user=idp_client.confirm_forgot_password(ClientId=settings.DEFAULT_USER_POOL_APP_ID,
                                    Username=settings.USERNAME,
                                    Password=request.data['newpassword'],
                                    ConfirmationCode=request.data['code']
                                    )
            
            return HttpResponse("비밀번호가 변경되었습니다.")
        except botocore.exceptions.ParamValidationError:
            return HttpResponse("다시 시도해주세요")
        except idp_client.exceptions.ExpiredCodeException:
            return HttpResponse("유효하지 않은 코드입니다.")
        except idp_client.exceptions.CodeMismatchException:
            return HttpResponse("올바르지 않은 코드입니다.")


# 사용자 정보 조회
class RetrieveInfo(APIView):
    def get(self,request,*args,**kwargs):
        try:
             idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
             user=idp_client.get_user(AccessToken=settings.ACCESS_TOKEN)

             return Response(data={'user':user}, status=status.HTTP_201_CREATED)

        except:
            return HttpResponse("로그인이 필요합니다.")


# 사용자 삭제 탈퇴
class DeleteUser(APIView):
    def get(self,request,*args,**kwargs):
        try:
             idp_client = boto3.client('cognito-idp', **settings.DEFAULT_CONFIG)
             user=idp_client.delete_user(AccessToken=settings.ACCESS_TOKEN)

             return HttpResponse("탈퇴 되었습니다.")

        except:
            return HttpResponse("로그인이 필요합니다.")

            