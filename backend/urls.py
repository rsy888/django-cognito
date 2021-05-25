from django.views.generic.base import TemplateView
from django.conf.urls import include, url
from backend import views

urlpatterns = [
    url(r'^sign_up/$', views.SignUp.as_view()),
    url(r'^confirm_sign_up/$',views.ConfirmSignUp.as_view()),
    url(r'^confirm_email/$',views.ConfirmEmail.as_view()),
    url(r'^get_email_verification/$',views.GetEmailVerification.as_view()),
    url(r'^admin_initiate_user/$', views.AdminInitiateAuth.as_view()),
    url(r'^public_provider_login/$', views.PublicProviderLogin.as_view()),
    url(r'^change_password/$', views.ChangePassword.as_view()),
    url(r'^retrieve_info/$', views.RetrieveInfo.as_view())
]