from django.urls import path
from backend import views

urlpatterns = [
    path('sign_up/', views.SignUp.as_view()),
    path('sign_out/',views.SignOut.as_view()),
    path('confirm_sign_up/',views.ConfirmSignUp.as_view()),
    path('get_email_verification/',views.GetEmailVerification.as_view()),
    path('admin_initiate_user/', views.AdminInitiateAuth.as_view()),
    path('change_password/', views.ChangePassword.as_view()),
    path('forgot_password/', views.ForgotPassword.as_view()),
    path('confirm_forgot_password/',views.ConfirmForgotPassword().as_view()),
    #path('retrieve_info/', views.RetrieveInfo.as_view()),
    path('delete_user/', views.DeleteUser.as_view())
]