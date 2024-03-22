from django.urls import path
from django.contrib.auth import views as auth_views
from .views import (user_login, user_reg, user_logout, 
                    sent_message, physical_key_authentication, 
                    revoke_key_and_generate_new, show_message,
                    home, show_key, get_received_messages,
                    change_password, get_sended_messages, resend_otp, verify_otp)
from .views import Thankyou


urlpatterns = [
    path('user-reg/', user_reg, name='user_reg'),
    path('user-login/', user_login, name='user_login'),
    path('user-logout/', user_logout, name = 'user_logout'),
    path('thankyou/', Thankyou.as_view(), name='thankyou'),
    path('send-message/', sent_message, name='sent_message'),
    path('physical-key-authentication/', physical_key_authentication),
    path('revoke-and-generate/', revoke_key_and_generate_new, name='revoke_and_generate'), 
    path('show-messages/', show_message, name='show_messages'),
    path('home/', home, name="home"),
    path('show-key/', show_key, name="show_key"),
    path('get-received-messages/', get_received_messages, name='get_received_messages'),
    path('change-password/', change_password, name='change_password'),
    path('get-sended-messages/', get_sended_messages, name='get_sended_messages'),
    path('resend_otp/', resend_otp, name='resend_otp'),
    path('otp_verification/', verify_otp, name='otp_verification')
]
