from django.urls import path
from .views import login_view, logout_view, logout_all_view, secure_endpoint,password_reset_request_view, password_reset_confirm_view,register_view,activate_user

urlpatterns = [
    path('register/', register_view, name='register'),
    path("login/", login_view, name="login"),
    path("logout/", logout_view, name="logout"),
    path("logout-all/", logout_all_view, name="logout_all"),  
    path("secure/", secure_endpoint, name="secure"),
    path("password-reset/", password_reset_request_view, name="password_reset"),
    path("reset-password-confirm/<uid>/<token>/", password_reset_confirm_view, name="password_reset_confirm"),
    path("activate/<uidb64>/<token>/", activate_user, name="activate_user"),
]