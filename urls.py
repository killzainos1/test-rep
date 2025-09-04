from django.urls import path
from .views import RegisterView,LogoutView,LoginView,PasswordResetRequestView,PasswordResetConfirmView,ActivateUserView

urlpatterns = [
    path("register/", RegisterView.as_view(), name="register"),
    path("login/", LoginView.as_view(), name="login"),
    path("logout/", LogoutView.as_view(), name="logout"),
    path("reset-password/", PasswordResetRequestView.as_view(), name="password_reset"),
    path("reset-password-confirm/<uidb64>/<token>/", PasswordResetConfirmView.as_view(), name="password_reset_confirm"),
    path("activate/<uidb64>/<token>/", ActivateUserView.as_view(), name="activate_user"),

]