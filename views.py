# accounts/views.py
from rest_framework import generics, status, permissions
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import RegisterSerializer,LoginSerializer,LogoutSerializer,PasswordResetRequestSerializer,PasswordResetConfirmSerializer,ActivateUserSerializer
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes,force_str
from django.utils.http import urlsafe_base64_encode,urlsafe_base64_decode
from django.core.mail import send_mail
from django.contrib.auth.tokens import default_token_generator

User = get_user_model()

class RegisterView(generics.CreateAPIView):
    serializer_class = RegisterSerializer
    permission_classes = [permissions.AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()

        refresh = RefreshToken.for_user(user)
        tokens = {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }

        return Response({
            "message": "ثبت‌ نام موفق بود.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name
            },
            "tokens": tokens
        }, status=status.HTTP_201_CREATED)

class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.validated_data['user']

        refresh = RefreshToken.for_user(user)
        tokens = {
            "refresh": str(refresh),
            "access": str(refresh.access_token)
        }

        return Response({
            "message": "ورود موفق بود.",
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "first_name": user.first_name,
                "last_name": user.last_name
            },
            "tokens": tokens
        })
               
class LogoutView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        serializer = LogoutSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        refresh_token = serializer.validated_data["refresh"]

        try:
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response({"message": "خروج با موفقیت انجام شد."})
        except Exception:
            return Response({"error": "توکن نامعتبر یا منقضی شده است."}, status=status.HTTP_400_BAD_REQUEST)

class PasswordResetRequestView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        serializer = PasswordResetRequestSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data["email"]

        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({"message": "اگر ایمیل موجود باشد، لینک تغییر رمز ارسال می‌شود."})

        uid = urlsafe_base64_encode(force_bytes(user.pk))
        token = default_token_generator.make_token(user)
        reset_link = f"http://localhost:8000/api/accounts/reset-password-confirm/{uid}/{token}/"

        send_mail(
            subject="بازیابی رمز عبور",
            message=f"برای تغییر رمز روی لینک زیر کلیک کنید:\n{reset_link}",
            from_email="noreply@example.com",
            recipient_list=[user.email],
            fail_silently=False
        )

        return Response({"message": "اگر ایمیل موجود باشد، لینک تغییر رمز ارسال می‌شود."})
       
class PasswordResetConfirmView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request, uidb64, token):
        serializer = PasswordResetConfirmSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=uid)
        except:
            return Response({"error": "لینک نامعتبر است."}, status=status.HTTP_400_BAD_REQUEST)

        if not default_token_generator.check_token(user, token):
            return Response({"error": "توکن نامعتبر یا منقضی شده است."}, status=status.HTTP_400_BAD_REQUEST)

        user.set_password(serializer.validated_data['new_password'])
        user.save()
        return Response({"message": "رمز عبور با موفقیت تغییر کرد."})
    
class ActivateUserView(APIView):
    permission_classes = [permissions.AllowAny]

    def get(self, request, uidb64, token):
        serializer = ActivateUserSerializer(data={"uidb64": uidb64, "token": token})
        serializer.is_valid(raise_exception=True)

        try:
            uid = force_str(urlsafe_base64_decode(serializer.validated_data['uidb64']))
            user = User.objects.get(pk=uid)
        except (TypeError, ValueError, OverflowError, User.DoesNotExist):
            return Response({"error": "لینک فعال‌سازی نامعتبر است."}, status=status.HTTP_400_BAD_REQUEST)

        if user.is_active:
            return Response({"message": "حساب شما قبلاً فعال شده است."})

        if default_token_generator.check_token(user, serializer.validated_data['token']):
            user.is_active = True
            user.save()

            refresh = RefreshToken.for_user(user)
            tokens = {
                "refresh": str(refresh),
                "access": str(refresh.access_token)
            }

            return Response({
                "message": "حساب کاربری شما با موفقیت فعال شد.",
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "first_name": user.first_name,
                    "last_name": user.last_name
                },
                "tokens": tokens
            }, status=status.HTTP_200_OK)

        return Response({"error": "لینک فعال‌سازی نامعتبر یا منقضی شده است."}, status=status.HTTP_400_BAD_REQUEST)