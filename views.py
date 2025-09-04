from django.contrib.auth import authenticate
from rest_framework.authtoken.models import Token
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework.decorators import api_view, authentication_classes, permission_classes
from rest_framework.authentication import TokenAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken, TokenError
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode
from django.contrib.auth.models import User
from django.utils.encoding import force_bytes
from .emails import send_reset_password_email
from django.utils.http import urlsafe_base64_decode

@api_view(['POST'])
@permission_classes([AllowAny])
def register_view(request):
    username = request.data.get("username")
    email = request.data.get("email")
    password = request.data.get("password")

    if not username or not password or not email:
        return Response({"error": "نام کاربری، ایمیل و رمز عبور الزامی است."},
                        status=status.HTTP_400_BAD_REQUEST)

    if len(password) < 6:
        return Response({"error": "رمز عبور باید حداقل 6 کاراکتر باشد."},
                        status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(username=username).exists():
        return Response({"error": "این نام کاربری قبلاً استفاده شده است."},
                        status=status.HTTP_400_BAD_REQUEST)

    if User.objects.filter(email=email).exists():
        return Response({"error": "این ایمیل قبلاً استفاده شده است."},
                        status=status.HTTP_400_BAD_REQUEST)

    user = User.objects.create_user(username=username, email=email, password=password)

    refresh = RefreshToken.for_user(user)
    return Response({
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email,
        },
        "tokens": {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
    }, status=status.HTTP_201_CREATED)

@api_view(['GET'])
@authentication_classes([TokenAuthentication])
@permission_classes([IsAuthenticated])
def secure_endpoint(request):
    user = request.user
    return Response({
        "message": f"Hello, {user.username}. You are authenticated!"
    })

@api_view(['POST'])
@permission_classes([AllowAny]) 
def login_view(request):
    username = request.data.get("username")
    password = request.data.get("password")

    if not username or not password:
        return Response(
            {"error": "نام کاربری و رمز عبور الزامی است."},
            status=status.HTTP_400_BAD_REQUEST
        )

    user = authenticate(username=username, password=password)
    if user is not None:
        refresh = RefreshToken.for_user(user)
        return Response({
            "user": {
                "id": user.id,
                "username": user.username,
                "email": user.email,
            },
            "tokens": {
                "refresh": str(refresh),
                "access": str(refresh.access_token),
            }
        })
    else:
        return Response(
            {"error": "نام کاربری یا رمز عبور اشتباه است."},
            status=status.HTTP_401_UNAUTHORIZED
        )
        
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_view(request):
    try:
        refresh_token = request.data.get("refresh")
        if not refresh_token:
            return Response({"error": "Refresh token الزامی است."},
                            status=status.HTTP_400_BAD_REQUEST)

        token = RefreshToken(refresh_token)
        token.blacklist()

        return Response({"message": "خروج موفقیت‌آمیز بود."},
                        status=status.HTTP_205_RESET_CONTENT)
    except TokenError:
        return Response({"error": "توکن معتبر نیست یا قبلاً بلاک شده است."},
                        status=status.HTTP_400_BAD_REQUEST)
    except Exception as e:
        return Response({"error": "خطایی رخ داد."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
    
@api_view(['POST'])
@permission_classes([IsAuthenticated])
def logout_all_view(request):
    try:
        tokens = RefreshToken.for_user(request.user)
        request.user.auth_token_set.all().delete()
        return Response({"message": "خروج از تمام دستگاه‌ها انجام شد."},
                        status=status.HTTP_205_RESET_CONTENT)
    except Exception as e:
        return Response({"error": "خطایی رخ داد."},
                        status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_request_view(request):
    email = request.data.get("email")

    if not email:
        return Response({"error": "ایمیل الزامی است."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        user = User.objects.get(email=email)
    except User.DoesNotExist:
        return Response({"error": "کاربری با این ایمیل پیدا نشد."}, status=status.HTTP_404_NOT_FOUND)


    uid = urlsafe_base64_encode(force_bytes(user.pk))
    token = default_token_generator.make_token(user)

    reset_link = f"http://localhost:8000/reset-password-confirm/{uid}/{token}/"

    
    send_reset_password_email(user, reset_link)

    return Response({"message": "ایمیل بازیابی ارسال شد."}, status=status.HTTP_200_OK)

@api_view(["POST"])
@permission_classes([AllowAny])
def password_reset_confirm_view(request, uid, token):
    new_password = request.data.get("new_password")

    if not new_password:
        return Response({"error": "رمز عبور جدید الزامی است."}, status=status.HTTP_400_BAD_REQUEST)

    try:
        uid = urlsafe_base64_decode(uid).decode()
        user = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        return Response({"error": "کاربر معتبر نیست."}, status=status.HTTP_400_BAD_REQUEST)

    if not default_token_generator.check_token(user, token):
        return Response({"error": "توکن معتبر نیست یا منقضی شده است."}, status=status.HTTP_400_BAD_REQUEST)

    user.set_password(new_password)
    user.save()

    return Response({"message": "رمز عبور با موفقیت تغییر یافت."}, status=status.HTTP_200_OK)