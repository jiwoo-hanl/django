# accounts/views.py
from django.contrib.auth.models import User 
from django.contrib import auth 
from rest_framework import status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken, AccessToken
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.token_blacklist.models import BlacklistedToken

from .serializers import UserSerializer, UserInfoSerializer, UserProfileSerializer, UserIdUsernameSerializer
from .models import UserProfile

def set_token_on_response_cookie(user:User) -> Response:
    token = RefreshToken.for_user(user)
    user_profile = UserProfile.objects.get(user=user)
    user_profile_serializer = UserProfileSerializer(user_profile)
    res = Response(user_profile_serializer.data, status=status.HTTP_200_OK)
    res.set_cookie('refresh_token', value=str(token))
    res.set_cookie('access_token', value=str(token.access_token))
    return res



class SignupView(APIView):
    def post(self, request):
        print(request.user)
        college=request.data.get('college')
        major=request.data.get('major')

        user_serialier = UserSerializer(data=request.data)
        if user_serialier.is_valid(raise_exception=True):
            user = user_serialier.save()
            
        user_profile = UserProfile.objects.create(
            user=user,
            college=college,
            major=major
        ) 
        return set_token_on_response_cookie(user)
        
class SigninView(APIView):
    def post(self, request):
        try:
            user = User.objects.get(
                username=request.data['username'],
                password=request.data['password']
            )
        except:
            return Response({"detail": "아이디 또는 비밀번호를 확인해주세요."}, status=status.HTTP_400_BAD_REQUEST)
        return set_token_on_response_cookie(user)
        
class LogoutView(APIView):
    def post(self, request):
        if not request.user.is_authenticated:
            return Response({"detail": "로그인 후 다시 시도해주세요."}, status=status.HTTP_401_UNAUTHORIZED)
        RefreshToken(request.data['refresh']).blacklist()
        return Response(status=status.HTTP_204_NO_CONTENT)      
        
class TokenRefreshView(APIView):
    def post(self, request):
        is_access_token_valid = request.user.is_authenticated
        refresh_token = request.data['refresh']
        try:
            RefreshToken(refresh_token).verify()
            is_refresh_token_blacklisted = True
        except:
            is_refresh_token_blacklisted = False
        if not is_access_token_valid :  
            if not is_refresh_token_blacklisted:
                return Response({"detail": "login 을 다시 해주세요."}, status=status.HTTP_401_UNAUTHORIZED)
            else:
                new_access_token = str(RefreshToken(refresh_token).access_token)
        else:
            user = request.user
            token = AccessToken.for_user(user)
            new_access_token = str(token)
        response = Response({"detail": "token refreshed"}, status=status.HTTP_200_OK)
        return response.set_cookie('access_token', value=str(new_access_token))
    
class UserInfoView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({"detail": "로그인 후 다시 시도해주세요."}, status=status.HTTP_401_UNAUTHORIZED)
        user = request.user

        serializer = UserProfileSerializer(user)
        print(serializer.data)
    
        return Response(serializer.data, status=status.HTTP_200_OK)
    
class MyPageView(APIView):
    def get(self, request):
        if not request.user.is_authenticated:
            return Response({"detail": "로그인 후 다시 시도해주세요."}, status=status.HTTP_401_UNAUTHORIZED)
        user = request.user
        profile = UserProfile.objects.get(user=user)
        print(profile, "hi!")
        if not profile:
            return Response({"No profl"})
        serializer = UserProfileSerializer(profile)
        
        return Response(serializer.data, status=status.HTTP_200_OK)
    

    def patch(self, request):

        if not request.user.is_authenticated:
            return Response({"detail": "Authentication credentials not provided"}, status=status.HTTP_401_UNAUTHORIZED)

        try:
            user_info = UserProfile.objects.get(user=request.user)
        except:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)
        print(request.data)
        user = User.objects.get(id=request.user.id)
        serializer_user = UserSerializer(user, data=request.data, partial = True)
        serializer_profile = UserProfileSerializer(user_info, data=request.data, partial=True)
        if not serializer_profile.is_valid():
            return Response({"detail": "data validation error"}, status=status.HTTP_400_BAD_REQUEST)
        
        if not serializer_user.is_valid():
            return Response({"detail": "data validation error"}, status=status.HTTP_400_BAD_REQUEST)
        serializer_user.save()
        serializer_profile.save()
        return Response(serializer_profile.data, status=status.HTTP_200_OK)
    
    
    
    # def patch(self, request, user_id):
        try:
            user = UserProfile.objects.get(user=user)
        except:
            return Response({"detail": "Not found."}, status=status.HTTP_404_NOT_FOUND)

        if request.user != user:
            return Response({"detail": "Permission denied"}, status=status.HTTP_401_UNAUTHORIZED)
        serializer = PostSerializer(post, data=request.data, partial=True)


        if not serializer.is_valid():
            return Response({"detail": "data validation error"}, status=status.HTTP_400_BAD_REQUEST)
        serializer.save()
        return Response(serializer.data, status=status.HTTP_200_OK)
    