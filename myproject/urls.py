"""
URL configuration for myproject project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path 
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from useraccount.views import RegisterView , LoginView , ProfileView , register_page , login_page , profile_page , token_send , success , forgot_password , reset_password
from useraccount.views import VerifyEmailView , LogoutView , ForgotPasswordView , ResetPasswordView
from django.conf.urls.static import static
from django.conf import settings


urlpatterns = [
    path('admin/', admin.site.urls),
    path('api/register/',RegisterView.as_view(),name ='auth_register'),
    path('api/token/', TokenObtainPairView.as_view(), name='token_obtain_pair'),
    path('api/token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('api/login/', LoginView.as_view(), name='login'),
    path('api/profile/', ProfileView.as_view(), name='profile'),
    path('api/logout/',LogoutView.as_view(), name='logout'),
    path('verify-email/<uidb64>/<token>/', VerifyEmailView.as_view(), name='verify-email'),
    path("forgot_password/", ForgotPasswordView.as_view(), name="forgot-password"),
    path("reset-password/<uid>/<token>/", ResetPasswordView.as_view(), name="reset-password"),
    
    
    
    #html pages
    path('register-page/', register_page),
    path('login-page/', login_page),
    path('profile-page/', profile_page),
    path('token/', token_send , name='token_send'),
    path('success/', success , name='success'),
    path('forgot-password/', forgot_password , name='forgot_password'),
    path('reset-password/', reset_password , name='reset_password')
]


urlpatterns+= static(settings.MEDIA_URL,document_root= settings.MEDIA_ROOT)