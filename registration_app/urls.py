from django.urls import path
from .views import UserRegistrationAPIView, LoginAPIView, EventListAPIView
from rest_framework_simplejwt.views import (TokenRefreshView)

urlpatterns = [
    path('user-register/', UserRegistrationAPIView.as_view(),
         name='user_registration'),
    path('login/', LoginAPIView.as_view(), name='user_login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('events/', EventListAPIView.as_view(), name='event_listing'),
]
