from django.urls import path
from .views import UserRegistrationAPIView, LoginAPIView, EventListAPIView, EventRegistrationAPIView, EventCreateAPIView, CancelEventRegistrationView
from rest_framework_simplejwt.views import (TokenRefreshView)

urlpatterns = [
    path('user-register/', UserRegistrationAPIView.as_view(),
         name='user_registration'),
    path('login/', LoginAPIView.as_view(), name='user_login'),
    path('token/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('events/', EventListAPIView.as_view(), name='event_listing'),
    path('event-register/', EventRegistrationAPIView.as_view(),
         name='event_register'),
    path('create-event/', EventCreateAPIView.as_view(),
         name='create_event'),
    path('cancel-event-registration/<int:pk>/',
         CancelEventRegistrationView.as_view(), name='cancel_event_registration'),
]
