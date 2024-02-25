from django.contrib.auth.models import User
from django.http import Http404
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework_simplejwt.tokens import RefreshToken
from drf_yasg.utils import swagger_auto_schema
from drf_yasg import openapi
from .models import Registration, Event
from .serializers import (
    RegisterSerializer,
    LoginSerializer,
    ProfileSerializer,
    EventSerializer,
    EventRegistrationSerializer,
    BasicEventRegistrationSerializer
)
from .utils import formatted_response
from .permissions import IsAdminOrReadOnly


class UserRegistrationAPIView(APIView):
    """
    API endpoint for user registration.

    This endpoint allows users to register by providing necessary information.
    Upon successful registration, it returns an access token and a refresh token.

    Request:
        - POST request with the following parameters in the request body:
            - username (str): The desired username for the user.
            - email (str): The email address of the user.
            - password (str): The password for the user account.
            - password2 (str): Confirmation of the password.
            - first_name (str): The first name of the user.
            - last_name (str): The last name of the user.

    Response:
        - If the registration is successful, it returns a 201 Created status along with:
            - 'success': True
            - 'message': "User registered successfully"
            - 'data':
                - 'token':
                    - 'refresh': Refresh token as a string
                    - 'access': Access token as a string
                - 'profile': Serialized user profile data

        - If the registration fails due to validation errors or other issues, it returns a 400 Bad Request status along with:
            - 'success': False
            - 'message': "User registration unsuccessful"
            - 'data': Detailed error information, if applicable.
    """
    @swagger_auto_schema(request_body=RegisterSerializer)
    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                refresh = RefreshToken.for_user(user)
                profile_data = ProfileSerializer(user).data
                token_data = {
                    'token': {
                        'refresh': str(refresh),
                        'access': str(refresh.access_token)
                    },
                    'profile': profile_data
                }
                return formatted_response(status=status.HTTP_201_CREATED, success=True, message="User registered successfully", data=token_data)
        return formatted_response(status=status.HTTP_400_BAD_REQUEST, success=False, message="User registration unsuccessful", data=serializer.errors)


class LoginAPIView(APIView):
    """
    API endpoint for user login.

    This endpoint allows users to log in by providing their username and password.
    Upon successful login, it returns an access token and a refresh token, along with user profile data.

    Request:
        - POST request with the following parameters in the request body:
            - username (str): The username of the user.
            - password (str): The password for the user account.

    Response:
        - If the login is successful, it returns a 200 OK status along with:
            - 'success': True
            - 'message': "User login successful"
            - 'data':
                - 'token':
                    - 'refresh': Refresh token as a string
                    - 'access': Access token as a string
                - 'profile': Serialized user profile data

        - If the login fails due to invalid credentials or other issues, it returns a 400 Bad Request status along with:
            - 'success': False
            - 'message': "User login unsuccessful"
            - 'data': Detailed error information, if applicable.
    """
    @swagger_auto_schema(request_body=LoginSerializer)
    def post(self, request, *args, **kwargs):
        serializer = LoginSerializer(data=request.data)
        if serializer.is_valid():
            username = serializer.validated_data['username']
            user = User.objects.get(username=username)

            refresh = RefreshToken.for_user(user)
            profile_data = ProfileSerializer(user).data
            response_data = {
                'token': {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                },
                'profile': profile_data
            }
            return formatted_response(status=status.HTTP_200_OK, success=True, message="User login successful", data=response_data)
        return formatted_response(status=status.HTTP_400_BAD_REQUEST, success=False, message="User login unsuccessful", data=serializer.errors)


class EventListAPIView(APIView):
    """
    API endpoint for listing events.

    This endpoint retrieves and returns a list of events available for registration.

    Response:
        - GET request returns a 200 OK status along with:
            - 'success': True
            - 'message': "Event listing successful"
            - 'data': Serialized list of events using the EventSerializer
    """

    def get(self, request, *args, **kwargs):
        events = Event.objects.all()
        serializer = EventSerializer(events, many=True)
        return formatted_response(status=status.HTTP_200_OK, success=True, message="Event listing successful", data=serializer.data)


class EventDetailAPIView(APIView):
    """
    API endpoint for retrieving details of a specific event.

    This endpoint retrieves and returns detailed information about a specific event identified by its id.

    Request:
        - GET request with the event's id  as a parameter.

    Response:
        - If the event is found, it returns a 200 OK status along with:
            - 'success': True
            - 'message': "Event retrieval successful"
            - 'data': Serialized details of the specified event using the EventSerializer

        - If the event with the given id does not exist, it returns a 404 Not Found status.
    """

    def get_object(self, pk):
        try:
            return Event.objects.get(pk=pk)
        except Event.DoesNotExist:
            raise Http404

    def get(self, request, pk, *args, **kwargs):
        event = self.get_object(pk)
        serializer = EventSerializer(event)
        return formatted_response(status=status.HTTP_200_OK, success=True, message="Event retrieval successful", data=serializer.data)


class EventRegistrationAPIView(APIView):
    """
    API endpoint for handling event registrations.

    This endpoint allows authenticated users to register for events by providing the event ID.

    Request:
        - POST request with the following parameter in the request body:
            - event (number): ID of the event to register for.

    Authentication:
        - Requires a valid JWT token for authentication.
        - Users must be authenticated to register for events.

    Response:
        - If the registration is successful, it returns a 201 Created status along with:
            - 'success': True
            - 'message': "Event registration successful"
            - 'data': Serialized details of the registration using the EventRegistrationSerializer

        - If the registration fails due to validation errors or other issues, it returns a 400 Bad Request status along with:
            - 'success': False
            - 'message': "Event registration unsuccessful"
            - 'data': Detailed error information, if applicable.

    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    @swagger_auto_schema(request_body=openapi.Schema(
        type=openapi.TYPE_OBJECT,
        properties={
            'event': openapi.Schema(type=openapi.TYPE_INTEGER, description='event id'),
        },
        required=['event']
    ),
        responses={201: EventRegistrationSerializer}
    )
    def post(self, request, *args, **kwargs):
        request.data['user'] = request.user.id
        serializer = EventRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return formatted_response(status=status.HTTP_201_CREATED, success=True, message="Event registration successful", data=serializer.data)
        return formatted_response(status=status.HTTP_400_BAD_REQUEST, success=False, message="Event registration unsuccessful", data=serializer.errors)


class EventCreateAPIView(APIView):
    """
    API endpoint for creating events (admin-only).

    This endpoint allows authenticated admin users to create events by providing necessary information.

    Request:
        - POST request with the following parameters in the request body:
            - name (str): The desired name for the event.
            - description (str, optional): Description about the event.
            - capacity (number): Total registration capacity for the event.

    Authentication:
        - Requires a valid JWT token for authentication.
        - Only admin users are permitted to create events.

    Response:
        - If the event creation is successful, it returns a 201 Created status along with:
            - 'success': True
            - 'message': "Event creation successful"
            - 'data': Serialized details of the created event using the EventSerializer

        - If the event creation fails due to validation errors or other issues, it returns a 400 Bad Request status along with:
            - 'success': False
            - 'message': "Event creation unsuccessful"
            - 'data': Detailed error information, if applicable.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAdminOrReadOnly]

    @swagger_auto_schema(request_body=EventSerializer)
    def post(self, request, *args, **kwargs):
        serializer = EventSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return formatted_response(status=status.HTTP_201_CREATED, success=True, message="Event creation successful", data=serializer.data)
        return formatted_response(status=status.HTTP_400_BAD_REQUEST, success=False, message="Event creation unsuccessful", data=serializer.errors)


class CancelEventRegistrationView(APIView):
    """
    API endpoint to cancel an event registration. Only the owner can change the status.

    This endpoint allows authenticated users to cancel their own event registration.

    Request:
        - PATCH request with the event registration's primary key (pk) as a parameter.

    Authentication:
        - Requires a valid JWT token for authentication.
        - Users can only cancel their own event registration.

    Response:
        - If the cancellation is successful, it returns a 200 OK status along with:
            - 'success': True
            - 'message': "Cancel event registration successful"
            - 'data': Serialized details of the updated event registration using the BasicEventRegistrationSerializer

        - If the cancellation fails due to validation errors, the user not being the owner, or other issues,
          it returns a 400 Bad Request status along with:
            - 'success': False
            - 'message': "Cancel event registration unsuccessful"
            - 'data': Detailed error information, if applicable.

        - If the event registration with the given primary key does not exist, it returns a 404 Not Found status.
    """
    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk, format=None):
        event_registration = self.get_object(pk)
        if event_registration.user != request.user:
            return formatted_response(status=status.HTTP_403_FORBIDDEN, success=False, message="You do not have permission to perform this action.", data=None)
        if event_registration.cancelled:
            return formatted_response(status=status.HTTP_200_OK, success=True, message="Event registration is already cancelled", data=None)

        event = event_registration.event
        event.total_registration = max(0, event.total_registration - 1)
        event.save()

        serializer = BasicEventRegistrationSerializer(
            event_registration, data={'cancelled': True}, partial=True)

        if serializer.is_valid():
            serializer.save()
            return formatted_response(status=status.HTTP_200_OK, success=True, message="Cancel event registration successful", data=serializer.data)
        return formatted_response(status=status.HTTP_400_BAD_REQUEST, success=False, message="Cancel event registration unsuccessful", data=serializer.errors)

    def get_object(self, pk):
        try:
            return Registration.objects.get(pk=pk)
        except Registration.DoesNotExist:
            raise Http404


class EventRegistrationListAPIView(APIView):
    """
    API endpoint for listing event registrations.

    This endpoint allows authenticated users to retrieve a list of their own event registrations.

    Request:
        - GET request to retrieve the list of event registrations for the authenticated user.

    Authentication:
        - Requires a valid JWT token for authentication.
        - Users can only retrieve their own event registrations.

    Response:
        - If the retrieval is successful, it returns a 200 OK status along with:
            - 'success': True
            - 'message': "Event Registration listing successful"
            - 'data': Serialized list of event registrations using the BasicEventRegistrationSerializer

        - If the retrieval fails due to authentication issues or other reasons, it returns a 400 Bad Request status along with:
            - 'success': False
            - 'message': "Event Registration listing unsuccessful"
            - 'data': Detailed error information, if applicable.
    """

    authentication_classes = [JWTAuthentication]
    permission_classes = [IsAuthenticated]

    def get(self, request, *args, **kwargs):
        event_registrations = Registration.objects.filter(user=request.user)
        serializer = BasicEventRegistrationSerializer(
            event_registrations, many=True)
        return formatted_response(status=status.HTTP_200_OK, success=True, message="Event Registration listing successful", data=serializer.data)
