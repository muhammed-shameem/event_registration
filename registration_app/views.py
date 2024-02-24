from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from .serializers import RegisterSerializer
from rest_framework_simplejwt.tokens import RefreshToken
from .utils import formatted_response


class UserRegistrationAPIView(APIView):
    """
    API endpoint for user registration.

    This endpoint allows users to register by providing necessary information.
    Upon successful registration, it returns an access token and a refresh token.

    Req Body:
        - username (str): The desired username for the user.
        - email (str): The email address of the user.
        - password (str): The password for the user account.
        - password2 (str): Confirmation of the password.
        - first_name (str): The first name of the user.
        - last_name (str): The last name of the user.
    """
    def post(self, request, *args, **kwargs):
        serializer = RegisterSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                refresh = RefreshToken.for_user(user)
                token_data = {
                    'refresh': str(refresh),
                    'access': str(refresh.access_token)
                }
                return formatted_response(status=status.HTTP_201_CREATED, success=True, message="User registered successfully", data=token_data)
        return formatted_response(status=status.HTTP_400_BAD_REQUEST,success=False,message="User registration unsuccessful",data=serializer.errors)
