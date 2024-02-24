from rest_framework import serializers
from django.contrib.auth.models import User
from .models import Event, Registration
from rest_framework.validators import UniqueValidator
from django.contrib.auth.password_validation import validate_password, ValidationError


class RegisterSerializer(serializers.ModelSerializer):
    """
    Serializer for user registration.
    """
    email = serializers.EmailField(
        required=True,
        validators=[UniqueValidator(queryset=User.objects.all())]
    )
    password = serializers.CharField(write_only=True, required=True)
    password2 = serializers.CharField(write_only=True, required=True)
    first_name = serializers.CharField(min_length=2, required=True)
    last_name = serializers.CharField(min_length=1, required=True)

    class Meta:
        model = User
        fields = ('username', 'email', 'first_name',
                  'last_name', 'password', 'password2')
        extra_kwargs = {
            'first_name': {'required': True},
            'last_name': {'required': True}
        }

    def validate(self, attrs):
        if attrs['password'] != attrs['password2']:
            raise serializers.ValidationError(
                {"password": "Password fields didn't match."})

        return attrs

    def create(self, validated_data):
        user = User.objects.create(
            username=validated_data['username'],
            email=validated_data['email'],
            first_name=validated_data['first_name'],
            last_name=validated_data['last_name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user


class LoginSerializer(serializers.Serializer):
    """
    Serializer for user login.
    """
    username = serializers.CharField(max_length=150)
    password = serializers.CharField(write_only=True)

    def validate(self, data):
        username = data.get('username')
        password = data.get('password')

        user = User.objects.filter(username=username).first()

        if user and user.check_password(password):
            return data
        else:
            raise serializers.ValidationError("Invalid credentials")


class ProfileSerializer(serializers.ModelSerializer):
    """
    Serializer for user profile.
    """
    class Meta:
        model = User
        fields = ['id', 'username', 'first_name', 'last_name']


class EventSerializer(serializers.ModelSerializer):
    """
    Serializer for Event.
    """
    class Meta:
        model = Event
        fields = '__all__'


class RegistrationSerializer(serializers.ModelSerializer):
    """
    Serializer for Event Registration.
    """
    event = EventSerializer()

    class Meta:
        model = Registration
        fields = '__all__'

    def validate(self, data):
        event_data = data.get('event')
        event_id = event_data.get('id') if event_data else None
        if event_id:
            try:
                event = Event.objects.get(id=event_id)
            except Event.DoesNotExist:
                raise serializers.ValidationError("Event not found")
            if Registration.objects.filter(event=event).count() >= event.capacity:
                raise serializers.ValidationError("Event is at full capacity")
        return data
