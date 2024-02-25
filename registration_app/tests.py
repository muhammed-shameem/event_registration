from django.test import TestCase, Client
from django.http import QueryDict
from django.contrib.auth.models import User
from rest_framework.test import APIClient, APIRequestFactory
from rest_framework_simplejwt.tokens import RefreshToken
from datetime import timedelta, datetime
from .models import Event, Registration
from .views import EventListAPIView, EventRegistrationAPIView, EventRegistrationListAPIView
from .serializers import EventSerializer, EventRegistrationSerializer, BasicEventRegistrationSerializer


class EventListAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.event1 = Event.objects.create(
            name="Test Event 1", capacity=10, valid_until="2024-03-01")
        self.event2 = Event.objects.create(
            name="Test Event 2", capacity=20, valid_until="2024-03-15")

    def test_list_events(self):
        response = self.client.get('/api/events/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['success'], True)
        self.assertEqual(response.data['message'], "Event listing successful")
        self.assertEqual(len(response.data['data']), 2)
        serialized_events = EventSerializer(
            [self.event1, self.event2], many=True).data
        self.assertEqual(response.data['data'], serialized_events)

    def test_invalid_url(self):
        response = self.client.get('/invalid-url/')
        self.assertEqual(response.status_code, 404)


class EventDetailAPITestCase(TestCase):

    def setUp(self):
        self.client = APIClient()
        self.event = Event.objects.create(
            name="Test Event", capacity=10, valid_until="2024-03-01")

    def test_retrieve_event_details(self):
        url = f"/api/events/{self.event.pk}/"
        response = self.client.get(url)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['success'], True)
        self.assertEqual(response.data['message'],
                         "Event retrieval successful")

        expected_data = EventSerializer(self.event).data
        self.assertEqual(response.data['data'], expected_data)

    def test_retrieve_nonexistent_event(self):
        url = "/api/events/999/"
        response = self.client.get(url)
        self.assertEqual(response.status_code, 404)


class EventRegistrationAPIViewTestCase(TestCase):

    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(
            username='testuser', password='testpassword')
        self.event = Event.objects.create(
            name='Test Event', capacity=1, valid_until=datetime.now() + timedelta(days=1))

    def get_jwt_token(self):
        refresh = RefreshToken.for_user(self.user)
        return f'Bearer {refresh.access_token}'

    def test_successful_registration(self):
        jwt_token = self.get_jwt_token()
        data = {'event': self.event.id}
        request = self.factory.post(
            '/api/event-register/', data, HTTP_AUTHORIZATION=jwt_token)
        request.POST = QueryDict(request.POST.urlencode(), mutable=True)
        view = EventRegistrationAPIView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 201)
        self.assertEqual(response.data['success'], True)
        self.assertEqual(response.data['message'],
                         'Event registration successful')
        self.assertEqual(Registration.objects.count(), 1)

    def test_missing_event_id(self):
        jwt_token = self.get_jwt_token()
        data = {}
        request = self.factory.post(
            '/api/event-register/', data, HTTP_AUTHORIZATION=jwt_token)
        request.POST = QueryDict(request.POST.urlencode(), mutable=True)
        view = EventRegistrationAPIView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['success'], False)
        self.assertEqual(response.data['message'],
                         'Event registration unsuccessful')
        self.assertEqual(
            str(response.data['data']['event'][0]), 'This field is required.')

    def test_invalid_event_id(self):
        jwt_token = self.get_jwt_token()
        data = {'event': 999}
        request = self.factory.post(
            '/api/event-register/', data, HTTP_AUTHORIZATION=jwt_token)
        request.POST = QueryDict(request.POST.urlencode(), mutable=True)

        view = EventRegistrationAPIView.as_view()
        response = view(request)
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['success'], False)
        self.assertEqual(response.data['message'],
                         'Event registration unsuccessful')
        self.assertEqual(
            str(response.data['data']['event'][0]), 'Event doesn\'t exist')

    def test_event_full_capacity(self):
        jwt_token = self.get_jwt_token()
        data = {'event': self.event.id}

        # Registering one users to reach full capacity
        request_first = self.factory.post(
            '/api/event-register/', data, HTTP_AUTHORIZATION=jwt_token)
        request_first.POST = QueryDict(
            request_first.POST.urlencode(), mutable=True)
        view = EventRegistrationAPIView.as_view()
        response_first = view(request_first)
        self.assertEqual(response_first.status_code, 201)
        self.assertEqual(response_first.data['success'], True)

        # Attempting to register a second user
        request = self.factory.post(
            '/api/event-register/', data, HTTP_AUTHORIZATION=jwt_token)
        request.POST = QueryDict(request.POST.urlencode(), mutable=True)
        view = EventRegistrationAPIView.as_view()
        response = view(request)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.data['success'], False)
        self.assertEqual(response.data['message'],
                         'Event registration unsuccessful')
        self.assertEqual(response.data['data']
                         ['event'][0], 'Event is at full capacity')


class EventRegistrationListAPITestCase(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.event1 = Event.objects.create(
            name="Test Event 1", capacity=10, valid_until=datetime.now())
        self.event2 = Event.objects.create(
            name="Test Event 2", capacity=20, valid_until=datetime.now())
        self.user = User.objects.create_user(
            username='testuser', password='testpassword')
        self.registration1 = Registration.objects.create(
            user=self.user, event=self.event1)
        self.registration2 = Registration.objects.create(
            user=self.user, event=self.event2)

    def get_jwt_token(self):
        refresh = RefreshToken.for_user(self.user)
        return f'Bearer {refresh.access_token}'

    def test_list_registered_events(self):
        jwt_token = self.get_jwt_token()
        response = self.client.get(
            '/api/all-event-registrations/', HTTP_AUTHORIZATION=jwt_token)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['success'], True)
        self.assertEqual(response.data['message'],
                         "Event Registration listing successful")
        self.assertEqual(len(response.data['data']), 2)
        serialized_events = BasicEventRegistrationSerializer(
            [self.registration1, self.registration2], many=True).data
        self.assertEqual(response.data['data'], serialized_events)

    def test_invalid_url(self):
        response = self.client.get('/invalid-url/')
        self.assertEqual(response.status_code, 404)
