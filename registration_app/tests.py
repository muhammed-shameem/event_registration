from django.test import TestCase
from rest_framework.test import APIClient
from .models import Event
from .views import EventListAPIView
from .serializers import EventSerializer


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
