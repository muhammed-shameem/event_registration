from django.db import models
from django.contrib.auth.models import User
from django.core.validators import MinValueValidator


class Event(models.Model):
    name = models.CharField(max_length=255, unique=True)
    description = models.TextField(blank=True)
    capacity = models.PositiveIntegerField(validators=[MinValueValidator(1)])
    total_registration = models.PositiveIntegerField(
        default=0, validators=[MinValueValidator(0)])
    valid_until = models.DateField()
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.name}"


class Registration(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    event = models.ForeignKey(Event, on_delete=models.CASCADE)
    cancelled = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self):
        return f"{self.user.username} - {self.event.name}"
