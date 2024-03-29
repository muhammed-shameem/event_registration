from django.contrib import admin
from django.urls import path, include
from rest_framework import permissions
from drf_yasg.views import get_schema_view
from drf_yasg import openapi

schema_view = get_schema_view(
    openapi.Info(
        title="Event Registration",
        default_version='v1',
        description="Event Registration APIs",
        terms_of_service="https://www.google.com/policies/terms/",
        contact=openapi.Contact(email="muhammadshami977@gmail.com"),
        license=openapi.License(name="BSD License"),
    ),
    public=True,
    permission_classes=(permissions.AllowAny,),
)

urlpatterns = [
    # DRF-Swagger URLs
    path('swagger<format>/', schema_view.without_ui(cache_timeout=0),
         name='schema-json'),
    path('documentation/', schema_view.with_ui('swagger',
         cache_timeout=0), name='schema-swagger-ui'),
    path('redoc/', schema_view.with_ui('redoc',
         cache_timeout=0), name='schema-redoc'),

    # APP URLS
    path('admin/', admin.site.urls),
    path('api/', include('registration_app.urls')),
]
