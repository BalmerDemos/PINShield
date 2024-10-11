# pin_app/urls.py
from django.urls import path
from .views import welcome_view, pin_entry_view, load_keys, thanks_view # Import your views

urlpatterns = [
    path('', welcome_view, name='welcome'),       # Welcome view
    path('pin-entry/', pin_entry_view, name='pin_entry'),  # Pin entry view
    path('load/', load_keys, name='load_keys'),
    path('thanks/', thanks_view, name='thanks'),  # Pin entry view
]