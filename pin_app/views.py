from django.http import HttpResponse
from django.shortcuts import render
from cryptography.fernet import Fernet # it is not used..

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization  # Import serialization
from cryptography.hazmat.primitives.asymmetric import padding # it is not used..
from cryptography.hazmat.primitives import hashes # it is not used..

from .generate_keys_v2 import create_keys_folder, generate_keys, encrypt_and_log_pin    # type: ignore # Adjust the import based on your file structure

import logging

# Set up logging
#logging.basicConfig(filename='encrypted_pins.log', level=logging.INFO)

# Create your views here.
# pin_app/views.py
from django.shortcuts import render, redirect

def welcome_view(request):
    return render(request, 'welcome.html')

def pin_entry_view(request):
    if request.method == 'POST':
        pin = request.POST.get('pin')

        try:
            # Generate keys and get the public key
            public_key = generate_keys()
            # Encrypt and log the provided PIN
            encrypt_and_log_pin(pin, public_key)
            return redirect('thanks')  # Redirect after processing

        except ValueError as e:
            # Handle the error ( e.g invalid PIN)
             return render(request, 'pin_entry.html', {'error': str(e)})

    return render(request, 'pin_entry.html')

from django.shortcuts import render
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

def load_keys(request):
    # Generate keys for demonstration purposes
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Convert keys to PEM format for display
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()  # Specify no encryption
    ).decode('utf-8')

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    context = {
        'private_key': private_pem,
        'public_key': public_pem,
    }

    return render(request, 'load.html', context)


def thanks_view(request):
    return render(request, 'thanks.html',
                   {'description': "This mini-project demonstrates"+
                    "the process of capturing a user PIN," +
                    "generating RSA keys, encrypting the " +
                    "PIN, and logging the encrypted PIN."})
