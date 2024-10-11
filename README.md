# PinShield

### Description
**PinShield** is a security-focused application that generates RSA key pairs and encrypts user PINs using public-key cryptography. The application logs the key generation and encryption process, storing logs in the `Logs` directory for audit and security purposes.

---

### Table of Contents
1. [Installation](#installation)
2. [Usage](#usage)
3. [Pending Features](#pending-features)
4. [Key Features](#key-features)
5. [Project Structure](#project-structure)
6. [Contributing](#contributing)
7. [Disclaimer](#disclaimer)

---

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/BalmerDemos/

    ```

2. Install the required dependencies:
    ```bash
    pip install -r requirements.txt
    ```

   **Current Dependencies**:
   - `asgiref==3.8.1`
   - `cffi==1.17.1`
   - `cryptography==43.0.1`
   - `Django==5.1.1`
   - `djangorestframework==3.15.2`
   - `dnspython==2.7.0`
   - `pycparser==2.22`
   - `pymongo==4.10.1`
   - `setuptools==75.1.0`
   - `sqlparse==0.5.1`
   - `tzdata==2024.2`
   - `wheel==0.44.0`

---

### Usage

1. **Key Generation**: Generates RSA key pairs (private and public keys), saving them in the `keys/` directory.
2. **PIN Encryption**: Encrypts a given PIN using the generated public key and logs the encrypted PIN in the `Logs/pin.log` file.

To run the application:
```bash
python manage.py runserver <port_number>

### For validation:
# Example usage
if __name__ == "__main__":
    public_key = generate_keys()
    encrypt_and_log_pin("1234", public_key)  # Example PIN


3. [Pending Features](#pending-features)

Debug Tool: The debug tool has not been configured in this version. Future updates will include detailed debugging capabilities.
MongoDB Connection: The code includes pymongo in the dependencies, but MongoDB has not been connected or configured in this version.

4. [Key Features](#key-features)
Generates a private and public RSA key pair.

5. [Project Structure](#project-structure)
    pin_app/
    static/
        images/
        styles.css
    templates/
        load.html          # Load keys
        pin_entry.html     # Capture PIN entry to encrypt
        thanks.html        # Display after encryption is done
        welcome.html       # Information about the project and developer
    generate_keys_v2.py    # Handles the encryption process
    logs/                  # Store logs
    keys/                  # Stores public and private keys


6. [Contributing](#contributing)

### Notes

-Project Overview

PinShield is a security-focused application designed to generate RSA key pairs and encrypt user PINs using public-key cryptography. This project serves as an educational tool to understand the principles of encryption and key management.

-Key Contributions

Key Generation: Developed a robust function to generate RSA key pairs (public and private keys) based on user input, ensuring secure and unique key creation.

PIN Encryption: Implemented an encryption mechanism that securely encrypts user-entered PINs using the generated public key, enhancing data security.

Logging Mechanism: Created a logging system that records the key generation and encryption processes, storing logs in the Logs directory for audit and security purposes.

-Skills Developed

Django Framework: Gained hands-on experience with Django, including setting up views, templates, and routing.

Cryptography: Developed a solid understanding of public-key cryptography principles, particularly RSA encryption and key management.

-Problem Solving
Overcame challenges related to Django's routing and key management by researching best practices and implementing effective solutions.

-Learning Resources
Utilized various online resources, including the official Django documentation, to enhance understanding and implementation of features.

-Reflection
This project significantly enhanced my programming skills and provided a solid foundation for future web development and cryptography projects. It has been a valuable learning experience in applying theoretical concepts to --practical applications.

-Disclaimer
This is a learning project created for educational purposes only. It is not intended for production use. The code is provided as-is, and there are no guarantees or warranties regarding its performance or suitability for any particular purpose.






