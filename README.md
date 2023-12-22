# A Keycloak Authenticator Template for DJANGO

**Overview**

This project is created to streamline the process between creating an OIDC authentication with Django.

**Change Log (Date: 2023-12-21)**

**Updated Django Version:** 

Upgraded Django to version [django==5.0.0] for enhanced security and performance.
Updated Django REST Framework Version: Upgraded Django REST Framework to version [djangorestframework==3.14.0] to ensure compatibility with the latest Django version.

**Fixed ImportError:** 

Resolved an import issue with parse_header from django.http.multipartparser by updating package versions.
Template Configuration: Reviewed and corrected the TEMPLATES setting in Django settings for better template handling.

**Dependency Management:** 

Ensured consistency of dependencies within the Anaconda environment to avoid conflicts.

**Installation**

Include steps on how to install or set up your project. This is especially useful for new contributors or users.

```bash
# Example installation steps
git clone https://github.com/Celestialchips/Django_Keycloak_Template.git
cd Django_Keycloak_Template

# Setting up a virtual environment (optional)
python -m venv venv
source venv/bin/activate

# Installing dependencies
pip install -r requirements.txt

# run migrations
python3 manage.py migrate

# runserver
python3 manage.py runserver
```

**Usage**

Integrate the keycloak authenticator into your django application to provide OIDC usage using keycloak.

**Contributing**

If you would like to contribute to the project feel free to fork and make a pull request.

**License**

MIT License

**Contact**

Contact me [here](ryan.glass.dev@gmail.com) if you have any questions about this repository.