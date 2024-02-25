# Event Registration API

## Description
This Django Rest Framework (DRF) project provides an API for managing event registrations.

## Table of Contents
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Testing](#testing)

## Prerequisites

Make sure you have Python 3 installed on your system. If not, you can download and install it from the [official Python website](https://www.python.org/downloads/).

## Installation

### 1. Clone this repository

```bash
git clone https://github.com/your-username/your-project.git
cd event-registration
```

### 2. Create and activate a virtual environment

```bash
python3 -m venv venv
source venv/bin/activate  # On Windows, use: .\venv\Scripts\activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Create database migrations

```bash
python manage.py makemigrations
```

### 5. Apply database migrations

```bash
python manage.py migrate
```

### 6. Create a superuser (for Django Admin)

```bash
python manage.py createsuperuser
```

### 7. Run the development server

```bash
python manage.py runserver
```

Visit /admin/ to access the Django Admin interface.


## Testing

Run the tests using the following command:

```bash
python manage.py test
```

