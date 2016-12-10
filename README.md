# P3--Catalog-project

This app is the third project of udacity full stack developer nanodegree
This app implements CRUD opreations from a database. Create, Update and Delete operations are only allowed for logged users.
Authentication & Authorization

This apps uses Google  as authentication & authorization service.
##Run

    Clone this repository and log in the virtual machine with this commands:

    Setup database, initialize database with categories:

    python database_setup.py
    python insertitems.py

    Replace your client secrets for Facebook and Google sing in:
        Replace your Google client secrets in clientsecrets_google.json

    NOTE: You must configure your Google app correctly

    Now you can run the application:

    python application.py

    Go to your browser an type localhost:8000
