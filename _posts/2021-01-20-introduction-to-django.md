---
title: "TryHackMe - Introduction to Django"
categories:
  - TryHackMe
tags:
  - django
  - writeup
  - tryhackme
---
How it works and why should I learn it?

## Introduction
- Django is a high-level Python web framework that enables rapid development of secure and maintainable websites. It allows you to develop websites and web applications in a matter of hours.
- Django can automatically compile HTML code, therefore making it possible for anyone without any advanced knowledge in markup languages to develop a website. Additionally, Django is arguably one of the most secure developing frameworks, which in the right configuration, can strongly resist against SQL injections and XSS.\
- All in all, if you are familiar with Python and considering creating a website, Django can be a really good choice. As for penetration tester, it is important to understand the basic structure of Django-powered websites in order to be able to identify possible weaknesses and mistakes a developer can make.

## Getting started
Installation:
- Install Django by running this command:

    ```bash
    $ pip3 install Django==2.2.12
    ```

- Make a directory for your project files and navigate there with the command prompt.
- Run `django-admin startproject {project_name}` in order to start your project. (Replace {project_name} with your prefered name).

    ```bash
    $ django-admin startproject wuvel
    $ ls
    wuvel
    ```

- Run `python3 manage.py migrate` to automatically configure new files.

    ```bash
    $ python3 manage.py migrate
    Operations to perform:
    Apply all migrations: admin, auth, contenttypes, sessions
    Running migrations:
    Applying contenttypes.0001_initial... OK
    Applying auth.0001_initial... OK
    Applying admin.0001_initial... OK
    Applying admin.0002_logentry_remove_auto_add... OK
    Applying admin.0003_logentry_add_action_flag_choices... OK
    Applying contenttypes.0002_remove_content_type_name... OK
    Applying auth.0002_alter_permission_name_max_length... OK
    Applying auth.0003_alter_user_email_max_length... OK
    Applying auth.0004_alter_user_username_opts... OK
    Applying auth.0005_alter_user_last_login_null... OK
    Applying auth.0006_require_contenttypes_0002... OK
    Applying auth.0007_alter_validators_add_error_messages... OK
    Applying auth.0008_alter_user_username_max_length... OK
    Applying auth.0009_alter_user_last_name_max_length... OK
    Applying auth.0010_alter_group_name_max_length... OK
    Applying auth.0011_update_proxy_permissions... OK
    Applying sessions.0001_initial... OK
    ```

    After creating the project you can see that Django creates a file `manage.py` and a file directory named after your project.

    `manage.py` is a command-line utility that lets you interact with your Django project in various ways. It is especially handy in creating web-apps, managing databases, and most importantly running the server.

Basic syntax:
- Basic syntax for using this utility is `python3 manage.py {command}`.
    - `runserver`.
    
        Runserver is the most important command used with manage.py; It allows you to deploy your website on the server. Django has a wonderful feature that allows you to instantly see changes made on the website without restarting it. (It is only necessary to restart runserver command when adding a new app).

        Run this command and navigate to your website with IP given in the outline. You should see a page like this:

        <a href="/assets/images/tryhackme/django/1.png"><img src="/assets/images/tryhackme/django/1.png"></a>

        Note: If you are willing to run the server to your local network, just add `0.0.0.0:8000` after runserver command. (In case if you get an error afterward, just go to `settings.py` located your websites folder and add this address to `ALLOWED_HOSTS`)
        {: .notice--info}

    - `createsuperuser`.

        This command allows you to create an admin account for your Django web admin panel. Run this command .

        ```bash
        $ python3 manage.py createsuperuser                                                                                                             1 ⨯
        Username (leave blank to use 'kali'): 
        Email address: 
        Password: 
        Password (again): 
        Error: Blank passwords aren't allowed.
        Password:                                                                                                                                             
        Password (again): 
        The password is too similar to the username.
        This password is too short. It must contain at least 8 characters.                                                                                    
        Bypass password validation and create user anyway? [y/N]: y                                                                                           
        Superuser created successfully.
        ```

        Access the panel at `IP:8000/admin`.

        <a href="/assets/images/tryhackme/django/2.png"><img src="/assets/images/tryhackme/django/2.png"></a>

    - `startapp`.

        Startapp allows you to initialize an app for your project. Django projects can have infinite number of apps. Basic syntax:
        
        ```bash
        $ python3 manage.py startapp {app_name}
        ```

#### How would we create an app called Forms? 

```bash
$ python3 manage.py startapp Forms
```

#### How would we run our project to a local network?

```bash
$ python3 manage.py runserver 0.0.0.0:8080
```

## Creating a website
Now, let's go ahead and create a very simple app: 
1. Create an app using a command from Unit 2 and call it whatever you like. I will be using 'app' for this lesson.

    ```bash
    $ python3 manage.py startapp app
    ```

2. Head over to settings.py and include your **app name** in *INSTALLED_APPS*:

    <a href="/assets/images/tryhackme/django/3.png"><img src="/assets/images/tryhackme/django/3.png"></a>

3. Head over to urls.py (located in the main folder!) and include a path to your app there:

    <a href="/assets/images/tryhackme/django/4.png"><img src="/assets/images/tryhackme/django/4.png"></a>

4. Migrate your changes by running `python3 manage.py migrate`