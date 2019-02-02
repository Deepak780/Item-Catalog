# Item-Catalog

### Overview
In this project, we will develop an application that provides a list of items within a variety of categories as well as provide a user registration and authentication system. Registered users will have the ability to post, edit and delete their own items.
A user need not logged in, in order to read the categories pr items. However, users who are created an item or category will be able to update the data.
It also uses a user authentication like third party auth Google or Facebook.

[Top](#top)
### What you will learn?
You will learn how to develop a RESTful web application using the Python framework Flask along with implementing third-party OAuth authentication. You will then learn when to properly use the various HTTP methods available to you and how these methods relate to CRUD (create, read, update and delete) operations.

[Top](#top)
### Technologies required
* Python
* HTML
* CSS
* Bootstrap
* Flask
* Jinja2
* SQLAchemy
* OAuth
* Facebook / Google Login

[Top](#top)
### Softwares needed
* Python
* Vagrant
* VirtualBox

[Top](#top)
### How to run this project
* Download and install Vagrant and VirtualBox.
* Clone the vagrant file from the Udacity repo.
* From the command prompt cd to vagrant directory, then either clone this repo or download and place zip here.
* Launch the virtual machine using the command
```
vagrant up
```
* To log in into Virtual machine use
```
vagrant up
```
* Install all the necessary files here such as 
1. flask ``` pip install flask ```
2. sqlalchemy ``` pip install flask ```
3. oauth2client ``` pip install oauth2client ```
4. requests ``` pip install oauth2client ``` 

* Set up the application databse using the command:
```
python my_database.py
```
* Insert sample data using the command:
```
python sample_data.py
```
* Finally run the project using the command:
```
python item_catalog.py
```

[Top](#top)
### Google Login Credentials
To get the Google login credentials follow these steps:

1. Go to [Google Dev Console](https://console.developers.google.com).
2. Sign up or Login if prompted.
3. Go to Credentials.
4. Select Create Crendentials > OAuth Client ID.
5. Select Web application.
6. Enter name 'Item-Catalog'.
7. Authorized JavaScript origins = 'http://localhost:5000'.
8. Authorized redirect URIs = 'http://localhost:5000/login' && 'http://localhost:5000/gconnect'.
9. Select Create.
10. Copy the Client ID and paste it into the `data-clientid` in login.html.
11. On the Dev Console Select Download JSON.
12. Rename JSON file to client_secrets.json.
13. Place JSON file in item-catalog directory that you cloned from here.

[Top](#top)
### Output

[Top](#top)
FAQ's [here]()
