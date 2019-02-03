from flask import Flask, render_template, flash, url_for
from flask import request, redirect, jsonify

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from my_database import Base, Gadget, Items, User

from flask import session as login_session
import random
import string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests
from functools import wraps

app = Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Gadgets Menu App"

engine = create_engine("sqlite:///GadgetDB.db",
                       connect_args={"check_same_thread": False}, echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/category/JSON')
def showGadgetsJSON():
    gadgets = session.query(Gadget).all()
    return jsonify(gadgets=[gadget.serialize for gadget in gadgets])


@app.route('/category/<int:gadget_id>/JSON')
def showGadgetItemsJSON(gadget_id):
    items = session.query(Items).filter_by(gadget_id=gadget_id)
    return jsonify(gadgetItems=[item.serialize for item in items])


@app.route('/login')
def showLogin():
    state = ''.join(random.choice(
                    string.ascii_uppercase +
                    string.digits) for x in xrange(32))
    login_session['state'] = state
    # return "Current Session state is %s" %login_session['state']
    return render_template('login.html', STATE=state)


def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in login_session:
            return redirect(url_for('showLogin'))
        return f(*args, **kwargs)
    return decorated_function


# Show Category
# Home Page
# Catalog page which shows all categories and recent items
@app.route('/')
@app.route('/categories/')
def showGadgets():
    gadgets = session.query(Gadget).all()
    items = session.query(Items).order_by(Items.id.desc()).limit(3)
    if 'username' not in login_session:
        return render_template('public_showGadgets.html',
                               gadgets=gadgets, items=items)
    else:
        return render_template('showGadgets.html',
                               gadgets=gadgets, items=items)


# Create Category
# Allows user to create a new category
@app.route('/category/new', methods=['GET', 'POST'])
@login_required
def createGadgets():
    if request.method == 'POST':
        if 'user_id' not in login_session and 'email' in login_session:
            login_session['user_id'] = getUserId(login_session['email'])
        newGadget = Gadget(name=request.form['name'],
                           user_id=login_session['user_id'])
        session.add(newGadget)
        session.commit()
        flash("New Gadget added successfully....!")
        return redirect(url_for('showGadgets'))
    else:
        return render_template('createGadgets.html')


# Edit Category
# Allows users to edit the category which they created
@app.route('/category/<int:gadget_id>/edit', methods=['GET', 'POST'])
@login_required
def editGadgets(gadget_id):
    editGadget = session.query(Gadget).filter_by(id=gadget_id).one()
    if 'username' in login_session:
        if editGadget.user_id == login_session['user_id']:
            if request.method == 'POST':
                if request.form['name']:
                    editGadget.name = request.form['name']
                session.commit()
                flash("Edited Successfully....!")
                return redirect(url_for('showGadgets'))
            else:
                return render_template('editGadgets.html',
                                       editGadget=editGadget)
        else:
            flash("You are not authorized.......")
            return redirect(url_for('showGadgets'))
    else:
        return redirect(url_for('/showLogin'))


# Delete Category
# Allows user to delete categories which they are created
@app.route('/category/<int:gadget_id>/delete', methods=['GET', 'POST'])
@login_required
def deleteGadgets(gadget_id):
    deleteGadget = session.query(Gadget).filter_by(id=gadget_id).one()
    if 'username' not in login_session:
        return redirect('/login')
    if deleteGadget.user_id != login_session['user_id']:
        return "<script>function myFunction(){\
        alert('You are not authorized to delete. \
        This belongs to....');}</scripts><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(deleteGadget)
        session.commit()
        return redirect(url_for('showGadgets'))
    else:
        return render_template('deleteGadgets.html', deleteGadget=deleteGadget)


# Show Item
# Show Catalog item page which shows the Items belonging
# to a selected category, also shows the categories.
@app.route('/category/<int:gadget_id>/')
def showGadgetItems(gadget_id):
    gadgets = session.query(Gadget).all()
    gadget = session.query(Gadget).filter_by(id=gadget_id).one()
    creator = getUserInfo(gadget.user_id)
    items = session.query(Items).filter_by(gadget_id=gadget_id)
    quantity = items.count()

    if 'username' not in login_session:
        return render_template('public_showGadgetsItems.html',
                               gadgets=gadgets, gadget=gadget,
                               items=items, count=quantity, creator=creator)
    else:
        return render_template('showGadgetsItems.html',
                               gadgets=gadgets, gadget=gadget,
                               items=items, count=quantity, creator=creator)


# Create Item
# Allows users to add items to a category which they are created
@app.route('/category/<int:gadget_id>/new', methods=['GET', 'POST'])
@login_required
def createGadgetItem(gadget_id):
    gadget = session.query(Gadget).filter_by(id=gadget_id).one()
    if 'username' in login_session:
        if login_session['user_id'] == gadget.user_id:
            if request.method == 'POST':
                newItem = Items(name=request.form['name'],
                                description=request.form['description'],
                                price=request.form['price'],
                                gadget_id=gadget_id,
                                user_id=login_session['user_id'])
                session.add(newItem)
                session.commit()
                return redirect(url_for(
                    'showGadgetItems', gadget_id=gadget_id))
            else:
                return render_template('createGadgetItems.html',
                                       gadget_id=gadget_id)
        else:
            flash("permission denied")
            return redirect(url_for('showGadgets'))
    else:
        redirect('/showLogin')


# Edit Item
# Allows users to edit the gadget items which they are added or created.
@app.route('/category/<int:gadget_id>/<int:item_id>/edit',
           methods=['GET', 'POST'])
@login_required
def editGadgetItem(gadget_id, item_id):
    editItem = session.query(Items).filter_by(id=item_id).one()
    if editItem.user_id != login_session['user_id']:
        return "<script>function myFunction(){\
        alert('You are not authorized to edit. \
        This belongs to....');}</scripts><body onload='myFunction()'>"
    if request.method == 'POST':
        if request.form['name']:
            editItem.name = request.form['name']
        if request.form['description']:
            editItem.description = request.form['description']
        if request.form['price']:
            editItem.price = request.form['price']

        session.add(editItem)
        session.commit()
        return redirect(url_for('showGadgetItems', gadget_id=gadget_id))
    else:
        return render_template('editGadgetItems.html',
                               gadget_id=gadget_id,
                               item_id=item_id,
                               item=editItem)


# Delete Item
# Allows users to delete a category item which they are created or added
@app.route('/category/<int:gadget_id>/<int:item_id>/delete',
           methods=['GET', 'POST'])
@login_required
def deleteGadgetItem(gadget_id, item_id):
    deleteItem = session.query(Items).filter_by(id=item_id).one()
    if deleteItem.user_id != login_session['user_id']:
        return "<script>function myFunction(){\
        alert('You are not authorized to delete. \
        This belongs to....');}</scripts><body onload='myFunction()'>"
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        return redirect(url_for('showGadgetItems', gadget_id=gadget_id))
    else:
        return render_template('deleteGadgetItems.html',
                               gadget_id=gadget_id,
                               item_id=item_id,
                               item=deleteItem)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check whether the access token is valid or not.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # Alert and abort if there is an error in the access token.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(
            json.dumps('Current user is already connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()
    login_session['provider'] = 'google'
    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check whether user exists or not, if not create a new user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; \
    height: 300px;border-radius: 150px;-webkit-border-radius: \
    150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'], 'success')
    print "done!"
    return output


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    # only disconnect a connected user
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = ('https://accounts.google.com/o/oauth2/revoke?token=%s'
           % access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']

        response = make_response(
            json.dumps('Successfully logged out!.'), 200)
        response.headers['Content-Type'] = 'application/json'
        flash('Successfully Logged Out!')
        return redirect(url_for('showGadgets'))
    else:
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# User helper functions
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(
        name=login_session['username'],
        email=login_session['email'],
        picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=5000)
