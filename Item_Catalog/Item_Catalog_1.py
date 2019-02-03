from flask import Flask,render_template,flash,url_for,request,redirect,jsonify

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from my_database import Base,Gadget,Items,User

from flask import session as login_session
import random,string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app=Flask(__name__)

CLIENT_ID = json.loads(
    open('client_secrets.json','r').read())['web']['client_id']
APPLICATION_NAME = "Gadgets Menu App"

engine = create_engine("sqlite:///GadgetDB.db",connect_args={"check_same_thread":False},echo=True)
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


@app.route('/category/JSON')
def showGadgetsJSON():
    gadgets=session.query(Gadget).all()
    return jsonify(gadgets = [gadget.serialize for gadget in gadgets])


@app.route('/category/<int:gadget_id>/JSON')
def showGadgetItemsJSON(gadget_id):
    items=session.query(Items).filter_by(gadget_id=gadget_id)
    return jsonify(gadgetItems = [item.serialize for item in items])

'''
@app.route('/catalog/<int:catalog_id>/items/<int:item_id>/JSON')
def showCategoryItemJSON(catalog_id, item_id):
    categoryItem = session.query(CategoryItem).filter_by(id = item_id).first()
    return jsonify(categoryItem = [categoryItem.serialize])
'''


@app.route('/login')
def showLogin():
    state=''.join(random.choice(string.ascii_uppercase + string.digits) for x in xrange(32))
    login_session['state'] = state
    #return "Current Session state is %s" %login_session['state']
    return render_template('login.html',STATE=state)


'''
@app.route('/logout')
def showLogout():
    if login_session['provider'] == 'facebook':
        fbdisconnect()
        del login_session['facebook_id']

    if login_session['provider'] == 'google':
        gdisconnect()
        del login_session['gplus_id']
        del login_session['access_token']

    del login_session['username']
    del login_session['email']
    del login_session['picture']
    del login_session['user_id']
    del login_session['provider']

    return redirect(url_for('showGadgets'))
'''

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

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
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
        response = make_response(json.dumps
                                 ('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # ADD PROVIDER TO LOGIN SESSION
    login_session['provider'] = 'google'

    # see if user exists, if it doesn't make a new one
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
    output += ' " style = "width: 300px; height: 300px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    return output


#DISCONNECT - Revoke a current usser's token and reset their login_session
@app.route('/gdisconnect')
def gdisconnect():
    #Disconnects only a user.
    credentials = login_session.get('access_token')
    if access_token is None:
        response = make_response(json.dumps('Current user not connected'),401)
        response.headers['Content-Type'] = 'app/json'
        return response

        #Execute HTTP GEt request to revoke current token
        url = 'https://accounts.google.com/o/oauth2/revoke?token=%s'%access_token
        h = httplib2.Http()
        result = h.request(url,'GET')[0]

        if result['status'] == '200':
            #Resets the user's session
            del login_session['access_token']
            del login_session['gplus_id']
            del login_session['username']
            del login_session['email']
            del login_session['picture']

            response = make_response(json.dumps('Disconnected successfully'),200)
            response.headers['Content-Type'] = 'application/json'
            return response
        else:
            #For whatever reason, the given token was invalid
            response = make_response(json.dumps('Failed to revoke token for given user.'),400)
            response.headers['Content-Type'] = 'application/json'
            return response


                                            #-------------Show Category-------------
@app.route('/')
@app.route('/categories')
def showGadgets():
    gadgets=session.query(Gadget).all()
    items=session.query(Items).order_by(Items.id.desc()).limit(2)
    if 'username' not in login_session:
        return render_template('public_showGadgets.html',gadgets=gadgets,items=items)
    else:
        return render_template('showGadgets.html',gadgets=gadgets,items=items)




#Create a new Gadget                                            #-------------Create Category-------------
@app.route('/category/new', methods=['GET', 'POST'])
def createGadgets():
    if request.method == 'POST':
        newGadget=Gadget(name=request.form['name'])
        session.add(newGadget)
        session.commit()
        return redirect(url_for('showGadgets'))
    else:
        return render_template('createGadgets.html')




                                            #-------------Edit Category-------------
@app.route('/category/<int:gadget_id>/edit', methods=['GET', 'POST'])
def editGadgets(gadget_id):
    editGadget = session.query(Gadget).filter_by(id=gadget_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editGadget.name = request.form['name']
        session.commit()
        return redirect(url_for('showGadgets'))
    else:
        return render_template('editGadgets.html',editGadget = editGadget)



                                            #-------------Delete Category-------------
@app.route('/category/<int:gadget_id>/delete', methods=['GET', 'POST'])
def deleteGadgets(gadget_id):
    deleteGadget=session.query(Gadget).filter_by(id=gadget_id).one()

    if 'username' not in login_session:
        return redirect('/login')
    if deleteGadget.user_id!=login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete. This belongs to....');}</scripts><body onload='myFunction()'>"
    if request.method == 'POST'    :
        session.delete(deleteGadget)
        session.commit()
        return redirect(url_for('showGadgets'))
    else:
        return render_template('deleteGadgets.html',deleteGadget=deleteGadget)



                                            #-------------Show Item-------------
@app.route('/category/<int:gadget_id>/')
def showGadgetItems(gadget_id):
    gadgets=session.query(Gadget).all()
    gadget=session.query(Gadget).filter_by(id=gadget_id).one()
    
    #creator = getUserInfo(gadget.user_id)

    items=session.query(Items).filter_by(gadget_id=gadget_id)
    quantity=items.count()

    return render_template('public_showGadgetsItems.html',gadgets=gadgets,gadget=gadget,items=items,count=quantity)

'''    if 'username' not in login_session or creator.id!= login_session['user_id']:
        return render_template('public_showGadgetsItems.html',gadgets=gadgets,gadget=gadget,items=items,count=quantity,creator=creator)
    else:
        return render_template('showGadgetsItems.html',gadgets=gadgets,gadget=gadget,items=items,count=quantity,creator=creator)
'''


                                            #-------------Create Item-------------
@app.route('/category/<int:gadget_id>/new', methods=['GET', 'POST'])
def createGadgetItem(gadget_id):
    if request.method == 'POST':
        newItem = Items(name=request.form['name'],description=request.form['description'],price=request.form['price'],gadget_id=gadget_id,user_id=gadget.user_id)
        session.add(newItem)
        session.commit()
        return redirect(url_for('showGadgetItems',gadget_id=gadget_id))
    else:
        return render_template('createGadgetItems.html',gadget_id=gadget_id)



                                            #-------------Edit Item-------------
@app.route('/category/<int:gadget_id>/<int:item_id>/edit', methods=['GET', 'POST'])
def editGadgetItem(gadget_id,item_id):
    editItem = session.query(Items).filter_by(id=item_id).one()
    if request.method == 'POST':
        if request.form['name']:
            editItem.name = request.form['name']
        if request.form['description']:
            editItem.description = request.form['description']
        if request.form['price']:
            editItem.price = request.form['price']

        session.add(editItem)
        session.commit()
        return redirect(url_for('showGadgetItems',gadget_id=gadget_id))
    else:
        return render_template('editGadgetItems.html',gadget_id=gadget_id,item_id=item_id,item=editItem)



                                            #-------------Delete Item-------------
@app.route('/category/<int:gadget_id>/<int:item_id>/delete', methods=['GET', 'POST'])
def deleteGadgetItem(gadget_id,item_id):
    deleteItem=session.query(Items).filter_by(id=item_id).one()
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        return redirect(url_for('showGadgetItems',gadget_id=gadget_id))
    else:
        return render_template('deleteGadgetItems.html',gadget_id=gadget_id,item_id=item_id,item=deleteItem)



def getUserId(email):
    try:
        user = session.query(User).filter_by(email = email).one()
        return user.id
    except:
        return None

def getUserInfo():
    user = session.query(User).filter_by(id = user_id).one()
    return user

def createUser(login_session):
    newUser = User(name = login_session['username'], email = login_session['email'], picture = login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email = login_session['email']).one()
    return user.id


if __name__=='__main__':
    app.secret_key = 'super_secret_key'
    app.debug=True
    app.run(host='0.0.0.0',port=5000)
