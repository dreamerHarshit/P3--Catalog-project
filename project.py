import json
import httplib2
import requests
import string,random
import os
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from flask import Flask, url_for, session, redirect, request, render_template, flash
from flask import jsonify, make_response, send_from_directory
from database_setup import Base, Category, Item, User
from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
from flask import session as login_session
import httplib2

app = Flask(__name__)

credentials = {}
token_info = {}

CLIENT_ID = json.loads(open('client_secret.json','r').read())['web']['client_id']
# This is the path to the uploads
UPLOAD_FOLDER = 'images/'
# Extension we are accepting to be uploaded
ALLOWED_EXTENSIONS = set(['png','jpg', 'gif'])

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


def createUser(login_session):
	newuser = User(
		name = login_session['username'],
		email = login_session['email'],
		picture = login_session['picture'])
	session.add(newuser)
	session.commit()
	user = session.query(User).filter_by(email=login_session['email']).one()
	return user.id

def getuserInfo(useri_d):
		"""gets user based on user_id"""
		user = session.query(User).filter_by(id=user_id).one()
		return user

def getUserID(email):
	"""get user_id by email address"""
	try:
		user = session.query(User).filter_by(email=email).one()
		return user.id
	except:
		return None
#Create a state token to prevent request forgery.
#Store it in the session for later validation.
@app.route('/login')
def showLogin():
	"""Route for rendering login screen"""
	state = ''.join(random.choice(string.ascii_uppercase + string.digits)
		for x in xrange(32))
	login_session['state'] = state
	return render_template("login.html",STATE=state)

@app.route('/gconnect', methods=['POST'])
def gconnect():
	"""coonection using google+"""
	code = request.data
	auth_config = json.loads(open('client_secret.json','r').read())['web']

	try:
		oauth_flow =flow_from_clientsecrets('client_secrets_google.json',scope='')
		oauth_flow.redirect_uri = 'postmessage'
		credentials = oauth_flow.step2_exchange(code)
	except FlowExchangeError:
		response = make_response(json.dumps('Failed to upgrade the authorization code.'),401)
		response.headers['Content-Type'] = 'application/json'
		return response

	access_token = credentials.access_token
	url = (auth_config['access_token_uri']
           % access_token)
	h = httplib2.Http()
	result = json.loads(h.request(url, 'GET')[1])
	if result.get('error') is not None:
		response = make_response(json.dumps(result.get('error')), 500)
		response.headers['Content-Type'] = 'application/json'
		return response
	gplus_id = credentials.id_token['sub']
	# Verify user id's match
	if result['user_id'] != gplus_id:
		response = make_response(json.dumps("Token's user_id doesn't match \given user ID"), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# verify that the access token is valid for this app
	if result['issued_to'] != auth_config['client_id']:
		response = make_response(json.dumps("Token's client id doesn't \match apps"), 401)
		response.headers['Content-Type'] = 'application/json'
		return response
	# Check to see if user is already logged in
	stored_credentials = login_session.get('credentials')
	stored_gplus_id = login_session.get('gplus_id')
	if stored_credentials is not None and gplus_id == stored_gplus_id:
		response = make_response(
			json.dumps('Current user is already connected'), 200)
		response.headers['Content-Type'] = 'application/json'
		return response

	# store the access token in the session for later use
	login_session['credentials'] = credentials.access_token
	login_session['gplus_id'] = gplus_id
	
	# get user info
	userinfo_url = auth_config["userinfo_url"]
	params = {'access_token': credentials.access_token, 'alt': 'json'}
	answer = requests.get(userinfo_url, params=params)

	data = answer.json()
	login_session['username'] = data['name']
	login_session['picture'] = data['picture']
	login_session['email'] = data['email']
	login_session['provider'] = "google"
	return "success"
	
def gdisconnect():
    """Disconnect method for logging out of Google+
    """
    # Only disconnect a connected user.
    credentials = login_session['credentials']
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % credentials
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response

@app.route('/disconnect')
def disconnect():
    """Logout method for destroying session based on the provider used"""
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['credentials']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
    else:
        flash("You were not logged in")
    return redirect(url_for('home'))        

#create a json of category
@app.route('/catalog.json')
def CategoryJSON():
	category = session.query(Category).all()
	categories = []
	for c in category:
		cat = c.serialize
		item = session.query(Item).filter_by(category_id = c.id).order_by(desc(Item.id))
		items = []
		for i in item:
			items.append(i.serialize)
		cat['items'] = items
		categories.append(cat)
	return jsonify(Categories = categories)

#Show all Categories and latest items
@app.route('/')
def showCatalog():
	categories = session.query(Category).order_by(asc(Category.id))
	items = session.query(Item).order_by(desc(Item.id))
	catDict = {}
	for cat in categories:
		catDict[cat.id] = cat.name
	return render_template('catalog.html',categories=categories, items=items, catDict=catDict)


# Handler to Show all items for a Category
@app.route('/catalog/<category_name>/items/')
def showItems(category_name):
    category_name = category_name.replace('%20', ' ')
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(
        category_id=category.id).all()
    itemCount = len(items)
    return render_template('items.html', items=items, category=category, itemCount=itemCount, categories=categories)

#Handler to Show a Category menu
@app.route('/catalog/<category_name>/<item_name>/')
def showItem(item_name, category_name):
    item_name = item_name.replace('%20', ' ')
    category_name = category_name.replace('%20', ' ')
    print category_name
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(name=item_name, category_id=category.id).one()
    creator = getUserInfo(item.user_id)
    return render_template('display_item.html', item=item, category=category, creator=creator)

#Handler to Create a new menu item
@app.route('/catalog/new/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    elif request.method == 'POST':
        newItem = Item(name=request.form['name'], description=request.form['description'], category_id=request.form[
                           'category_id'], user_id=login_session['user_id'])
        session.add(newItem)
        session.commit()
        flash('New Item %s Successfully Created' % (newItem.name))
        return redirect(url_for('showCatalog'))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('item_new.html', categories=categories)

#Handler to Edit a menu item
@app.route('/catalog/<category_name>/<item_name>/edit', methods=['GET', 'POST'])
def editItem(item_name, category_name):
    if 'username' not in login_session:
        return redirect('/login')
    item_name = item_name.replace('%20', ' ')
    category_name = category_name.replace('%20', ' ')
    editedItem = session.query(Item).filter_by(name=item_name).one()
    categories = session.query(Category).order_by(asc(Category.name))
    if login_session['user_id'] != editedItem.user_id:
        return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own item in order to edit it.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        print request.form
        if request.form['name']:
            editedItem.name = request.form['name']
        if request.form['description']:
            editedItem.description = request.form['description']
        if request.form['category_id']:
            editedItem.category_id = request.form['category_id']
        session.add(editedItem)
        session.commit()
        flash('Item Successfully Edited')
        return redirect(url_for('showCatalog'))
    else:
        return render_template('item_edit.html', category_name=category_name,item=editedItem, categories=categories)


#Handler to Delete a menu item
@app.route('/catalog/<category_name>/<item_name>/delete', methods=['GET', 'POST'])
def deleteItem(item_name, category_name):
    if 'username' not in login_session:
        return redirect('/login')
    item_name = item_name.replace('%20', ' ')
    category_name = category_name.replace('%20', ' ')
    itemToDelete = session.query(Item).filter_by(name=item_name).one()
    print itemToDelete
    if login_session['user_id'] != itemToDelete.user_id:
        return "<script>function myFunction() {alert('You are not authorized to delete this items. Please create your own item in order to delete it.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash('Item Deleted Successfully!')
        return redirect('/')
    else:
        return render_template('item_delete.html', item=itemToDelete, category_name=category_name)

if __name__ == '__main__':
    app.debug = True
    app.secret_key = 'super_secret_key'
    app.run(host='0.0.0.0', port=5000)
