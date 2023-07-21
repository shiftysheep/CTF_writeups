from application.database import *
from flask import Blueprint, session, jsonify, redirect, render_template, request, current_app, Response
from application.util import user_profile_schema, response, is_authenticated, allowed_file
from flask_expects_json import expects_json
from application.bot.bot import bot
import os, threading

web = Blueprint('web', __name__)
api = Blueprint('api', __name__)

@web.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@web.route('/login')
def login():
    return render_template('login.html')

@web.route('/go')
def goto_external_url():
    return redirect(request.args.get('to'))

@web.route('/logout')
def logout():
    session['auth'] = None
    return redirect('/')

@web.route('/profile/<uid>')
@is_authenticated
def profiles(user, uid):
    profile = get_profile_db(int(uid))

    if not profile:
        return redirect('/')
    
    return render_template('profile.html', user=profile, all_profiles=get_all_profiles_db())

@web.route('/settings')
@is_authenticated
def settings(user):
    current_user = get_user_db(user['username'])

    if not current_user:
        return redirect('/logout')

    return render_template('settings.html', user=current_user)

@web.route('/ipc_documents')
@is_authenticated
def ipc_documents(user):
    if user['username'] != 'admin':
        return redirect('/settings')
    
    return render_template('ipc_document.html', all_users=get_all_users_db())

@api.route('/login', methods=['POST'])
def api_login():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = login_user_db(username, password)
    
    if user:
        session['auth'] = user
        return response('Logged In sucessfully'), 200
        
    return response('Invalid credentials!'), 403

@api.route('/register', methods=['POST'])
def api_register():
    if not request.is_json:
        return response('Invalid JSON!'), 400
    
    data = request.get_json()
    username = data.get('username', '')
    password = data.get('password', '')
    
    if not username or not password:
        return response('All fields are required!'), 401
    
    user = register_user_db(username, password)
    
    if user:
        return response('User registered! Please login'), 200
        
    return response('User already exists!'), 403

@api.route('/profile/me/update', methods=['POST'])
@is_authenticated
@expects_json(user_profile_schema)
def setting_update(user):
    if not request.is_json:
        return response('Missing required parameters!'), 401
    
    data = request.get_json()

    update_profile_db(user['username'], data)
    return response('Profile Updated!')

@api.route('/report', methods=['POST'])
@is_authenticated
def report(user):
    if not request.is_json:
        return response('Missing required parameters!'), 401
    
    data = request.get_json()

    user_id = data.get('id', '')

    if not user_id:
        return response('Missing required parameters!'), 401
    
    admin_user = get_profile_db(1)
    
    thread = threading.Thread(target=bot, args=(user_id, admin_user['username'], admin_user['password']))
    thread.start()

    return response('User reported! Our mods are reviewing your report')

@api.route('/ipc_submit', methods=['POST'])
@is_authenticated
def ipc_submit(user):
    if 'file' not in request.files:
        return response('Invalid file!')
    
    ipc_file = request.files['file']

    if ipc_file.filename == '':
        return response('No selected file!'), 403
    
    if ipc_file and allowed_file(ipc_file.filename):
        ipc_file.filename = f'{user["username"]}.png'
        ipc_file.save(os.path.join(current_app.root_path, current_app.config['UPLOAD_FOLDER'], ipc_file.filename))
        update_ipc_db(user['username'])

        return response('File submitted! Our moderators will review your request.')
    
    return response('Invalid file! only png files are allowed'), 403

@api.route('/ipc_download')
@is_authenticated
def ipc_download(user):
    if user['username'] != 'admin':
        return response('Unauthorized'), 401

    path = f'{os.path.join(current_app.root_path, current_app.config["UPLOAD_FOLDER"])}{request.args.get("file")}'
    try:
        with open(path, "rb") as file:
            file_content = file.read()
        return Response(file_content, mimetype='application/octet-stream')
    except:
        return response('Something Went Wrong!')