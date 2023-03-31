from chatGPT import getAns, getFullAns

from datetime import timedelta
from flask import Flask, make_response
from flask import jsonify
from flask import request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_jwt_extended import create_access_token
from flask_jwt_extended import current_user
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this!
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///test.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["SECRET_KEY"] = "super-secret"  # Change this!
jwt = JWTManager(app)
db = SQLAlchemy(app)

@jwt.user_identity_loader
def user_identity_lookup(user):
    return user.id


@jwt.user_lookup_loader
def user_lookup_callback(_jwt_header, jwt_data):
    identity = jwt_data["sub"]
    return User.query.filter_by(id=identity).one_or_none()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.Text, nullable=False, unique=True)
    name = db.Column(db.Text, nullable=False)
    password = db.Column(db.Text, nullable=False)
    email = db.Column(db.Text, nullable=False, unique=True)

class Prompt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    prompt = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))

class Answer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    answer = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    prompt_id = db.Column(db.Integer, db.ForeignKey('prompt.id'))

class DetailsAnswer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    answer = db.Column(db.Text, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    ans_from = db.Column(db.Text, nullable=False)

@app.route('/', methods=['GET'])
def index():
    user_numbers = User.query.count()
    return jsonify({"message": "This is home", "total registered user": user_numbers})


@app.route('/sign-up', methods=['POST'])
def sign_up():
    data = request.get_json()
    if(data is None):
        return make_response(jsonify({'msg': 'No data provided'}), 400)
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256', salt_length=8)
    
    check_db = User.query.filter_by(username=data['username']).one_or_none()
    check_db_email = User.query.filter_by(email=data['email']).one_or_none()

    if check_db is not None or check_db_email is not None:
        return make_response(jsonify({'msg': 'Email and Username must be unique'}), 400)
    
    
    user = User(username=data['username'], password = hashed_password, email=data['email'], name=data['name'])
    try:
        db.session.add(user)
        db.session.commit()

        return make_response(jsonify({'msg': "User created successfully"}), 201)
    except:
        return make_response(jsonify({'msg': 'There is an error while creating user'}), 500)

@app.route("/login", methods=["POST"])
def login():
    data = request.get_json()
    username = data['username']
    password = data['password']
    user = User.query.filter_by(username=username).one_or_none()
    if not user or user.username != username or not check_password_hash(user.password, password):
        return make_response(jsonify({'msg': 'Incorrect username or password'}), 401)
    # Notice that we are passing in the actual sqlalchemy user object here
    
    print(user.username == username, check_password_hash(user.password, password))

    access_token = create_access_token(identity=user, expires_delta=timedelta(hours=5))
    print(access_token)
    return make_response(jsonify({'access_token': access_token, "msg": "Login Success"}), 200)

@app.route('/users', methods=['GET'])
@jwt_required()
def users():
    return jsonify(
        name=current_user.name,
        id=current_user.id,
        username=current_user.username,
    )


@app.route("/prompts", methods=['POST'])
@jwt_required()
def prompts():
    data = request.get_json()
    if(data is None):
        return jsonify({'msg': 'No data provided'})
    prompt = Prompt(prompt=data['prompt'], user_id=current_user.id)
    try:
        db.session.add(prompt)
        db.session.commit()
    except:
        return make_response({'msg': 'There is an error while creating prompt'} , 500)
    return make_response ( {'msg': 'Your search is queued', 'prompt': prompt.id}, 201)

@app.route("/answers", methods=['GET'])
@jwt_required()
def answers():
    prompts = request.args.get('prompt_id')
    if(prompts is None):
        return make_response(jsonify({'message': 'No data provided'}), 400)
    
    query = Prompt.query.filter_by(id=prompts).one_or_none()
    
    if(query is None):
        return make_response(jsonify({'message': 'No prompt is found'}), 404) 

    oldAnswers = Answer.query.filter_by(prompt_id=prompts).one_or_none()
    if(oldAnswers is not None):
        return make_response({'answers': oldAnswers.answer} , 200)
    
    answers = getAns(prompts)
    ans = Answer(answer=answers, user_id=current_user.id, prompt_id=prompts)
    try:
        db.session.add(ans)
        db.session.commit()
        return make_response({'answers': answers} , 200)
    except:
        return jsonify({'message': 'There is an error while creating answer'})
    
@app.route("/full-answers", methods=['POST'])
@jwt_required()
def full_answers():
    options = request.get_json()
    if(options is None):
        return jsonify({'msg': 'No data provided'})
    optionText = options['text']

    query = DetailsAnswer.query.filter_by(ans_from=optionText).one_or_none()
    if(query is not None):
        return make_response({'answers': query.answer} , 200)
    answers = str(getFullAns(optionText))
    ans = DetailsAnswer(answer=answers, user_id=current_user.id, ans_from=optionText)
    print(ans.answer)
    try:
        db.session.add(ans)
        db.session.commit()
        return jsonify(answers)
    except:
        return jsonify({'message': 'There is an error while creating answer'})
    
@app.route("/auth", methods=['GET'])
@jwt_required()
def auth():
    return make_response(jsonify({'msg': 'success'}), 200)

with app.app_context():
    db.create_all();

if(__name__ == '__main__'):
    app.run(debug=True)