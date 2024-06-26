from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_bcrypt import Bcrypt
from flask_sqlalchemy import SQLAlchemy
from googleapiclient.discovery import build
import requests
from sympy import symbols, Eq, solve, sympify
from sympy.parsing.sympy_parser import parse_expr

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
bcrypt = Bcrypt(app)
db = SQLAlchemy(app)

# Google API credentials
API_KEY = 'AIzaSyCIBYQVKX5lbixLVIffnLCVK_-av-rjGHo'
SEARCH_ENGINE_ID = '0619a0a39d63f4503'

# User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), nullable=False, unique=True)
    email = db.Column(db.String(150), nullable=False, unique=True)
    password = db.Column(db.String(60), nullable=False)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and bcrypt.check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('chat'))
        else:
            return "Login Unsuccessful. Please check email and password", 403
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = bcrypt.generate_password_hash(request.form['password']).decode('utf-8')
        user = User(username=username, email=email, password=password)
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('index'))

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return render_template('chat.html')

@app.route('/get_response', methods=['POST'])
def get_response():
    user_message = request.form['message']
    if 'solve' in user_message.lower():  # Example of handling mathematical queries
        response = solve_equation(user_message)
    elif 'code' in user_message.lower() or 'program' in user_message.lower():  # Example of handling programming queries
        response = get_programming_code(user_message)
    else:
        response = get_google_search_response(user_message)
    return jsonify({'response': response})

def get_google_search_response(query):
    try:
        service = build("customsearch", "v1", developerKey=API_KEY)
        result = service.cse().list(q=query, cx=SEARCH_ENGINE_ID, num=3).execute()
        items = result.get('items', [])

        if not items:
            return "Sorry, I couldn't find any relevant information."

        response = ""
        for item in items:
            title = item.get('title', '')
            snippet = item.get('snippet', '')
            link = item.get('link', '')
            response += f"<strong>{title}</strong>: {snippet} <a href='{link}' target='_blank'>Read More</a><br><br>"

        return response

    except Exception as e:
        return f"Error: {str(e)}"

def get_programming_code(query):
    search_query = f"{query} site:stackoverflow.com OR site:geeksforgeeks.org OR site:github.com"
    return get_google_search_response(search_query)

def solve_equation(query):
    try:
        # Extract the equation part after 'solve'
        equation = query.split('solve')[-1].strip()
        # Check if it is a simple arithmetic expression
        if '=' not in equation:
            result = sympify(equation)
            return f"Result: {result}"

        # Handle complex equations
        lhs, rhs = equation.split('=')
        lhs_expr = parse_expr(lhs)
        rhs_expr = parse_expr(rhs)
        equation = Eq(lhs_expr, rhs_expr)

        # Solve the equation
        solutions = solve(equation)
        response = f"Solutions for {query}:<br>"
        for sol in solutions:
            response += f"{sol}<br>"
        return response

    except Exception as e:
        return f"Error solving equation: {str(e)}"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
