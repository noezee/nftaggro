from config import host, user, password, database
from flask_sqlalchemy import SQLAlchemy
from models import User
from db import db
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_bootstrap import Bootstrap
from flask import Flask, request, redirect, url_for, render_template
import collections
from time import sleep
from json2html import *
import requests, psycopg2, json
from werkzeug.security import generate_password_hash, check_password_hash


app = Flask(__name__)
app.config['SECRET_KEY'] = 'Secret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///user.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(80))


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')


class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


with app.app_context():
    db.create_all()


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user, remember=form.remember.data)
                return redirect(url_for('dashboard'))

        return '<h1>Invalid username or password</h1>'


    return render_template('login.html', form=form)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data, method='sha256')
        new_user = User(username=form.username.data, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        return '<h1>New user has been created!</h1>'


    return render_template('signup.html', form=form)

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('nft.html', name=current_user.username)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    app.run(debug=True)


@app.route("/")
def home():
    return render_template('index.html')


if __name__ == ('__main__'):
    app.run(debug=True)

url = "https://solana-gateway.moralis.io/nft/mainnet/2camF6sXuq4eQ2h2815xiA2r3BvoYNQbFztbLNymiwsq/metadata"
headers = {

    "accept": "application/json",
    "X-API-Key": "Xm96DGFZOQWOTq3LFifK9ksaO4s7xhvwGRBLu8HpZHAGApHHzOnbIWC6YrhOOBTl"

}

response = requests.get(url, headers=headers)

print(response.text)

connection = psycopg2.connect(database=database, user=user, password=password, host=host)

cursor = connection.cursor()

cursor.execute("""SELECT * from metaplex""")

# Fetch all rows from database

record = cursor.fetchall()

print("Data from Database:- ", record)

@app.route("/nft", methods=['GET', 'POST'])
def nft():
    if request.method == 'POST':
        address = request.form.get('address')

        # Checking if the nft table exists in our database
        cur = conn.cursor()
        cur.execute("select * from information_schema.tables where table_name='nft_table'")
        check1 = bool(cur.rowcount)
        check2 = False
        # Checking if our table has this particular address
        if check1:
            cur.execute("SELECT mint FROM nft_table WHERE mint = %s", (address,))
            check2 = (cur.fetchone() is not None)

            # If this address is already in our table, let's try to display it
        if check2:

            # The code below converts our record from the database to JSON, similar to what we get from Moralis API
            cur.execute('''SELECT * FROM nft_table LEFT JOIN multiplex_table USING(metaplex_id)  
                LEFT JOIN owners ON nft_table.mint = owners.nft_address WHERE mint=%s''', (address,))
            rows = cur.fetchall()

            owners = []
            for owner in rows:
                o = collections.OrderedDict()
                o["address"] = owner[11]
                o["share"] = owner[14]
                o["verified"] = owner[13]
                owners.append(o)

            m = collections.OrderedDict()
            m["isMutable"] = rows[0][9]
            m["masterEdition"] = rows[0][10]
            m["metadatauri"] = rows[0][5]
            m["owners"] = owners
            m["primarySaleHappened"] = rows[0][8]
            m["sellerFeeBasisPoints"] = rows[0][7]
            m["updateauthority"] = rows[0][6]

            n = collections.OrderedDict()
            n["mint"] = rows[0][1]
            n["name"] = rows[0][2]
            n["standard"] = rows[0][3]
            n["symbol"] = rows[0][4]
            n['metaplex'] = m

            j = json.dumps(n)
            return render_template('nftresult.html', table=json2html.convert(json=j))
            # If nft address is not in our table, try to get it through Moralis API
        else:
            response = requests.get(url.format(address), headers=headers).json()
            sleep(3)

            # In case of Bad Request
            if 'statusCode' in response:
                return '''<h1>NFT with this address not found</h1>'''

                # If the Bad Request did not occur, Moralis will return JSON with information about the NFT
            # The code below saves this information to the DB
            with conn.cursor() as cur:
                cur.execute(""" CREATE TABLE IF NOT EXISTS owners( 
                    owner_address text, nft_address text, verified integer, share integer, PRIMARY KEY (owner_address, nft_address)) """)
                query_sql = """ INSERT INTO owners(owner_address, nft_address, verified, share) VALUES(%s, %s, %s, %s) """
                for o in response['metaplex']['owners']:
                    cur.execute(query_sql, (o['address'], response['mint'], o['verified'], o['share'],))
                conn.commit()

                cur.execute(""" CREATE TABLE IF NOT EXISTS multiplex_table( 
                    metaplex_id serial, metadataUri text, updateAuthority text, sellerFeeBasisPoints integer, primarySaleHappened integer,  
                    isMutable boolean, masterEdition boolean, PRIMARY KEY (metaplex_id)) """)
                query_sql = """ INSERT INTO multiplex_table(metadataUri, updateAuthority, sellerFeeBasisPoints, primarySaleHappened,  
                    isMutable, masterEdition) VALUES(%s, %s, %s, %s, %s, %s) """
                cur.execute(query_sql, (response['metaplex']['metadataUri'], response['metaplex']['updateAuthority'],
                                        response['metaplex']['sellerFeeBasisPoints'],
                                        response['metaplex']['primarySaleHappened'],
                                        response['metaplex']['isMutable'], response['metaplex']['masterEdition'],))
                conn.commit()

                cur.execute(""" CREATE TABLE IF NOT EXISTS

nft_table( 
                    mint text, name text, standard text, symbol text, metaplex_id serial, PRIMARY KEY (mint), 
                    FOREIGN KEY (metaplex_id) REFERENCES multiplex_table(metaplex_id)) """)
                query_sql = """ INSERT INTO nft_table(mint, name, standard, symbol) VALUES(%s, %s, %s, %s) """
                cur.execute(query_sql, (response['mint'], response['name'], response['standard'], response['symbol'],))
                conn.commit()

            return render_template('nftresult.html', table=json2html.convert(json=response))

    return render_template('nft.html')


if name == "__main__":
    app.run(debug=True)
