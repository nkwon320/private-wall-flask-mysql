from flask import Flask, render_template, request, redirect, session, flash
from mysqlconnection import connectToMySQL
import re
from flask_bcrypt import Bcrypt

app = Flask(__name__)
app.secret_key = "it's a secret!"
bcrypt = Bcrypt(app)

myDB='the_wall'

EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/createUser', methods=['POST'])
def create():
    is_valid=True
    if len(request.form['first_name']) < 1:
        is_valid=False
        flash("Please enter your first name")
    if len(request.form['last_name']) < 1:
        is_valid=False
        flash("Please enter your last name")
    if len(request.form['email']) < 1:
        is_valid = False
        flash ("Please enter your email!")
    if not EMAIL_REGEX.match(request.form['email']):
        flash("Invalid email format!")
        return redirect('/')
    if len(request.form['pword']) < 8:
        is_valid = False
        flash("Password too short!")
    if len(request.form['pword2']) < 0:
        is_valid=False
        flash("Password too short!")
    if request.form['pword'] != request.form['pword2']:
        is_valid=False
        flash("Passwords don't match!")
    if not is_valid:
        return redirect('/')
    else:
        #include some logic to validate user input before adding them to the database!
        #create the hash
        pw_hash = bcrypt.generate_password_hash(request.form['pword'])
        print(pw_hash)
        #prints something like b'$2b$12$sqjyok5RQcc19.../cimMIEnhnLb7iC'
        #be sure you set up your database so it can store password hashes this long (60 characters)
        query = "INSERT INTO users (first_name, last_name, email, password, created_at, updated_at) VALUES (%(f)s, %(l)s, %(e)s, %(pw)s, NOW(), NOW());"
        #put the pw_hash in our data dictionary, NOT the password the user provided
        data = {
            "f": request.form['first_name'],
            "l": request.form['last_name'],
            "e": request.form['email'],
            "pw": pw_hash
        }
        mysql = connectToMySQL(myDB)
        id = mysql.query_db(query, data)
        print(id)

        query2 = "SELECT * FROM users where id=%(id)s"
        data2 = {
            "id": id
        }

        mysql=connectToMySQL(myDB)
        user=mysql.query_db(query2,data2)[0]

        session['name'] = user['first_name']
        session['userid'] = id
        flash("You've been successfully registered!")
        # never render on a post, always redirect!
        return redirect('/wall')

@app.route('/login', methods=['POST'])
def login():
    #see if the username provided exists in the database
    mysql = connectToMySQL(myDB)
    query = "SELECT * FROM users WHERE email = %(e)s;"
    data = { "e": request.form["email"]}
    result = mysql.query_db(query, data)
    if len(result) > 0:
        #assuming we only have one user with this username, the user would be first in the list we get back
        #of course, we should have some logic to prevent duplicates of usernames when we create users
        #use bcrypt's check_password_has method, passing the has from our database and the password from the form
        if bcrypt.check_password_hash(result[0]['password'], request.form['pword']):
            #if we get True after checking the password, we may put the user id in session
            session['userid'] = result[0]['id']
            session['firstn'] = result[0]['first_name']
            #never render on a post, always redirect!
            return redirect('/wall')
    #if we didn't find anything in the database by searching the username or if the passwords don't match,
    #flash an error message and redirect back to a safe route
    flash("You could not be logged in")
    return redirect('/')

@app.route('/wall')
def wall():
    query = "SELECT * FROM users where id<>%(id)s"
    data = {
        "id": session['userid']
    }
    mysql = connectToMySQL(myDB)
    users = mysql.query_db(query, data)
    query = "select m.text,m.message_id,m.users_id, m.recipient_id,u.first_name, u.last_name from messages m join users u on u.id=m.users_id where m.recipient_id=%(id)s"
    data= {
        "id": session['userid']
    }
    mysql = connectToMySQL(myDB)
    messages=mysql.query_db(query, data)
    return render_template('wall.html', all_users = users, messages=messages)

@app.route('/send', methods=['POST'])
def send():
    mysql = connectToMySQL(myDB)
    query = "INSERT INTO messages(text, users_id, recipient_id, created_at, updated_at) VALUES (%(message)s, %(id)s, %(r_id)s, NOW(), NOW());"
    data = {
        "message": request.form['message'],
        "r_id": request.form['recipient_id'],
        "id": session['userid']
    }
    mysql.query_db(query, data)
    return redirect('/wall')

@app.route('/logout')
def logout():
    session.clear()
    flash('You successfully logged out!')
    return redirect('/')

@app.route('/delete/<int:id>')
def delete_message(id):
    id=id
    print(id)
    query = "DELETE FROM messages where message_id=%(id)s"
    data = {
        "id": id
    }
    mysql = connectToMySQL(myDB)
    mysql.query_db(query, data)
    return redirect("/wall")

if __name__=="__main__":
    app.run(debug=True)