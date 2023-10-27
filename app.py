from flask import Flask, render_template, request, redirect, url_for, session, flash, make_response
import mysql.connector
from passlib.hash import sha256_crypt

app = Flask(__name__)
app.secret_key = '1379'

db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'pyverse',
}

# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'logged_in' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']  # Get the confirmation password
        firstname = request.form['firstname']
        lastname = request.form['lastname']

        # Check if the passwords match
        if password != confirm_password:
            flash("Passwords don't match. Please try again.", 'danger')
            return render_template('register.html')

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        # Check if the email already exists
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            flash("Email already exists. Please choose a different email.", 'danger')
            return render_template('register.html')

        # If the email doesn't exist and passwords match, proceed with registration
        password = sha256_crypt.hash(password)

        cursor.execute("INSERT INTO users (email, password, firstname, lastname) VALUES (%s, %s, %s, %s)",
                       (email, password, firstname, lastname))
        conn.commit()
        conn.close()
        flash("Successfully created account.", 'success')
        return redirect(url_for('login'))

    return render_template('register.html')



# Login
@app.route('/', methods=['GET', 'POST'])
def login():
    if 'logged_in' in session:
        response = make_response(redirect(url_for('dashboard')))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response

    if request.method == 'POST':
        email = request.form['email']
        password_candidate = request.form['password']

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
        user_data = cursor.fetchone()
        conn.close()

        if user_data:
            stored_password = user_data[4]  # Assuming the hashed password is in the third column
            if sha256_crypt.verify(password_candidate, stored_password):
                session['logged_in'] = True
                session['email'] = email
                flash("Login successful", 'success')
                return redirect(url_for('dashboard'))
            else:
                flash("Invalid password", 'danger')
        else:
            flash("Account doesn't exist", 'danger')

    return render_template('login.html')

# Profile
@app.route('/dashboard/user_profile')
def user_profile():
    if 'logged_in' in session:
        email = session['email']  # Updated session variable name
        # Query the database to retrieve user information
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = %s", (email,))  # Updated SQL query
        user_data = cursor.fetchone()
        conn.close()
        return render_template('user_profile.html', user_data=user_data)
    else:
        flash("You need to log in first.", 'danger')
        return redirect(url_for('login'))

# Edit Profile
@app.route('/dashboard/edit_profile', methods=['GET', 'POST'])
def edit_profile():
    if 'logged_in' in session:
        if request.method == 'POST':
            new_password = request.form['new_password']
            confirm_new_password = request.form['confirm_new_password']
            new_firstname = request.form['new_firstname']
            new_lastname = request.form['new_lastname']
            new_contactNo = request.form['new_contactNo']
            new_origin = request.form['new_origin']

            # Check if the new password and confirm password match
            if new_password != confirm_new_password:
                flash("Passwords don't match. Please try again.", 'danger')
                return render_template('edit_profile.html')

            # Hash the new password
            new_password = sha256_crypt.hash(new_password)

            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            # Update the user's information in the database
            cursor.execute("UPDATE users SET password = %s, firstname = %s, lastname = %s, contactNo = %s, origin = %s WHERE email = %s",
                           (new_password, new_firstname, new_lastname, new_contactNo, new_origin, session['email']))
            conn.commit()
            conn.close()

            flash("Profile updated successfully", 'success')
            session['firstname'] = new_firstname
            session['lastname'] = new_lastname
            # You can also update contactNo and origin in the session if needed
            session['contactNo'] = new_contactNo
            session['origin'] = new_origin

            return redirect(url_for('dashboard'))

        return render_template('edit_profile.html')
    else:
        flash("You need to log in first.", 'danger')
        return redirect(url_for('login'))




# Delete Account
@app.route('/dashboard/delete_account', methods=['GET', 'POST'])
def delete_account():
    if 'logged_in' in session:
        if request.method == 'POST':
            email = session['email']

            conn = mysql.connector.connect(**db_config)
            cursor = conn.cursor()

            # Delete the user's account from the database
            cursor.execute("DELETE FROM users WHERE email = %s", (email,))  # Updated SQL query
            conn.commit()
            conn.close()

            flash("Account deleted successfully", 'success')
            session.clear()  # Log the user out after deleting the account
            return redirect(url_for('login'))

        return render_template('delete_account.html')
    else:
        flash("You need to log in first.", 'danger')
        return redirect(url_for('login'))

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash("You are now logged out", 'success')
    return redirect(url_for('login'))

# Dashboard
@app.route('/dashboard')
def dashboard():
    if 'logged_in' in session:
        response = make_response(render_template('dashboard.html'))
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        return response
    else:
        flash("You need to log in first.", 'danger')
        return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
