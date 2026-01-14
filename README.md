1. make sure to install the required libraries:

pip install flask flask-sqlalchemy flask-login flask-wtf flask-bcrypt flask-session flask-session-captcha flask-mail sqlalchemy werkzeug pillow email-validator

2. Please change the host variable value to the IP of your device (or use 127.0.0.1). App is accessed via port 5000.

3. During the initial launch you will be asked to provide an e-mail address for the superadmin account, please make sure to provide an email you have access to

Other info:

2FA is implemented via PIN codes which are sent to the email of the account

If you create a new account in the app an activation url will be sent to the email provided during registration

Password reset: in the login panel click on forgot password. A link will be sent to the provided email (if an account with this email exists in the DB) to confirm that you want to change the password. Once you click the link you should receive another email with your temporary password. The app will require you to change the password to another one which wasn't provided in the email.

I think that's all the main information needed, but if something doesn't work as expected (page not loading etc.) or there would be anything else you would want to know please feel free to contact me via the student mail, or messenger


