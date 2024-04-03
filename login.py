# login.py

class Login:
    def __init__(self, username, password):
        self.username = username
        self.password = password

    def authenticate(self):
        if self.username == "admin" and self.password == "password":
            return True
        else:
            return False
