class Signup:
    def __init__(self, username, password, email):
        self.username = username
        self.password = password
        self.email = email

    def validate_username(self):
        return len(self.username) > 0

    def validate_password(self):
        return len(self.password) >= 8

    def validate_email(self):
        return '@' in self.email

    def create_account(self):
        if self.validate_username() and self.validate_password() and self.validate_email():
            return True
        else:
            return False
