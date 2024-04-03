# test_login.py
import unittest
from login import Login
from signup import Signup
from change_password import ChangePassword

class TestLogin(unittest.TestCase):
    def test_correct_credentials(self):
        login = Login("admin", "password")
        self.assertTrue(login.authenticate())

    def test_incorrect_credentials(self):
        login = Login("admin", "wrongpassword")
        self.assertFalse(login.authenticate())

class TestSignup(unittest.TestCase):
    def test_successful_signup(self):
        signup = Signup("testuser", "password123", "test@example.com")
        self.assertTrue(signup.create_account())

    def test_invalid_signup(self):
        signup = Signup("", "", "invalidemail")
        self.assertFalse(signup.create_account())

class TestChangePassword(unittest.TestCase):
    def test_successful_password_change(self):
        change_password = ChangePassword("testuser", "oldpassword", "newpassword123")
        self.assertTrue(change_password.change_password())

    def test_invalid_password_change(self):
        # Example with invalid input data
        change_password = ChangePassword("", "", "")
        self.assertFalse(change_password.change_password())       
        
if __name__ == '__main__':
    unittest.main()
  


