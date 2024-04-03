import unittest
import sys
sys.path.append('/Users/admin/Desktop/billboard project')
from app import app, db


class TestLoginSignup(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app = app.test_client()
        db.create_all()

    def tearDown(self):
        db.session.remove()
        db.drop_all()

    def test_signup(self):
        response = self.app.post('/signup', data=dict(
            username='testuser',
            email='test@example.com',
            password='password'
        ), follow_redirects=True)
        self.assertIn(b'You have successfully registered!', response.data)
        self.assertEqual(response.status_code, 200)

    def test_login(self):
        response = self.app.post('/login', data=dict(
            username='testuser',
            password='password'
        ), follow_redirects=True)
        self.assertIn(b'You are logged in!', response.data)
        self.assertEqual(response.status_code, 200)


if __name__ == '__main__':
    unittest.main()

