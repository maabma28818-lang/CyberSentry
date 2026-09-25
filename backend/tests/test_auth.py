import unittest
import json
import os
import sys

# Ensure backend root is on Python path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from app import app, db
from models.scan_results import User


class TestAuthEndpoints(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = app.test_client()
        with app.app_context():
            db.create_all()

    def tearDown(self):
        with app.app_context():
            db.session.remove()
            db.drop_all()

    def test_signup_success(self):
        payload = {
            "username": "sec_analyst",
            "email": "analyst@cybersentry.io",
            "password": "Password123!",
            "role": "analyst"
        }
        res = self.client.post('/api/auth/signup', json=payload)
        self.assertEqual(res.status_code, 201)
        data = res.get_json()
        self.assertIn("token", data)
        self.assertIn("user", data)
        self.assertEqual(data["user"]["username"], "sec_analyst")
        self.assertEqual(data["user"]["email"], "analyst@cybersentry.io")

    def test_signup_duplicate_fails(self):
        payload = {
            "username": "duplicate_user",
            "email": "dup@cybersentry.io",
            "password": "Password123!"
        }
        res1 = self.client.post('/api/auth/signup', json=payload)
        self.assertEqual(res1.status_code, 201)

        res2 = self.client.post('/api/auth/signup', json=payload)
        self.assertEqual(res2.status_code, 409)

    def test_signin_success_with_email_and_username(self):
        signup_payload = {
            "username": "operator1",
            "email": "operator1@cybersentry.io",
            "password": "SecurePassword#99"
        }
        self.client.post('/api/auth/signup', json=signup_payload)

        # Test login via email
        res_email = self.client.post('/api/auth/signin', json={
            "account": "operator1@cybersentry.io",
            "password": "SecurePassword#99"
        })
        self.assertEqual(res_email.status_code, 200)
        data_email = res_email.get_json()
        self.assertIn("token", data_email)
        token = data_email["token"]

        # Test login via username
        res_user = self.client.post('/api/auth/signin', json={
            "account": "operator1",
            "password": "SecurePassword#99"
        })
        self.assertEqual(res_user.status_code, 200)

        # Test /api/auth/me
        res_me = self.client.get('/api/auth/me', headers={
            "Authorization": f"Bearer {token}"
        })
        self.assertEqual(res_me.status_code, 200)
        me_data = res_me.get_json()
        self.assertEqual(me_data["user"]["username"], "operator1")

    def test_signin_invalid_password(self):
        signup_payload = {
            "username": "operator2",
            "email": "operator2@cybersentry.io",
            "password": "CorrectPassword123"
        }
        self.client.post('/api/auth/signup', json=signup_payload)

        res = self.client.post('/api/auth/signin', json={
            "account": "operator2",
            "password": "WrongPassword456"
        })
        self.assertEqual(res.status_code, 401)


if __name__ == '__main__':
    unittest.main()
