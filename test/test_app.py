import unittest
import json
from app import app
from api.user import add_user, remove_user

class AppTestCase(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.test_user = 'testuser'
        add_user(self.test_user)

    def tearDown(self):
        remove_user(self.test_user)

    def test_register_user(self):
        response = self.client.post('/users', json={'user': 'newuser'})
        self.assertEqual(response.status_code, 201)
        self.assertIn('User registered successfully', response.get_data(as_text=True))
        # Clean up
        remove_user('newuser')

    def test_get_token(self):
        response = self.client.post('/tokens', json={'user': self.test_user})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertIn('token', data)
        self.assertIn('exp', data)

    def test_external_api_with_valid_token(self):
        # Get token
        token_resp = self.client.post('/tokens', json={'user': self.test_user})
        token = token_resp.get_json()['token']
        # Call external-api
        response = self.client.post('/renault/gen3/sign', json={'data': 'value'}, headers={'Authorization': f'Bearer {token}'})
        # 외부 API가 실제로 동작하지 않으므로 200 또는 외부 API 에러 예상
        self.assertIn(response.status_code, [200, 500])

    def test_external_api_with_invalid_token(self):
        response = self.client.post('/renault/gen3/sign', json={'data': 'value'}, headers={'Authorization': 'Bearer invalidtoken'})
        self.assertEqual(response.status_code, 401)
        self.assertIn('Invalid token', response.get_data(as_text=True))

    def test_remove_user(self):
        add_user('deleteuser')
        response = self.client.delete('/users/deleteuser')
        self.assertEqual(response.status_code, 200)
        self.assertIn('User removed successfully', response.get_data(as_text=True))

if __name__ == '__main__':
    unittest.main()
