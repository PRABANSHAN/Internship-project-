import os
import tempfile
import importlib
import sys
import json

import pytest


def setup_app_with_db(tmp_path):
    # create a temporary sqlite file path
    db_file = str(tmp_path / 'test_users.db')
    os.environ['DB_PATH'] = db_file
    # ensure no app cached
    if 'app' in sys.modules:
        del sys.modules['app']
    import app as myapp
    importlib.reload(myapp)
    # initialize DB
    myapp.init_db()
    return myapp


def test_signup_signin_and_local_chat(tmp_path):
    myapp = setup_app_with_db(tmp_path)
    client = myapp.app.test_client()

    # Signup
    resp = client.post('/signup', data={'name': 'Tester', 'email': 'tester@example.com', 'password': 'secret'}, follow_redirects=False)
    assert resp.status_code in (302, 303)

    # Signin
    resp = client.post('/signin', data={'email': 'tester@example.com', 'password': 'secret'}, follow_redirects=False)
    assert resp.status_code in (302, 303)

    # Now send chat messages (local bot) within session
    with client:
        # sign in to set session
        client.post('/signin', data={'email': 'tester@example.com', 'password': 'secret'})
        resp = client.post('/api/chat', json={'message': 'hi'})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data is not None
        assert 'reply' in data
        assert 'Hi there' in data['reply'] or 'I heard' in data['reply']

        # ask a simple math question and expect numeric result from local bot
        resp2 = client.post('/api/chat', json={'message': 'what is 7+9'})
        assert resp2.status_code == 200
        data2 = resp2.get_json()
        assert data2 is not None
        # local bot should evaluate 7+9 -> 16
        assert '16' in data2.get('reply', '')

        # history should contain the messages
        h = client.get('/history')
        assert h.status_code == 200
        assert 'hi' in h.get_data(as_text=True) or 'Hi there' in h.get_data(as_text=True)


def test_admin_user_and_admin_access(tmp_path):
    # Set ADMIN creds before importing app
    os.environ['DB_PATH'] = str(tmp_path / 'admin_test.db')
    os.environ['ADMIN_EMAIL'] = 'admin@gmail.com'
    os.environ['ADMIN_PASS'] = 'admin123'
    if 'app' in sys.modules:
        del sys.modules['app']
    import app as myapp
    importlib.reload(myapp)
    myapp.init_db()

    client = myapp.app.test_client()

    # sign in as admin
    resp = client.post('/signin', data={'email': 'admin@gmail.com', 'password': 'admin123'}, follow_redirects=True)
    assert resp.status_code == 200

    # access admin page
    with client:
        client.post('/signin', data={'email': 'admin@gmail.com', 'password': 'admin123'})
        r = client.get('/admin')
        assert r.status_code == 200
        assert 'Admin Dashboard' in r.get_data(as_text=True)
