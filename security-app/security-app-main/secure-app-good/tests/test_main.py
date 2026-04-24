import json

from app.main import app


def test_health_check():
    client = app.test_client()
    response = client.get('/health')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'healthy'}


def test_calculate_success():
    client = app.test_client()
    response = client.post('/calculate', json={'amount': 200})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['amount'] == 200
    assert payload['fee'] == 5.0
    assert payload['total'] == 205.0


def test_calculate_negative_amount():
    client = app.test_client()
    response = client.post('/calculate', json={'amount': -5})
    assert response.status_code == 400
    assert response.get_json() == {'error': 'amount must be non-negative'}
