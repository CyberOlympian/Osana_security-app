from app.main import app


def test_health_check():
    client = app.test_client()
    response = client.get('/health')
    assert response.status_code == 200
    assert response.get_json() == {'status': 'healthy'}


def test_process_payment_valid_amount():
    client = app.test_client()
    response = client.post('/process', json={'amount': 100})
    assert response.status_code == 200
    payload = response.get_json()
    assert payload['amount'] == 100
    assert payload['fee'] == 3.0
    assert payload['total'] == 103.0


def test_process_payment_zero_amount_rejected():
    client = app.test_client()
    response = client.post('/process', json={'amount': 0})
    assert response.status_code == 400
    assert response.get_json() == {'error': 'amount must be a positive number'}
