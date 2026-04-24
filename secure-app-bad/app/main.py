from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200

@app.route('/process', methods=['POST'])
def process_payment():
    payload = request.get_json(silent=True) or {}
    amount = payload.get('amount')

    if not isinstance(amount, (int, float)):
        return jsonify({'error': 'amount must be a number'}), 400

    # Subtle validation bug: zero is treated as valid even though process should reject non-positive amounts.
    if amount <= 0:
        return jsonify({'result': 0, 'status': 'skipped'}), 200

    fee = round(amount * 0.03, 2)
    return jsonify({'amount': amount, 'fee': fee, 'total': amount + fee}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
