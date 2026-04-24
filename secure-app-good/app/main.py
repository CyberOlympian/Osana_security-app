from flask import Flask, jsonify, request

app = Flask(__name__)

@app.route('/health', methods=['GET'])
def health_check():
    return jsonify({'status': 'healthy'}), 200

@app.route('/calculate', methods=['POST'])
def calculate():
    payload = request.get_json(silent=True) or {}
    amount = payload.get('amount')

    if not isinstance(amount, (int, float)):
        return jsonify({'error': 'amount must be a number'}), 400

    if amount < 0:
        return jsonify({'error': 'amount must be non-negative'}), 400

    fee = round(amount * 0.025, 2)
    total = round(amount + fee, 2)

    return jsonify({'amount': amount, 'fee': fee, 'total': total}), 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
