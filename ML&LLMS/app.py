# dummy flask server
from flask import Flask, request, jsonify

app = Flask(__name__)

# Sample patterns for detecting SQL injection and XSS
SQLI_PATTERNS = ["' OR 1=1", "' DROP TABLE", "SELECT * FROM"]
XSS_PATTERNS = ["<script>", "alert(", "onerror="]

def detect_sql_injection(data):
    for pattern in SQLI_PATTERNS:
        if pattern.lower() in data.lower():
            return True
    return False

def detect_xss(data):
    for pattern in XSS_PATTERNS:
        if pattern.lower() in data.lower():
            return True
    return False

@app.route('/detect', methods=['POST'])
def detect():
    content = request.json
    data = content.get('data', '')
    
    if detect_sql_injection(data):
        return jsonify({"result": "SQL Injection detected"}), 200
    
    if detect_xss(data):
        return jsonify({"result": "XSS Attack detected"}), 200
    
    return jsonify({"result": "No attack detected"}), 200

if __name__ == '__main__':
    app.run(debug=True)
