from flask import Flask, jsonify
from scanners.s3_scanner import scan_public_s3
from scanners.iam_scanner import scan_iam
from scanners.sg_scanner import scan_security_groups
from scanners.risk_engine import calculate_risk
import json

app = Flask(__name__)

@app.route('/scan', methods=['GET'])
def run_scan():
    findings = []
    findings.extend(scan_public_s3())
    findings.extend(scan_iam())
    findings.extend(scan_security_groups())

    risk = calculate_risk(findings)

    result = {
        "findings": findings,
        "risk_summary": risk
    }

    with open("findings.json", "w") as f:
        json.dump(result, f, indent=4)

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)
