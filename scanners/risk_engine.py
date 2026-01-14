def calculate_risk(findings):
    total = sum(f['risk_score'] for f in findings)

    if total >= 90:
        level = "Critical"
    elif total >= 60:
        level = "High"
    elif total >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "total_risk_score": total,
        "risk_level": level
    }
