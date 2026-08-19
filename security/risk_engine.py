"""
Risk Engine Module
Calculates security scores (0-100) and risk level categories based on detected security findings.
"""

SEVERITY_WEIGHTS = {
    'CRITICAL': 20,
    'HIGH': 12,
    'MEDIUM': 6,
    'LOW': 2,
    'INFO': 0
}

def calculate_security_score(findings):
    """
    Calculates overall cloud security score (0 to 100).
    Base score starts at 100 and deducts points per active/open finding based on severity.
    """
    total_deduction = 0
    
    for f in findings:
        # Only deduct for Open or Investigating findings
        status = f.get('status', 'Open') if isinstance(f, dict) else f.status
        if status in ['Open', 'Investigating']:
            sev = f.get('severity', 'LOW') if isinstance(f, dict) else f.severity
            total_deduction += SEVERITY_WEIGHTS.get(sev.upper(), 2)

    raw_score = 100 - total_deduction
    score = max(0, min(100, raw_score))
    return score


def get_score_category(score):
    """Returns human-readable rating, alert status badge class, and color code for a score."""
    if score == 100:
        return {
            'rating': 'EXCELLENT',
            'badge': 'bg-success',
            'color': '#22c55e',
            'description': 'Your cloud environment follows security best practices.'
        }
    elif 80 <= score < 100:
        return {
            'rating': 'GOOD',
            'badge': 'bg-info',
            'color': '#06b6d4',
            'description': 'Security status is solid, but minor configuration improvements exist.'
        }
    elif 60 <= score < 80:
        return {
            'rating': 'NEEDS IMPROVEMENT',
            'badge': 'bg-warning text-dark',
            'color': '#eab308',
            'description': 'Moderate risk detected. Action recommended for medium/high issues.'
        }
    elif 40 <= score < 60:
        return {
            'rating': 'POOR',
            'badge': 'bg-orange text-white',
            'color': '#f97316',
            'description': 'Significant security misconfigurations leave resources exposed.'
        }
    else:
        return {
            'rating': 'CRITICAL RISK',
            'badge': 'bg-danger',
            'color': '#ef4444',
            'description': 'Urgent action required! Severe vulnerabilities present.'
        }


def summarize_findings_by_severity(findings):
    """Counts open findings broken down by severity level."""
    counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0,
        'INFO': 0,
        'TOTAL': 0
    }
    
    for f in findings:
        status = f.get('status', 'Open') if isinstance(f, dict) else f.status
        if status in ['Open', 'Investigating']:
            sev = (f.get('severity') if isinstance(f, dict) else f.severity).upper()
            if sev in counts:
                counts[sev] += 1
            counts['TOTAL'] += 1

    return counts
