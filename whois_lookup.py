"""Whois domain expiration lookup."""
import config

def lookup_expiration(domain):
    """Return expiration date string (YYYY-MM-DD) or empty."""
    try:
        import whois  # python-whois / whois package
    except ImportError:
        return ""
    try:
        w = whois.whois(domain)
        exp = w.get("expiration_date")
        if not exp:
            return ""
        if isinstance(exp, list):
            exp = exp[0]
        return exp.strftime("%Y-%m-%d") if hasattr(exp, "strftime") else str(exp)[:10]
    except Exception:
        return ""
