
def parse_single_cookie(cookie_str):
    if not cookie_str or not isinstance(cookie_str, str):
        return None
    parts = [p.strip() for p in cookie_str.split(";") if p.strip()]
    if not parts:
        return None
    first_part = parts[0]
    if "=" not in first_part:
        return None
    cookie_name, _ = first_part.split("=", 1)
    cookie_name = cookie_name.strip()
    if not cookie_name:
        return None

    flags_lower = {p.lower() for p in parts[1:]}
    has_secure = "secure" in flags_lower
    has_httponly = "httponly" in flags_lower

    samesite_val = None
    for p in parts[1:]:
        if "=" in p:
            k, v = p.split("=", 1)
            if k.strip().lower() == "samesite":
                samesite_val = v.strip().capitalize()
                break

    missing = []
    if not has_httponly:
        missing.append("HttpOnly")
    if not has_secure:
        missing.append("Secure")
    if not samesite_val:
        missing.append("SameSite")
    elif samesite_val.lower() == "none" and not has_secure:
        missing.append("SameSite=None without Secure")

    return {
        "name": cookie_name,
        "secure": has_secure,
        "httponly": has_httponly,
        "samesite": samesite_val or "Eksik",
        "missing": missing,
        "is_insecure": len(missing) > 0,
    }


def audit_cookies(cookie_headers):
    results = []
    if not cookie_headers:
        return results
    if isinstance(cookie_headers, str):
        cookie_headers = [cookie_headers]
    for raw in cookie_headers:
        audited = parse_single_cookie(raw)
        if audited:
            results.append(audited)
    return results
