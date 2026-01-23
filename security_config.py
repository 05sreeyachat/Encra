import os

# Security Header Config (Talisman)
CSP = {
    'default-src': '\'self\'',
    'script-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        '\'unsafe-eval\'',
        'https://cdnjs.cloudflare.com',
        'https://cdn.jsdelivr.net'
    ],
    'style-src': [
        '\'self\'',
        '\'unsafe-inline\'',
        'https://cdnjs.cloudflare.com',
        'https://fonts.googleapis.com'
    ],
    'img-src': [
        '\'self\'',
        'data:',
        'blob:'
    ],
    'font-src': [
        '\'self\'',
        'https://cdnjs.cloudflare.com',
        'https://fonts.gstatic.com'
    ],
    'connect-src': [
        '\'self\'',
        'https://ip-api.com'
    ],
    'media-src': [
        '\'self\'',
        'blob:'
    ],
    'frame-src': [
        '\'self\'',
        'data:',
        'blob:'
    ]
}

SECURE_HEADERS = {
    'strict_transport_security': True,
    'strict_transport_security_max_age': 31536000, # 1 year
    'strict_transport_security_include_subdomains': True,
    'force_https': True,
    'frame_options': 'DENY',
    'content_security_policy': CSP,
    'referrer_policy': 'strict-origin-when-cross-origin'
}

# Session Management
SESSION_LIFETIME = 600 # 10 minutes

# Rate Limiting
GLOBAL_LIMITS = ["200 per hour", "20 per minute"]
ROUTE_LIMITS = {
    'open': '10 per minute',
    'verify': '5 per minute',
    'decrypt': '3 per minute',
    'encrypt': '5 per minute'
}

# SMTP Config (Env vars fallback)
SMTP_USER = os.environ.get('SMTP_USER', 'chatterjeesreeya@gmail.com')
SMTP_PASS = os.environ.get('SMTP_PASS', 'artr blif jkhq givi')
