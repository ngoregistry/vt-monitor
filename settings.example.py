# Add your VirusTotal API key and endpoints here 
API_KEY = ''
API_URL_IP = 'https://www.virustotal.com/api/v3/ip_addresses/'
API_URL_DOMAIN = 'https://www.virustotal.com/api/v3/domains/'
API_URL_SUBDOMAINS = 'https://www.virustotal.com/api/v3/domains/{}/subdomains'

# Email/SMTP Configuration (can be overridden by environment variables)
SMTP_SERVER = 'smtp.gmail.com'
SMTP_PORT = 587
SMTP_USERNAME = 'your-email@gmail.com'
SMTP_PASSWORD = 'your-app-password'  # Use app password for Gmail
SMTP_USE_TLS = True

# Email Settings
EMAIL_FROM = 'your-email@gmail.com'
EMAIL_TO = ['security@yourcompany.com', 'admin@yourcompany.com']  # List of recipient emails
EMAIL_SUBJECT = 'Domain Security Report - {date}'
EMAIL_REPLY_TO = 'noreply@yourcompany.com'

# Report Settings
COMPANY_NAME = 'Your Company'
REPORT_TITLE = 'Domain Security Monitoring Report'

