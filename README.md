# Multi-Tenant Subdomain Security Monitor

The Multi-Tenant Subdomain Security Monitor is a security tool designed for organizations that provide subdomains to untrusted users, such as SaaS platforms offering customer-specific subdomains (e.g., customer.yoursaas.com), educational institutions hosting student projects, or free subdomain providers. It helps detect and prevent malicious activities, phishing attempts, and security threats that could arise when third parties have control over subdomains within your domain space. By continuously monitoring subdomain reputations and analyzing security indicators, it provides early warning of potential abuse and helps maintain the integrity of your domain infrastructure.

## Features

- Fetches detailed information about IP addresses and domains from VirusTotal.
- Provides security details (reputation score, malicious counts, etc.).
- Discovers and analyzes all subdomains of a given domain to identify malicious, suspicious, undetected, harmless, or timeout subdomains.
- **Automated Domain Monitoring**: Continuous monitoring of multiple domains with email reporting via `suffix_report.py`.
- **GitHub Actions Integration**: Automated scheduled scanning with email alerts and artifact storage.
- Outputs results to timestamped files in the `output` directory. (the output directory will be created on your first run)

## Prerequisites

- Python 3.6 or later.
- An API key from [VirusTotal](https://www.virustotal.com/).
- For automated monitoring: SMTP server credentials for email reporting.
- For DNS filtering: `dnspython` library (optional, install with `pip install dnspython`).

## Quick Start

1. **Get a VirusTotal API key** from [VirusTotal](https://www.virustotal.com/)
2. **Set environment variable** (simplest setup):
   ```bash
   export VT_API_KEY="your-virustotal-api-key-here"
   python suffix_report.py
   ```
3. **Or create settings.py** for persistent configuration:
   ```bash
   cp settings.example.py settings.py
   # Edit settings.py with your API key
   ```

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/yourusername/subdomain-vt-security-monitor.git
   cd subdomain-vt-security-monitor
   ```

2. **Install dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

3. **Configure your settings:**
   ```bash
   cp settings.example.py settings.py
   # Edit settings.py with your VirusTotal API key and email configuration
   ```

## Usage

### Interactive Mode

Run the main script for interactive domain and IP analysis:

```bash
python vt.py
```

This provides options for:

- Single IP address analysis
- Single domain analysis
- IP/Domain list analysis
- Subdomain analysis

### Automated Domain Monitoring

The `suffix_report.py` script provides automated monitoring of multiple domains with email reporting:

#### Basic Usage

```bash
python suffix_report.py
```

#### Configuration

1. **Domain List**: Edit `suffix.txt` to add domains you want to monitor:

   ```
   # Domain monitoring list - one domain per line
   # Lines starting with # are ignored
   example.com
   yourdomain.org
   another-domain.net
   ```

2. **Settings**: Configure `settings.py` with your credentials:

   ```python
   # VirusTotal API
   API_KEY = 'your-virustotal-api-key'

   # Email/SMTP Configuration
   SMTP_SERVER = 'smtp.gmail.com'
   SMTP_PORT = 587
   SMTP_USERNAME = 'your-email@gmail.com'
   SMTP_PASSWORD = 'your-app-password'  # Use app password for Gmail

   # Email Settings
   EMAIL_FROM = 'your-email@gmail.com'
   EMAIL_TO = ['security@yourcompany.com', 'admin@yourcompany.com']
   EMAIL_SUBJECT = 'Domain Security Report - {date}'
   ```

#### Features

- **Comprehensive Analysis**: Analyzes both main domains and all subdomains
- **DNS Filtering**: Optionally filters out subdomains without DNS records (requires `dnspython`)
- **Email Reporting**: Sends detailed HTML reports with security findings
- **Progress Tracking**: Real-time progress updates during analysis
- **Multiple Output Formats**: Console summary, text report, and email report

#### Output

The script generates:

- Console summary with security statistics
- Text report saved to `output/automated-reports/`
- Email report with detailed findings and recommendations

### GitHub Actions Automation

Set up automated monitoring with GitHub Actions for continuous security monitoring.

#### 1. Repository Setup

1. **Fork or clone** this repository to your GitHub account
2. **Add your domains** to `suffix.txt`
3. **Configure secrets** in your repository settings

#### 2. GitHub Secrets Configuration

Go to your repository → Settings → Secrets and variables → Actions, then add these secrets:

**Required Secrets:**

- `VT_API_KEY`: Your VirusTotal API key
- `SMTP_SERVER`: SMTP server (e.g., `smtp.gmail.com`)
- `SMTP_PORT`: SMTP port (e.g., `587`)
- `SMTP_USERNAME`: Your email username
- `SMTP_PASSWORD`: Your email password or app password
- `EMAIL_FROM`: Sender email address
- `EMAIL_TO`: Comma-separated recipient emails (e.g., `"admin@company.com,security@company.com"`)

**Optional Secrets:**

- `EMAIL_SUBJECT`: Custom email subject (default: `"Domain Security Report - {date}"`)
- `EMAIL_REPLY_TO`: Reply-to email address
- `COMPANY_NAME`: Your organization name (default: `"Security Team"`)
- `REPORT_TITLE`: Custom report title (default: `"Automated Domain Security Report"`)

#### 3. Workflow Configuration

The workflow is already configured in `.github/workflows/domain-monitoring.yml`:

- **Schedule**: Runs every Monday at 8:00 AM UTC (configurable)
- **Manual Trigger**: Can be run manually via GitHub Actions tab
- **Artifacts**: Uploads reports for 30-day retention
- **Security Alerts**: Creates GitHub issues on high-severity findings

#### 4. Customizing the Schedule

Edit `.github/workflows/domain-monitoring.yml` to change the schedule:

```yaml
on:
  schedule:
    # Run daily at 6 AM UTC
    - cron: "0 6 * * *"

    # Run every 6 hours
    - cron: "0 */6 * * *"

    # Run on weekdays only
    - cron: "0 8 * * 1-5"
```

#### 5. Monitoring and Alerts

- **Email Reports**: Receive detailed security reports via email
- **GitHub Issues**: Automatic issue creation for security alerts
- **Artifacts**: Download reports from the Actions tab
- **Logs**: View detailed execution logs in the Actions tab

## Subdomain Analysis

The subdomain analysis feature allows you to:

1. **Discover Subdomains**: Automatically finds all direct subdomains of a given domain using VirusTotal's subdomain relationship API.
2. **Analyze Each Subdomain**: Checks the reputation of each discovered subdomain against VirusTotal's security engines.
3. **Categorize Results**: Organizes subdomains into categories:
   - 🔴 **MALICIOUS**: Subdomains flagged as malicious by security engines
   - 🟡 **SUSPICIOUS**: Subdomains flagged as suspicious
   - ⚪ **UNDETECTED**: Subdomains with no detections
   - 🟢 **HARMLESS**: Subdomains classified as harmless
   - ⏱️ **TIMEOUT**: Subdomains that timed out during analysis
4. **Detailed Reporting**: Provides comprehensive reports with:
   - Summary statistics for each category
   - Detailed breakdown showing engine detection counts (M:malicious, S:suspicious, U:undetected, H:harmless, T:timeout)
   - Reputation scores for each subdomain
   - Timestamped output files for record keeping

### Example Usage

When you select option 4 (Subdomain Analysis), you'll be prompted to enter a domain (e.g., `is-a-suffix.tld`). The tool will then:

1. Query VirusTotal for all subdomains of the specified domain
2. Analyze each subdomain's reputation
3. Display real-time progress as each subdomain is processed
4. Generate a comprehensive summary report
5. Save detailed results to a timestamped file in `output/subdomain-analysis/`

This feature is particularly useful for:

- Security researchers investigating potentially compromised domains
- IT administrators monitoring their organization's domain infrastructure
- Threat hunters looking for malicious subdomains in their environment

## Environment Variables

For automated deployments, you can use environment variables instead of `settings.py`:

```bash
export VT_API_KEY="your-api-key"
export SMTP_SERVER="smtp.gmail.com"
export SMTP_PORT="587"
export SMTP_USERNAME="your-email@gmail.com"
export SMTP_PASSWORD="your-app-password"
export EMAIL_FROM="your-email@gmail.com"
export EMAIL_TO="admin@company.com,security@company.com"
export COMPANY_NAME="Your Company"
export REPORT_TITLE="Security Monitoring Report"
```

## Troubleshooting

### Common Issues

1. **API Rate Limits**: VirusTotal has rate limits. The script includes delays between requests.
2. **SMTP Authentication**: Use app passwords for Gmail and enable 2FA.
3. **DNS Filtering**: Install `dnspython` for DNS record filtering: `pip install dnspython`
4. **Email Delivery**: Check spam folders and verify SMTP settings.

### Debug Mode

Run with verbose output:

```bash
python suffix_report.py --verbose
```

## Security Considerations

- Store API keys and credentials securely (use GitHub Secrets for automation)
- Use app passwords instead of regular passwords for email
- Regularly rotate API keys and credentials
- Monitor GitHub Actions usage and costs
- Review security reports promptly

## Acknowledgement

Original author of `virustotal-ip-rep`: https://github.com/Dan-Duran/virustotal-ip-rep

## License

This project is licensed under the MIT License.
