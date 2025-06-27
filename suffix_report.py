#!/usr/bin/env python3
"""
Domain Security Monitoring Script
Automated domain and subdomain security analysis with email reporting
Compatible with GitHub Actions and standalone execution
"""

import os
import sys
import json
import urllib.request
import urllib.parse
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
import ssl

# DNS checking imports
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    print("⚠️ Warning: dnspython not installed. DNS checking will be skipped.")
    print("Install with: pip install dnspython")
    DNS_AVAILABLE = False

# Import our modules
from includes.single_domain import fetch_data
from includes.subdomain_analysis import get_all_subdomains, extract_subdomain_reputation

# Configuration - Environment variables override settings.py
def get_config():
    """Load configuration from environment variables or settings.py"""
    # Set default configuration values
    config = {
        'API_KEY': '',
        'API_URL_DOMAIN': 'https://www.virustotal.com/api/v3/domains/',
        'API_URL_SUBDOMAINS': 'https://www.virustotal.com/api/v3/domains/{}/subdomains',
        'SMTP_SERVER': 'smtp.gmail.com',
        'SMTP_PORT': 587,
        'SMTP_USERNAME': '',
        'SMTP_PASSWORD': '',
        'SMTP_USE_TLS': True,
        'EMAIL_FROM': '',
        'EMAIL_TO': [],
        'EMAIL_SUBJECT': 'Domain Security Report - {date}',
        'EMAIL_REPLY_TO': 'noreply@company.com',
        'COMPANY_NAME': 'Security Team',
        'REPORT_TITLE': 'Domain Security Monitoring Report',
    }
    
    # Try to import from settings, override defaults if available
    try:
        import settings
        config.update({
            'API_KEY': getattr(settings, 'API_KEY', config['API_KEY']),
            'API_URL_DOMAIN': getattr(settings, 'API_URL_DOMAIN', config['API_URL_DOMAIN']),
            'API_URL_SUBDOMAINS': getattr(settings, 'API_URL_SUBDOMAINS', config['API_URL_SUBDOMAINS']),
            'SMTP_SERVER': getattr(settings, 'SMTP_SERVER', config['SMTP_SERVER']),
            'SMTP_PORT': getattr(settings, 'SMTP_PORT', config['SMTP_PORT']),
            'SMTP_USERNAME': getattr(settings, 'SMTP_USERNAME', config['SMTP_USERNAME']),
            'SMTP_PASSWORD': getattr(settings, 'SMTP_PASSWORD', config['SMTP_PASSWORD']),
            'SMTP_USE_TLS': getattr(settings, 'SMTP_USE_TLS', config['SMTP_USE_TLS']),
            'EMAIL_FROM': getattr(settings, 'EMAIL_FROM', config['EMAIL_FROM']),
            'EMAIL_TO': getattr(settings, 'EMAIL_TO', config['EMAIL_TO']),
            'EMAIL_SUBJECT': getattr(settings, 'EMAIL_SUBJECT', config['EMAIL_SUBJECT']),
            'EMAIL_REPLY_TO': getattr(settings, 'EMAIL_REPLY_TO', config['EMAIL_REPLY_TO']),
            'COMPANY_NAME': getattr(settings, 'COMPANY_NAME', config['COMPANY_NAME']),
            'REPORT_TITLE': getattr(settings, 'REPORT_TITLE', config['REPORT_TITLE']),
        })
        print("✓ Using configuration from settings.py")
    except ImportError:
        print("⚠️ settings.py not found, using default configuration and environment variables")
    
    # Override with environment variables
    env_mappings = {
        'VT_API_KEY': 'API_KEY',
        'SMTP_SERVER': 'SMTP_SERVER',
        'SMTP_PORT': 'SMTP_PORT',
        'SMTP_USERNAME': 'SMTP_USERNAME',
        'SMTP_PASSWORD': 'SMTP_PASSWORD',
        'EMAIL_FROM': 'EMAIL_FROM',
        'EMAIL_TO': 'EMAIL_TO',
        'EMAIL_SUBJECT': 'EMAIL_SUBJECT',
        'EMAIL_REPLY_TO': 'EMAIL_REPLY_TO',
        'COMPANY_NAME': 'COMPANY_NAME',
        'REPORT_TITLE': 'REPORT_TITLE',
    }
    
    for env_var, config_key in env_mappings.items():
        if os.getenv(env_var):
            if config_key == 'EMAIL_TO' and os.getenv(env_var):
                # Handle comma-separated email list
                config[config_key] = [email.strip() for email in os.getenv(env_var).split(',')]
            elif config_key == 'SMTP_PORT':
                config[config_key] = int(os.getenv(env_var, 587))
            else:
                config[config_key] = os.getenv(env_var)
    
    return config

def read_domains_from_file(filename='suffix.txt'):
    """Read domains from suffix.txt file"""
    domains = []
    try:
        with open(filename, 'r') as file:
            for line in file:
                line = line.strip()
                if line and not line.startswith('#'):
                    domains.append(line)
    except FileNotFoundError:
        print(f"ERROR: {filename} not found!")
        sys.exit(1)
    return domains

def check_dns_records(subdomain):
    """
    Check if a subdomain has DNS records (A or NS records).
    Returns True if subdomain has at least one A record OR one NS record.
    Returns False if subdomain has neither A nor NS records.
    """
    if not DNS_AVAILABLE:
        return True  # Skip DNS checking if library not available
    
    try:
        has_a_record = False
        has_ns_record = False
        
        # Check for A records
        try:
            dns.resolver.resolve(subdomain, 'A')
            has_a_record = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        
        # Check for NS records
        try:
            dns.resolver.resolve(subdomain, 'NS')
            has_ns_record = True
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, dns.exception.DNSException):
            pass
        
        # Return True if at least one record type exists
        return has_a_record or has_ns_record
        
    except Exception as e:
        # In case of any unexpected error, include the subdomain to be safe
        print(f"  DNS check error for {subdomain}: {e}")
        return True

def analyze_domain(domain, config):
    """Analyze a single domain and return results"""
    print(f"\n{'='*60}")
    print(f"ANALYZING DOMAIN: {domain}")
    print(f"{'='*60}")
    
    # Get domain analysis
    url = config['API_URL_DOMAIN'] + urllib.parse.quote(domain)
    domain_data = fetch_data(url)
    
    if not domain_data:
        return {
            'domain': domain,
            'error': 'Failed to retrieve domain data',
            'domain_stats': None,
            'subdomains': [],
            'subdomain_stats': {'total': 0, 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'timeout': 0}
        }
    
    # Extract domain stats
    attributes = domain_data.get('data', {}).get('attributes', {})
    domain_stats = attributes.get('last_analysis_stats', {})
    
    print(f"Domain Analysis: M:{domain_stats.get('malicious', 0)}, S:{domain_stats.get('suspicious', 0)}, "
          f"U:{domain_stats.get('undetected', 0)}, H:{domain_stats.get('harmless', 0)}, T:{domain_stats.get('timeout', 0)}")
    
    # Get subdomain analysis
    print("Fetching subdomains...")
    subdomains_list = get_all_subdomains(domain)
    
    subdomain_results = []
    subdomain_stats = {'total': 0, 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'timeout': 0}
    dns_filtered_count = 0
    
    if subdomains_list:
        print(f"Analyzing {len(subdomains_list)} subdomains...")
        if DNS_AVAILABLE:
            print("  DNS filtering enabled: excluding subdomains without A or NS records")
        
        for i, subdomain_obj in enumerate(subdomains_list, 1):
            subdomain_name = subdomain_obj.get('id', '')
            if not subdomain_name:
                continue
                
            if i % 50 == 0:  # Progress indicator for large lists
                print(f"  Progress: {i}/{len(subdomains_list)} subdomains processed...")
            
            # Check DNS records - skip if no A or NS records
            if not check_dns_records(subdomain_name):
                dns_filtered_count += 1
                if i % 100 == 0:  # Occasional logging for filtered entries
                    print(f"    Filtered {subdomain_name} (no DNS records)")
                continue
            
            reputation_data = extract_subdomain_reputation(subdomain_obj)
            
            if reputation_data and reputation_data['domain']:
                subdomain_results.append(reputation_data)
                subdomain_stats['total'] += 1
                
                # Categorize subdomain
                if reputation_data['malicious'] > 0:
                    subdomain_stats['malicious'] += 1
                elif reputation_data['suspicious'] > 0:
                    subdomain_stats['suspicious'] += 1
                elif reputation_data['timeout'] > 0:
                    subdomain_stats['timeout'] += 1
                elif reputation_data['harmless'] > 0:
                    subdomain_stats['harmless'] += 1
                else:
                    subdomain_stats['undetected'] += 1
    
    print(f"Subdomain Summary: Total:{subdomain_stats['total']}, "
          f"🔴M:{subdomain_stats['malicious']}, 🟡S:{subdomain_stats['suspicious']}, "
          f"🟢H:{subdomain_stats['harmless']}, ⚪U:{subdomain_stats['undetected']}, "
          f"⏱️T:{subdomain_stats['timeout']}")
    if dns_filtered_count > 0:
        print(f"DNS Filtered: {dns_filtered_count} subdomains excluded (no A/NS records)")
    
    return {
        'domain': domain,
        'domain_stats': domain_stats,
        'domain_reputation': attributes.get('reputation', 0),
        'subdomains': subdomain_results,
        'subdomain_stats': subdomain_stats,
        'dns_filtered_count': dns_filtered_count,
        'creation_date': attributes.get('creation_date'),
        'last_analysis_date': attributes.get('last_analysis_date'),
    }

def generate_console_summary(results):
    """Generate and print console summary"""
    print(f"\n{'='*80}")
    print("DOMAIN SECURITY MONITORING SUMMARY")
    print(f"{'='*80}")
    print(f"Report Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}")
    print(f"Total Domains Analyzed: {len(results)}")
    
    total_subdomains = 0
    total_malicious_domains = 0
    total_malicious_subdomains = 0
    total_suspicious_subdomains = 0
    
    for result in results:
        if 'error' in result:
            print(f"\n❌ {result['domain']}: ERROR - {result['error']}")
            continue
            
        domain_stats = result['domain_stats']
        subdomain_stats = result['subdomain_stats']
        
        # Domain status
        domain_malicious = domain_stats.get('malicious', 0) > 0
        if domain_malicious:
            total_malicious_domains += 1
            status = "🔴 MALICIOUS"
        elif domain_stats.get('suspicious', 0) > 0:
            status = "🟡 SUSPICIOUS"
        elif domain_stats.get('harmless', 0) > 0:
            status = "🟢 HARMLESS"
        else:
            status = "⚪ UNDETECTED"
        
        total_subdomains += subdomain_stats['total']
        total_malicious_subdomains += subdomain_stats['malicious']
        total_suspicious_subdomains += subdomain_stats['suspicious']
        
        print(f"\n{status} {result['domain']}")
        print(f"  Domain: M:{domain_stats.get('malicious', 0)}, S:{domain_stats.get('suspicious', 0)}, "
              f"H:{domain_stats.get('harmless', 0)}, U:{domain_stats.get('undetected', 0)}")
        print(f"  Subdomains: {subdomain_stats['total']} total, "
              f"🔴{subdomain_stats['malicious']} malicious, "
              f"🟡{subdomain_stats['suspicious']} suspicious")
        
        # Show DNS filtering info in main result if applicable
        if 'dns_filtered_count' in result and result['dns_filtered_count'] > 0:
            print(f"  DNS Filtered: {result['dns_filtered_count']} excluded (no A/NS records)")
        
        # Alert on high-risk findings
        if subdomain_stats['malicious'] > 0:
            print(f"  ⚠️  ALERT: {subdomain_stats['malicious']} malicious subdomains detected!")
        if subdomain_stats['suspicious'] > 0:
            print(f"  ⚠️  WARNING: {subdomain_stats['suspicious']} suspicious subdomains detected!")
    
    print(f"\n{'='*80}")
    print("OVERALL SUMMARY")
    print(f"{'='*80}")
    print(f"🔴 Malicious Domains: {total_malicious_domains}")
    print(f"🔴 Malicious Subdomains: {total_malicious_subdomains}")
    print(f"🟡 Suspicious Subdomains: {total_suspicious_subdomains}")
    print(f"📊 Total Subdomains Analyzed: {total_subdomains}")
    
    if total_malicious_domains > 0 or total_malicious_subdomains > 0:
        print(f"\n🚨 SECURITY ALERT: Malicious activity detected!")
    elif total_suspicious_subdomains > 0:
        print(f"\n⚠️  WARNING: Suspicious activity detected!")
    else:
        print(f"\n✅ All domains and subdomains appear clean!")

def generate_txt_report(results, config):
    """Generate detailed text report"""
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    report_lines = [
        f"{config['REPORT_TITLE']}",
        f"Generated by: {config['COMPANY_NAME']}",
        f"Report Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}",
        f"{'='*80}",
        "",
        "EXECUTIVE SUMMARY",
        f"{'='*80}",
    ]
    
    total_domains = len(results)
    total_subdomains = sum(r.get('subdomain_stats', {}).get('total', 0) for r in results if 'error' not in r)
    total_malicious_domains = sum(1 for r in results if 'error' not in r and r.get('domain_stats', {}).get('malicious', 0) > 0)
    total_malicious_subdomains = sum(r.get('subdomain_stats', {}).get('malicious', 0) for r in results if 'error' not in r)
    total_suspicious_subdomains = sum(r.get('subdomain_stats', {}).get('suspicious', 0) for r in results if 'error' not in r)
    
    report_lines.extend([
        f"Total Domains Monitored: {total_domains}",
        f"Total Subdomains Analyzed: {total_subdomains}",
        f"Malicious Domains Found: {total_malicious_domains}",
        f"Malicious Subdomains Found: {total_malicious_subdomains}",
        f"Suspicious Subdomains Found: {total_suspicious_subdomains}",
        "",
        "DETAILED ANALYSIS",
        f"{'='*80}",
        ""
    ])
    
    for result in results:
        if 'error' in result:
            report_lines.extend([
                f"DOMAIN: {result['domain']} - ERROR",
                f"Error: {result['error']}",
                f"{'-'*60}",
                ""
            ])
            continue
        
        domain = result['domain']
        domain_stats = result['domain_stats']
        subdomain_stats = result['subdomain_stats']
        
        report_lines.extend([
            f"DOMAIN: {domain}",
            f"Reputation Score: {result.get('domain_reputation', 0)}",
            f"Creation Date: {result.get('creation_date', 'Unknown')}",
            f"Last Analysis: {result.get('last_analysis_date', 'Unknown')}",
            f"Domain Analysis: Malicious:{domain_stats.get('malicious', 0)}, "
            f"Suspicious:{domain_stats.get('suspicious', 0)}, "
            f"Harmless:{domain_stats.get('harmless', 0)}, "
            f"Undetected:{domain_stats.get('undetected', 0)}, "
            f"Timeout:{domain_stats.get('timeout', 0)}",
            "",
            f"SUBDOMAINS ({subdomain_stats['total']} total):",
            f"Malicious: {subdomain_stats['malicious']}",
            f"Suspicious: {subdomain_stats['suspicious']}",
            f"Harmless: {subdomain_stats['harmless']}",
            f"Undetected: {subdomain_stats['undetected']}",
            f"Timeout: {subdomain_stats['timeout']}",
        ])
        
        # Add DNS filtering information if applicable
        if result.get('dns_filtered_count', 0) > 0:
            report_lines.append(f"DNS Filtered: {result['dns_filtered_count']} (excluded - no A/NS records)")
        
        report_lines.append("")
        
        # List malicious subdomains
        malicious_subs = [s for s in result['subdomains'] if s['malicious'] > 0]
        if malicious_subs:
            report_lines.append("🔴 MALICIOUS SUBDOMAINS:")
            for sub in malicious_subs:
                report_lines.append(f"  - {sub['domain']} (M:{sub['malicious']}, S:{sub['suspicious']}, Rep:{sub['reputation']})")
            report_lines.append("")
        
        # List suspicious subdomains
        suspicious_subs = [s for s in result['subdomains'] if s['suspicious'] > 0 and s['malicious'] == 0]
        if suspicious_subs:
            report_lines.append("🟡 SUSPICIOUS SUBDOMAINS:")
            for sub in suspicious_subs:
                report_lines.append(f"  - {sub['domain']} (S:{sub['suspicious']}, Rep:{sub['reputation']})")
            report_lines.append("")
        
        report_lines.extend([f"{'-'*60}", ""])
    
    # Save report
    os.makedirs('output/automated-reports', exist_ok=True)
    report_path = f'output/automated-reports/domain-security-report-{timestamp}.txt'
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(report_lines))
    
    print(f"\n📄 Detailed report saved to: {report_path}")
    return report_path, '\n'.join(report_lines)

def defang_domain(domain):
    """Replace dots with [.] to defang domains for security emails"""
    return domain.replace('.', '[.]')

def generate_html_email(results, config):
    """Generate HTML email content"""
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')
    
    # Calculate summary stats
    total_domains = len(results)
    total_subdomains = sum(r.get('subdomain_stats', {}).get('total', 0) for r in results if 'error' not in r)
    total_malicious_domains = sum(1 for r in results if 'error' not in r and r.get('domain_stats', {}).get('malicious', 0) > 0)
    total_malicious_subdomains = sum(r.get('subdomain_stats', {}).get('malicious', 0) for r in results if 'error' not in r)
    total_suspicious_subdomains = sum(r.get('subdomain_stats', {}).get('suspicious', 0) for r in results if 'error' not in r)
    
    # Determine alert level
    if total_malicious_domains > 0 or total_malicious_subdomains > 0:
        alert_level = "HIGH"
        alert_color = "#dc3545"
        alert_icon = "🚨"
    elif total_suspicious_subdomains > 0:
        alert_level = "MEDIUM"
        alert_color = "#ffc107"
        alert_icon = "⚠️"
    else:
        alert_level = "LOW"
        alert_color = "#28a745"
        alert_icon = "✅"
    
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>{config['REPORT_TITLE']}</title>
        <style>
            body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }}
            .container {{ max-width: 800px; margin: 0 auto; background-color: white; border-radius: 8px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }}
            .header {{ background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); color: white; padding: 30px; border-radius: 8px 8px 0 0; text-align: center; }}
            .header h1 {{ margin: 0; font-size: 28px; font-weight: 300; }}
            .header p {{ margin: 10px 0 0 0; opacity: 0.9; }}
            .alert {{ padding: 20px; margin: 20px; border-radius: 6px; text-align: center; font-weight: bold; }}
            .alert.high {{ background-color: #f8d7da; border: 1px solid #f5c6cb; color: #721c24; }}
            .alert.medium {{ background-color: #fff3cd; border: 1px solid #ffeaa7; color: #856404; }}
            .alert.low {{ background-color: #d4edda; border: 1px solid #c3e6cb; color: #155724; }}
            .summary {{ padding: 30px; }}
            .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }}
            .stat-card {{ background: #f8f9fa; padding: 20px; border-radius: 6px; text-align: center; border-left: 4px solid #667eea; }}
            .stat-number {{ font-size: 32px; font-weight: bold; color: #333; margin-bottom: 5px; }}
            .stat-label {{ color: #666; font-size: 14px; }}
            .domain-section {{ margin: 30px 0; }}
            .domain-header {{ background-color: #e9ecef; padding: 15px; border-radius: 6px; margin-bottom: 15px; }}
            .domain-name {{ font-size: 18px; font-weight: bold; color: #333; }}
            .domain-stats {{ margin-top: 5px; font-size: 14px; color: #666; }}
            .subdomain-list {{ margin: 15px 0; }}
            .subdomain-item {{ padding: 8px 12px; margin: 5px 0; border-radius: 4px; font-size: 14px; }}
            .malicious {{ background-color: #f8d7da; border-left: 4px solid #dc3545; }}
            .suspicious {{ background-color: #fff3cd; border-left: 4px solid #ffc107; }}
            .footer {{ background-color: #f8f9fa; padding: 20px; border-radius: 0 0 8px 8px; text-align: center; color: #666; font-size: 12px; }}
            .status-badge {{ display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: bold; margin-left: 10px; }}
            .status-malicious {{ background-color: #dc3545; color: white; }}
            .status-suspicious {{ background-color: #ffc107; color: black; }}
            .status-clean {{ background-color: #28a745; color: white; }}
        </style>
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1>{config['REPORT_TITLE']}</h1>
                <p>Generated by {config['COMPANY_NAME']} • {timestamp}</p>
            </div>
            
            <div class="alert alert.{alert_level.lower()}">
                {alert_icon} <strong>Security Alert Level: {alert_level}</strong>
            </div>
            
            <div class="summary">
                <h2>Executive Summary</h2>
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">{total_domains}</div>
                        <div class="stat-label">Domains Monitored</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">{total_subdomains}</div>
                        <div class="stat-label">Subdomains Analyzed</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #dc3545;">{total_malicious_domains + total_malicious_subdomains}</div>
                        <div class="stat-label">Malicious Threats</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number" style="color: #ffc107;">{total_suspicious_subdomains}</div>
                        <div class="stat-label">Suspicious Items</div>
                    </div>
                </div>
            </div>
    """
    
    # Add domain details
    for result in results:
        if 'error' in result:
            html_content += f"""
            <div class="domain-section">
                <div class="domain-header">
                    <div class="domain-name">{defang_domain(result['domain'])} <span class="status-badge" style="background-color: #6c757d; color: white;">ERROR</span></div>
                    <div class="domain-stats">Error: {result['error']}</div>
                </div>
            </div>
            """
            continue
        
        domain = result['domain']
        domain_stats = result['domain_stats']
        subdomain_stats = result['subdomain_stats']
        
        # Determine domain status
        if domain_stats.get('malicious', 0) > 0:
            status_badge = '<span class="status-badge status-malicious">MALICIOUS</span>'
        elif domain_stats.get('suspicious', 0) > 0:
            status_badge = '<span class="status-badge status-suspicious">SUSPICIOUS</span>'
        else:
            status_badge = '<span class="status-badge status-clean">CLEAN</span>'
        
        html_content += f"""
        <div class="domain-section">
            <div class="domain-header">
                <div class="domain-name">{defang_domain(domain)} {status_badge}</div>
                <div class="domain-stats">
                    Domain: M:{domain_stats.get('malicious', 0)} S:{domain_stats.get('suspicious', 0)} H:{domain_stats.get('harmless', 0)} U:{domain_stats.get('undetected', 0)} • 
                    Subdomains: {subdomain_stats['total']} total, {subdomain_stats['malicious']} malicious, {subdomain_stats['suspicious']} suspicious
                    {f" • DNS Filtered: {result.get('dns_filtered_count', 0)}" if result.get('dns_filtered_count', 0) > 0 else ""}
                </div>
            </div>
        """
        
        # Show malicious/suspicious subdomains
        malicious_subs = [s for s in result['subdomains'] if s['malicious'] > 0]
        suspicious_subs = [s for s in result['subdomains'] if s['suspicious'] > 0 and s['malicious'] == 0]
        
        if malicious_subs or suspicious_subs:
            html_content += '<div class="subdomain-list">'
            
            for sub in malicious_subs:
                html_content += f'<div class="subdomain-item malicious">🔴 <strong>{defang_domain(sub["domain"])}</strong> (M:{sub["malicious"]}, Rep:{sub["reputation"]})</div>'
            
            for sub in suspicious_subs:
                html_content += f'<div class="subdomain-item suspicious">🟡 <strong>{defang_domain(sub["domain"])}</strong> (S:{sub["suspicious"]}, Rep:{sub["reputation"]})</div>'
            
            html_content += '</div>'
        
        html_content += '</div>'
    
    html_content += f"""
            <div class="footer">
                <p>This report was automatically generated by the Domain Security Monitoring System.</p>
                <p>For questions or concerns, please contact your security team.</p>
            </div>
        </div>
    </body>
    </html>
    """
    
    return html_content

def send_email_report(results, config, report_path):
    """Send email report"""
    try:
        print("\n📧 Sending email report...")
        
        # Create message
        msg = MIMEMultipart('alternative')
        msg['From'] = config['EMAIL_FROM']
        msg['To'] = ', '.join(config['EMAIL_TO'])
        msg['Subject'] = config['EMAIL_SUBJECT'].format(date=datetime.now().strftime('%Y-%m-%d'))
        if config.get('EMAIL_REPLY_TO'):
            msg['Reply-To'] = config['EMAIL_REPLY_TO']
        
        # Generate HTML content
        html_content = generate_html_email(results, config)
        
        # Create text and HTML parts
        text_part = MIMEText("Please view this email in HTML format for the full report.", 'plain')
        html_part = MIMEText(html_content, 'html')
        
        msg.attach(text_part)
        msg.attach(html_part)
        
        # Attach text report
        with open(report_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename= {os.path.basename(report_path)}'
            )
            msg.attach(part)
        
        # Send email
        context = ssl.create_default_context()
        with smtplib.SMTP(config['SMTP_SERVER'], config['SMTP_PORT']) as server:
            if config['SMTP_USE_TLS']:
                server.starttls(context=context)
            server.login(config['SMTP_USERNAME'], config['SMTP_PASSWORD'])
            server.sendmail(config['EMAIL_FROM'], config['EMAIL_TO'], msg.as_string())
        
        print(f"✅ Email sent successfully to: {', '.join(config['EMAIL_TO'])}")
        
    except Exception as e:
        print(f"❌ Failed to send email: {e}")
        print("Report generation completed, but email delivery failed.")

def main():
    """Main execution function"""
    print("🔍 Domain Security Monitoring System")
    print("====================================")
    
    # Load configuration
    config = get_config()
    
    # Validate required configuration
    required_fields = ['API_KEY', 'API_URL_DOMAIN', 'API_URL_SUBDOMAINS']
    missing_fields = [field for field in required_fields if not config.get(field)]
    
    if missing_fields:
        print(f"❌ Missing required configuration: {', '.join(missing_fields)}")
        print("Please check your settings.py file or environment variables.")
        sys.exit(1)
    
    # Read domains to monitor
    domains = read_domains_from_file()
    if not domains:
        print("❌ No domains found in suffix.txt")
        sys.exit(1)
    
    print(f"📋 Monitoring {len(domains)} domains: {', '.join(domains)}")
    
    # Analyze all domains
    results = []
    for domain in domains:
        try:
            result = analyze_domain(domain, config)
            results.append(result)
        except Exception as e:
            print(f"❌ Error analyzing {domain}: {e}")
            results.append({
                'domain': domain,
                'error': str(e),
                'domain_stats': None,
                'subdomains': [],
                'subdomain_stats': {'total': 0, 'malicious': 0, 'suspicious': 0, 'harmless': 0, 'undetected': 0, 'timeout': 0}
            })
    
    # Generate console summary
    generate_console_summary(results)
    
    # Calculate threat statistics
    total_malicious_domains = 0
    total_malicious_subdomains = 0
    
    for result in results:
        if 'error' not in result:
            # Count malicious domains
            domain_stats = result.get('domain_stats', {})
            if domain_stats.get('malicious', 0) > 0:
                total_malicious_domains += 1
            
            # Count malicious subdomains
            subdomain_stats = result.get('subdomain_stats', {})
            total_malicious_subdomains += subdomain_stats.get('malicious', 0)
    
    total_malicious_threats = total_malicious_domains + total_malicious_subdomains
    
    # Generate detailed report
    report_path, report_content = generate_txt_report(results, config)
    
    # Send email if configured
    if config.get('EMAIL_FROM') and config.get('EMAIL_TO') and config.get('SMTP_SERVER'):
        send_email_report(results, config, report_path)
    else:
        print("\n📧 Email not configured - skipping email notification")
        print("To enable email notifications, configure SMTP settings in settings.py or environment variables")
    
    print(f"\n✅ Domain security monitoring completed!")
    print(f"📄 Report saved to: {report_path}")
    
    # Exit with specific code if malicious threats detected
    if total_malicious_threats > 0:
        print(f"\n🚨 SECURITY ALERT: {total_malicious_threats} malicious threats detected!")
        print("Exiting with code 2 to trigger GitHub Actions alert...")
        sys.exit(2)  # Exit code 2 indicates malicious threats found

if __name__ == "__main__":
    main() 