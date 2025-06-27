import os
import json
import urllib.request
import urllib.parse
from datetime import datetime

# Configuration - try to import from settings, fallback to environment variables
try:
    from settings import API_KEY, API_URL_SUBDOMAINS
except ImportError:
    API_KEY = os.getenv('VT_API_KEY', '')
    API_URL_SUBDOMAINS = 'https://www.virustotal.com/api/v3/domains/{}/subdomains'

def fetch_data(url):
    request = urllib.request.Request(url, headers={'x-apikey': API_KEY})
    try:
        with urllib.request.urlopen(request) as response:
            data = json.load(response)
            return data
    except urllib.error.URLError as e:
        print(f"Failed to retrieve data: {e}")
        return None

def get_all_subdomains(domain):
    """Get all subdomains with pagination support"""
    all_subdomains = []
    
    # Start with the first page
    url = API_URL_SUBDOMAINS.format(urllib.parse.quote(domain))
    page_count = 1
    
    while url:
        print(f"Fetching subdomains page {page_count}...")
        data = fetch_data(url)
        
        if not data:
            print(f"Failed to retrieve subdomains page {page_count}")
            break
        
        # Add subdomains from this page
        page_subdomains = data.get('data', [])
        all_subdomains.extend(page_subdomains)
        
        # Check if there's a next page
        links = data.get('links', {})
        url = links.get('next')
        
        if url:
            page_count += 1
            print(f"Found {len(page_subdomains)} subdomains on page {page_count - 1}, continuing to next page...")
        else:
            print(f"Found {len(page_subdomains)} subdomains on page {page_count} (final page)")
    
    return all_subdomains

def extract_subdomain_reputation(subdomain_obj):
    """Extract reputation analysis from subdomain object"""
    subdomain_name = subdomain_obj.get('id', '')
    attributes = subdomain_obj.get('attributes', {})
    
    # Get last_analysis_stats directly from the subdomain response
    last_analysis_stats = attributes.get('last_analysis_stats', {})
    
    return {
        'domain': subdomain_name,
        'malicious': last_analysis_stats.get('malicious', 0),
        'suspicious': last_analysis_stats.get('suspicious', 0),
        'undetected': last_analysis_stats.get('undetected', 0),
        'harmless': last_analysis_stats.get('harmless', 0),
        'timeout': last_analysis_stats.get('timeout', 0),
        'reputation': attributes.get('reputation', 0)
    }

def analyze_subdomains(domain):
    """Main function to analyze subdomains of a given domain"""
    print(f"\nAnalyzing subdomains for: {domain}")
    print("=" * 50)
    
    # Get all subdomains with pagination
    print("Discovering subdomains...")
    subdomains_list = get_all_subdomains(domain)
    
    if not subdomains_list:
        print(f"No subdomains found for {domain}")
        return
    
    print(f"\nTotal subdomains discovered: {len(subdomains_list)}")
    print("=" * 50)
    print("Analyzing reputation data...")
    print("-" * 50)
    
    # Categorize subdomains
    malicious_subdomains = []
    suspicious_subdomains = []
    undetected_subdomains = []
    harmless_subdomains = []
    timeout_subdomains = []
    
    results = []
    
    for i, subdomain_obj in enumerate(subdomains_list, 1):
        subdomain_name = subdomain_obj.get('id', '')
        if not subdomain_name:
            continue
            
        print(f"[{i}/{len(subdomains_list)}] Processing: {subdomain_name}")
        
        # Extract reputation data directly from the subdomain object
        reputation_data = extract_subdomain_reputation(subdomain_obj)
        
        if reputation_data and reputation_data['domain']:
            # Categorize based on highest count
            stats = {
                'malicious': reputation_data['malicious'],
                'suspicious': reputation_data['suspicious'],
                'undetected': reputation_data['undetected'],
                'harmless': reputation_data['harmless'],
                'timeout': reputation_data['timeout']
            }
            
            # Determine primary category
            if stats['malicious'] > 0:
                malicious_subdomains.append(reputation_data)
                category = "MALICIOUS"
            elif stats['suspicious'] > 0:
                suspicious_subdomains.append(reputation_data)
                category = "SUSPICIOUS"
            elif stats['timeout'] > 0:
                timeout_subdomains.append(reputation_data)
                category = "TIMEOUT"
            elif stats['harmless'] > 0:
                harmless_subdomains.append(reputation_data)
                category = "HARMLESS"
            else:
                undetected_subdomains.append(reputation_data)
                category = "UNDETECTED"
            
            result_line = f"{subdomain_name} - {category} (M:{stats['malicious']}, S:{stats['suspicious']}, U:{stats['undetected']}, H:{stats['harmless']}, T:{stats['timeout']}) - Reputation: {reputation_data['reputation']}"
            results.append(result_line)
            print(f"  → {category}")
        else:
            results.append(f"{subdomain_name} - ERROR: Could not extract data")
            print(f"  → ERROR")
    
    # Generate summary
    summary = [
        f"\nSUBDOMAIN ANALYSIS SUMMARY FOR: {domain}",
        f"Analysis Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Total Subdomains Found: {len(subdomains_list)}",
        "=" * 60,
        f"🔴 MALICIOUS: {len(malicious_subdomains)}",
        f"🟡 SUSPICIOUS: {len(suspicious_subdomains)}",
        f"⚪ UNDETECTED: {len(undetected_subdomains)}",
        f"🟢 HARMLESS: {len(harmless_subdomains)}",
        f"⏱️  TIMEOUT: {len(timeout_subdomains)}",
        "=" * 60,
        ""
    ]
    
    # Add detailed results
    if malicious_subdomains:
        summary.append("🔴 MALICIOUS SUBDOMAINS:")
        for sub in malicious_subdomains:
            summary.append(f"  - {sub['domain']} (Reputation: {sub['reputation']})")
        summary.append("")
    
    if suspicious_subdomains:
        summary.append("🟡 SUSPICIOUS SUBDOMAINS:")
        for sub in suspicious_subdomains:
            summary.append(f"  - {sub['domain']} (Reputation: {sub['reputation']})")
        summary.append("")
    
    if timeout_subdomains:
        summary.append("⏱️  TIMEOUT SUBDOMAINS:")
        for sub in timeout_subdomains:
            summary.append(f"  - {sub['domain']} (Reputation: {sub['reputation']})")
        summary.append("")
    
    if harmless_subdomains:
        summary.append("🟢 HARMLESS SUBDOMAINS:")
        for sub in harmless_subdomains:
            summary.append(f"  - {sub['domain']} (Reputation: {sub['reputation']})")
        summary.append("")
    
    if undetected_subdomains:
        summary.append("⚪ UNDETECTED SUBDOMAINS:")
        for sub in undetected_subdomains:
            summary.append(f"  - {sub['domain']} (Reputation: {sub['reputation']})")
        summary.append("")
    
    summary.extend([
        "-" * 60,
        "DETAILED ANALYSIS:",
        "-" * 60
    ])
    summary.extend(results)
    
    # Save to file
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    output_dir = "output/subdomain-analysis"
    os.makedirs(output_dir, exist_ok=True)
    output_path = os.path.join(output_dir, f"{domain}-subdomains-{timestamp}.txt")
    
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write("\n".join(summary))
    
    # Display results
    print("\n".join(summary))
    print(f"\nResults saved to: {output_path}") 