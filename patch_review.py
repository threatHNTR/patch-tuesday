import argparse
import requests
import re
from colorama import Fore, Style, init

# Initialize colorama
init()

# Constants
BASE_URL = 'https://api.msrc.microsoft.com/cvrf/v2.0/'
HEADERS = {'Accept': 'application/json'}
VULN_TYPES = [
    'Elevation of Privilege',
    'Security Feature Bypass',
    'Remote Code Execution',
    'Information Disclosure',
    'Denial of Service',
    'Spoofing',
    'Edge - Chromium'
]


def fetch_security_release(date_str):
    """Fetch the security release data for the given date."""
    try:
        response = requests.get(f'{BASE_URL}cvrf/{date_str}', headers=HEADERS)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"{Fore.RED}[!] Error fetching data: {e}{Style.RESET_ALL}")
        exit(1)


def count_type(search_type, all_vulns):
    """Count vulnerabilities of a specific type."""
    return sum(
        1 for vuln in all_vulns for threat in vuln['Threats']
        if threat['Type'] == 0 and (
                (search_type == "Edge - Chromium" and threat['ProductID'][0] == '11655') or
                (threat['Description'].get('Value') == search_type and threat['ProductID'][0] != '11655')
        )
    )


def count_exploited(all_vulns):
    """Count exploited vulnerabilities."""
    counter, cves = 0, []
    for vuln in all_vulns:
        # Initialize CVSS score to 0.0 by default
        cvss_score = 0.0

        # Check if 'CVSSScoreSets' exists and is non-empty
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if cvss_sets:
            cvss_score = cvss_sets[0].get('BaseScore', 0.0)

        for threat in vuln['Threats']:
            if threat['Type'] == 1 and 'Exploited:Yes' in threat['Description']['Value']:
                counter += 1
                cves.append(f'{vuln["CVE"]} - {cvss_score} - {vuln["Title"]["Value"]}')
                break
    return {'counter': counter, 'cves': cves}


def exploitation_likely(all_vulns):
    """Count vulnerabilities more likely to be exploited."""
    counter, cves = 0, []
    for vuln in all_vulns:
        for threat in vuln['Threats']:
            if threat['Type'] == 1 and 'Exploitation More Likely'.lower() in threat['Description']['Value'].lower():
                counter += 1
                cves.append(f'{vuln["CVE"]} -- {vuln["Title"]["Value"]}')
                break
    return {'counter': counter, 'cves': cves}


def check_date_format(date_string):
    """Check if the date string is in the format yyyy-mmm."""
    return bool(re.match(r'\d{4}-(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)', date_string, re.IGNORECASE))


def print_header(title):
    """Print the report header."""
    print(f"{Fore.GREEN}[+] Microsoft Patch Tuesday Stats{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] https://github.com/Immersive-Labs-Sec/msrc-api{Style.RESET_ALL}")
    print(f"{Fore.GREEN}[+] {title}{Style.RESET_ALL}")


def print_vulnerability_summary(vuln_type, count):
    """Print the summary of vulnerabilities by type."""
    print(f'  {Fore.LIGHTBLUE_EX}[-] {count} {vuln_type} Vulnerabilities{Style.RESET_ALL}')


def main(security_update):
    """Main function to orchestrate the vulnerability report."""
    if not check_date_format(security_update):
        print(f"{Fore.RED}[!] Invalid date format. Please use 'yyyy-mmm'{Style.RESET_ALL}")
        exit(1)

    release_json = fetch_security_release(security_update)
    title = release_json.get('DocumentTitle', {}).get('Value', 'Release not found')
    all_vulns = release_json.get('Vulnerability', [])

    print_header(title)
    print(f'{Fore.BLUE}[+] Found a total of {len(all_vulns)} vulnerabilities{Style.RESET_ALL}')

    for vuln_type in VULN_TYPES:
        count = count_type(vuln_type, all_vulns)
        print_vulnerability_summary(vuln_type, count)

    exploited = count_exploited(all_vulns)
    print(f'{Fore.RED}[+] Found {exploited["counter"]} exploited in the wild{Style.RESET_ALL}')
    for cve in exploited['cves']:
        print(f'  {Fore.LIGHTRED_EX}[-] {cve}{Style.RESET_ALL}')

    print(f'{Fore.CYAN}[+] Highest Rated Vulnerabilities{Style.RESET_ALL}')
    for vuln in all_vulns:
        cvss_sets = vuln.get('CVSSScoreSets', [])
        if cvss_sets:  # Check if the list is non-empty
            cvss_score = cvss_sets[0].get('BaseScore', 0)
        else:
            cvss_score = 0  # Default value if CVSSScoreSets is empty or missing

        title = vuln.get('Title', {}).get('Value', 'Title not found')
        cve_id = vuln.get('CVE', 'CVE not found')
        if cvss_score >= 8.0:
            print(f'  {Fore.LIGHTCYAN_EX}[-] {cve_id} - {cvss_score} - {title}{Style.RESET_ALL}')

    exploitation = exploitation_likely(all_vulns)
    print(
        f'{Fore.RED}[+] Found {exploitation["counter"]} vulnerabilities more likely to be exploited{Style.RESET_ALL}')
    for cve in exploitation['cves']:
        print(f'  {Fore.LIGHTRED_EX}[-] {cve} - https://www.cve.org/CVERecord?id={cve.split()[0]}{Style.RESET_ALL}')


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Read vulnerability stats for a Patch Tuesday release.')
    parser.add_argument('security_update', help="Date string for the report query in format YYYY-mmm")
    args = parser.parse_args()

    main(args.security_update)
