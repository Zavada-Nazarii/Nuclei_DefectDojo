import os
import subprocess
import requests
import sys
from urllib.parse import urlparse
from datetime import datetime

# Функція для перевірки доступності ресурсу
def check_availability(url):
    try:
        response = requests.get(url, timeout=5)
        return response.status_code == 200
    except requests.exceptions.RequestException:
        return False

# Функція для виклику Nuclei для сканування
def run_nuclei(url, report_path):
    command = ["nuclei", "-u", url, "-t", "cves/", "-json-export", report_path]
    print(f"Running Nuclei command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Nuclei scan failed for {url}. Error: {result.stderr}")
    else:
        print(f"Nuclei scan completed for {url}.")

# Функція для виклику Nuclei через ProxyChains
def run_nuclei_with_proxychains(url, report_path):
    command = ["proxychains", "nuclei", "-u", url, "-t", "cves/", "-json-export", report_path]
    print(f"Running Nuclei with ProxyChains command: {' '.join(command)}")
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"Nuclei scan with ProxyChains failed for {url}. Error: {result.stderr}")
    else:
        print(f"Nuclei scan with ProxyChains completed for {url}.")

# Функція для отримання кореневого домену
def get_cleaned_root_domain(input_string):
    if not input_string:
        return ""
    if not input_string.startswith(('http://', 'https://')):
        temp_url = 'http://' + input_string
    else:
        temp_url = input_string
    parsed_url = urlparse(temp_url)
    domain = parsed_url.netloc
    if not domain:
        domain = input_string.strip()
    domain = domain.replace("www.", "").split(':')[0].strip()
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        if len(domain_parts[-1]) <= 3 and len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']:
            return ".".join(domain_parts[-3:])
        else:
            return ".".join(domain_parts[-2:])
    else:
        return domain

# Функція для отримання повного доменного імені (субдомен.домен)
def get_full_domain_name_from_url(url):
    if not url:
        return ""
    if not url.startswith(('http://', 'https://')):
        temp_url = 'http://' + url
    else:
        temp_url = url
    parsed_url = urlparse(temp_url)
    domain = parsed_url.netloc
    if not domain:
        domain = url.strip()
    domain = domain.replace("www.", "").split(':')[0].strip()
    return domain

# Завантаження Engagement з DefectDojo
def get_existing_engagement(defectdojo_url, api_key, target_root_domain):
    headers = {"Authorization": f"Token {api_key}"}
    response = requests.get(f"{defectdojo_url}/api/v2/engagements/?product=2&limit=1000", headers=headers)
    if response.status_code == 200:
        try:
            engagements = response.json()['results']
            for engagement in engagements:
                if isinstance(engagement, dict):
                    engagement_name = engagement.get("name", "")
                    cleaned_engagement_root_domain = get_cleaned_root_domain(engagement_name)
                    if target_root_domain == cleaned_engagement_root_domain:
                        return engagement['id']
            return None
        except ValueError:
            return None
    else:
        return None

# Створення нового Engagement у DefectDojo
def create_engagement(defectdojo_url, api_key, url_for_name):
    root_domain = get_cleaned_root_domain(url_for_name)
    headers = {"Authorization": f"Token {api_key}"}
    data = {
        "tags": ["NucleiScan"],
        "name": root_domain,
        "description": f"Engagement for {root_domain}.",
        "version": "1.0",
        "first_contacted": datetime.now().strftime("%Y-%m-%d"),
        "target_start": datetime.now().strftime("%Y-%m-%d"),
        "target_end": datetime.now().strftime("%Y-%m-%d"),
        "reason": "Routine scan",
        "status": "Not Started",
        "engagement_type": "Interactive",
        "deduplication_on_engagement": True,
        "product": 2
    }
    response = requests.post(f"{defectdojo_url}/api/v2/engagements/", headers=headers, json=data)
    if response.status_code == 201:
        return response.json()['id']
    else:
        return None

# Завантаження звіту у DefectDojo
def upload_report_to_defectdojo(defectdojo_url, api_key, engagement_id, report_path, original_target_url):
    headers = {"Authorization": f"Token {api_key}"}
    if not os.path.exists(report_path):
        return
    test_title_value = get_full_domain_name_from_url(original_target_url)
    if not test_title_value:
        test_title_value = original_target_url.strip()
    data = {
        'active': 'true',
        'verified': 'true',
        'close_old_findings': 'false',
        'test_title': test_title_value,
        'engagement_name': get_cleaned_root_domain(original_target_url),
        'scan_date': datetime.now().strftime("%Y-%m-%d"),
        'environment': 'Production',
        'service': 'true',
        'tags': 'Nuclei',
        'scan_type': 'Nuclei Scan',
        'engagement': str(engagement_id),
    }
    files = {'file': open(report_path, 'rb')}
    response = requests.post(f"{defectdojo_url}/api/v2/import-scan/", headers=headers, files=files, data=data)
    if response.status_code != 201:
        print(f"Upload failed: {response.status_code} - {response.text}")

# Основна логіка

def main():
    api_key = "your api"
    defectdojo_url = "http://127.0.0.1:8080"
    input_file = "all_sub_sort_uniq.txt"

    if not os.path.exists(input_file):
        print(f"Error: Input file '{input_file}' not found.")
        sys.exit(1)

    with open(input_file, 'r') as file:
        urls = [line.strip() for line in file if line.strip()]

    if not urls:
        print("No valid URLs found in input file. Exiting.")
        sys.exit(0)

    print(f"\n--- Starting Nuclei scans for {len(urls)} URLs ---")

    for url in urls:
        print(f"\n--- Processing URL: {url} for Nuclei scan ---")
        current_url_root_domain = get_cleaned_root_domain(url)
        if not current_url_root_domain:
            print(f"Skipping URL '{url}' due to invalid root domain after parsing.")
            continue

        report_path = f"{current_url_root_domain}_nuclei_report.json"

        if check_availability(url):
            print(f"Ресурс {url} доступний. Виконуємо сканування.")
            run_nuclei(url, report_path)
        else:
            print(f"Ресурс {url} недоступний. Виконуємо сканування через ProxyChains.")
            run_nuclei_with_proxychains(url, report_path)

        if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
            print(f"Звіт не створений або порожній: {report_path}. Пропускаємо завантаження до DefectDojo.")
            continue

        try:
            engagement_id = get_existing_engagement(defectdojo_url, api_key, current_url_root_domain)
            if not engagement_id:
                engagement_id = create_engagement(defectdojo_url, api_key, url)
            if engagement_id:
                upload_report_to_defectdojo(defectdojo_url, api_key, engagement_id, report_path, url)
        except Exception as e:
            print(f"An error occurred during DefectDojo interaction for URL {url}: {e}")
        finally:
            if os.path.exists(report_path):
                try:
                    os.remove(report_path)
                    print(f"Removed temporary report file: {report_path}")
                except OSError as e:
                    print(f"Error removing file {report_path}: {e}")

if __name__ == "__main__":
    main()

