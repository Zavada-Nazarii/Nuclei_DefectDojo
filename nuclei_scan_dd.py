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
    """
    Витягує кореневий домен з URL або доменного імені.
    Приклади:
    - 'http://sub.example.com' -> 'example.com'
    - 'www.example.co.uk' -> 'example.co.uk'
    - 'example.com' -> 'example.com'
    """
    if not input_string:
        return ""

    # Додаємо http:// для коректного парсингу urlparse, якщо протокол відсутній
    if not input_string.startswith(('http://', 'https://')):
        temp_url = 'http://' + input_string
    else:
        temp_url = input_string

    parsed_url = urlparse(temp_url)
    domain = parsed_url.netloc # Це буде 'sub.example.com' або 'example.com:8080'

    if not domain:
        # Якщо urlparse не зміг витягти netloc (наприклад, для 'example.com' без 'http://'),
        # спробуємо використати сам input_string як домен.
        domain = input_string.strip()

    # Видаляємо www. та порти
    domain = domain.replace("www.", "").split(':')[0].strip()

    if not domain:
        return ""

    # Логіка для виділення кореневого домену (без Public Suffix List)
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        # Проста евристика для 2-рівневих TLD (наприклад, .co.uk)
        # Ця евристика не є надійною для всіх можливих Public Suffixes
        if len(domain_parts[-1]) <= 3 and len(domain_parts) >= 3 and domain_parts[-2] in ['co', 'com', 'org', 'net', 'gov', 'edu']: # Додаємо часті Public Suffixes
            return ".".join(domain_parts[-3:]) # Наприклад, "example.co.uk"
        else:
            return ".".join(domain_parts[-2:]) # Наприклад, "example.com"
    else:
        return domain # Якщо домен занадто короткий, повертаємо як є

# Функція для отримання повного доменного імені (субдомен.домен)
def get_full_domain_name_from_url(url):
    """
    Витягує повне доменне ім'я з URL (включаючи субдомени, але без протоколу, www та порту).
    Приклади:
    - 'http://www.email2.example.com/path' -> 'email2.example.com'
    - 'https://example.com:8443' -> 'example.com'
    """
    if not url:
        return ""

    if not url.startswith(('http://', 'https://')):
        temp_url = 'http://' + url
    else:
        temp_url = url

    parsed_url = urlparse(temp_url)
    domain = parsed_url.netloc

    if not domain:
        # Якщо urlparse не зміг витягти netloc (наприклад, для 'email2.example.com' без протоколу)
        domain = url.strip()

    domain = domain.replace("www.", "").split(':')[0].strip()
    return domain

# Функція: Запуск Subfinder
def run_subfinder(target_domain, use_proxychains=False):
    print(f"\n[Subfinder] Running Subfinder for: {target_domain}")
    command = ["subfinder", "-d", target_domain, "-silent"]
    if use_proxychains:
        command.insert(0, "proxychains")

    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True, encoding='utf-8', errors='ignore')
        subdomains = result.stdout.strip().split('\n')
        subdomains = [s.strip() for s in subdomains if s.strip()]
        print(f"[Subfinder] Found {len(subdomains)} subdomains for {target_domain}.")
        return subdomains
    except subprocess.CalledProcessError as e:
        print(f"[Subfinder] Error running Subfinder for {target_domain}: {e.stderr}")
        return []
    except FileNotFoundError:
        print("[Subfinder] Error: Subfinder not found. Please ensure it's installed and in your PATH.")
        return []

# Функція для пошуку engagement за головним доменом
def get_existing_engagement(defectdojo_url, api_key, target_root_domain):
    headers = {"Authorization": f"Token {api_key}"}
    response = requests.get(f"{defectdojo_url}/api/v2/engagements/?product=2&limit=1000", headers=headers)

    if response.status_code == 200:
        try:
            engagements = response.json()['results']
            print(f"[DefectDojo] Found {len(engagements)} engagements in DefectDojo for product 2.")

            for engagement in engagements:
                if isinstance(engagement, dict):
                    engagement_name = engagement.get("name", "")
                    cleaned_engagement_root_domain = get_cleaned_root_domain(engagement_name)

                    print(f"[DefectDojo] Checking existing engagement '{engagement_name}' (root domain: '{cleaned_engagement_root_domain}') against target root domain '{target_root_domain}'")

                    if target_root_domain == cleaned_engagement_root_domain:
                        print(f"[DefectDojo] Found matching engagement for root domain: {target_root_domain} with ID: {engagement['id']}")
                        return engagement['id']
            print(f"[DefectDojo] No existing engagement found with exact root domain match for: {target_root_domain}")
            return None
        except ValueError:
            print(f"[DefectDojo] Error parsing response as JSON: {response.text}")
            return None
    else:
        print(f"[DefectDojo] Failed to retrieve engagements for product 2: {response.status_code} - {response.text}")
        return None

# Функція для створення engagement у DefectDojo
def create_engagement(defectdojo_url, api_key, url_for_name):
    root_domain = get_cleaned_root_domain(url_for_name)
    if not root_domain:
        raise Exception(f"Cannot create engagement. Root domain is empty for URL: {url_for_name}")

    headers = {"Authorization": f"Token {api_key}"}
    print(f"[DefectDojo] Creating new engagement for root domain: {root_domain}")

    data = {
        "tags": ["NucleiScan"],
        "name": root_domain,
        "description": f"Engagement for {root_domain} to perform Nuclei vulnerability scan.",
        "version": "1.0",
        "first_contacted": datetime.now().strftime("%Y-%m-%d"),
        "target_start": datetime.now().strftime("%Y-%m-%d"),
        "target_end": datetime.now().strftime("%Y-%m-%d"),
        "reason": "Routine security scan",
        "tracker": "",
        "test_strategy": "",
        "threat_model": True,
        "api_test": True,
        "pen_test": True,
        "check_list": True,
        "status": "Not Started",
        "engagement_type": "Interactive",
        "build_id": "",
        "commit_hash": "",
        "branch_tag": "",
        "source_code_management_uri": "",
        "deduplication_on_engagement": True,
        "lead": None,
        "requester": None,
        "preset": None,
        "report_type": None,
        "product": 2,
        "build_server": None,
        "source_code_management_server": None,
        "orchestration_engine": None
    }

    response = requests.post(f"{defectdojo_url}/api/v2/engagements/", headers=headers, json=data)
    if response.status_code == 201:
        engagement_data = response.json()
        print(f"[DefectDojo] Engagement created successfully with ID: {engagement_data['id']}")
        return engagement_data['id']
    else:
        raise Exception(f"[DefectDojo] Failed to create Engagement for {root_domain}: {response.status_code} - {response.text}")

# Функція для завантаження звіту в DefectDojo
def upload_report_to_defectdojo(defectdojo_url, api_key, engagement_id, report_path, original_target_url):
    headers = {"Authorization": f"Token {api_key}"}

    if not os.path.exists(report_path):
        raise Exception(f"Звіт {report_path} не знайдений.")

    test_title_value = get_full_domain_name_from_url(original_target_url)

    if not test_title_value:
        test_title_value = original_target_url.strip()
        print(f"Warning: Could not parse subdomain.domain for {original_target_url}. Using full URL for Test Title.")

    print(f"Uploading report for engagement ID: {engagement_id} with Test Title: {test_title_value}")

    data = {
        'product_type_name': 'Research and Development',
        'active': 'true',
        'verified': 'true',
        'close_old_findings': 'false',
        'test_title': test_title_value,
        'engagement_name': get_cleaned_root_domain(original_target_url),
        'build_id': '',
        'push_to_jira': 'false',
        'minimum_severity': 'Info',
        'scan_date': datetime.now().strftime("%Y-%m-%d"),
        'environment': 'Production',
        'service': 'true',
        'commit_hash': '',
        'group_by': '',
        'version': '',
        'tags': 'Nuclei',
        'api_scan_configuration': '',
        'product_name': 'Nuclei',
        'auto_create_context': '',
        'lead': '',
        'scan_type': 'Nuclei Scan',
        'branch_tag': '',
        'engagement': str(engagement_id),
    }

    files = {'file': open(report_path, 'rb')}

    response = requests.post(f"{defectdojo_url}/api/v2/import-scan/", headers=headers, files=files, data=data)
    if response.status_code == 201:
        print(f"Звіт для engagement {engagement_id} успішно завантажено.")
    else:
        print(f"Помилка при завантаженні звіту для engagement {engagement_id}: {response.status_code} - {response.text}")
        print(f"Response content: {response.text}")

# Основна логіка
def main():
    api_key = "api_key"
    defectdojo_url = "http://127.0.0.1:8080"
    input_file = "urls.txt"

    args = sys.argv[1:]
    
    use_proxychains_for_subfinder = '--subfinder-proxychains' in args
    if use_proxychains_for_subfinder:
        args.remove('--subfinder-proxychains')

    all_targets_for_nuclei = set() # Використовуємо set для унікальних цілей

    initial_inputs = []
    if args:
        initial_inputs = args
    else:
        if not os.path.exists(input_file):
            print(f"Error: Input file '{input_file}' not found.")
            sys.exit(1)
        with open(input_file, 'r') as file:
            initial_inputs = [line.strip() for line in file if line.strip()]

    if not initial_inputs:
        print("No URLs or root domains provided for scanning. Exiting.")
        sys.exit(0)

    # Етап 1: Збір усіх цілей для Nuclei, включно із запуском Subfinder
    for item in initial_inputs:
        item = item.strip()
        if not item:
            continue

        # Спроба отримати кореневий домен з поточного елемента
        current_root_domain = get_cleaned_root_domain(item)
        
        # Перевірка, чи це кореневий домен для Subfinder
        # Це вважається кореневим доменом, якщо:
        # 1. Він не містить протоколу (http/https).
        # 2. Він не містить шляху (/).
        # 3. Його кореневий домен збігається з самим елементом (тобто це вже "example.com", а не "sub.example.com").
        is_potential_root_for_subfinder = (
            not item.startswith(('http://', 'https://')) and
            '/' not in item and
            current_root_domain == item
        )

        if is_potential_root_for_subfinder:
            print(f"\n[Main] Processing input '{item}' as a root domain for Subfinder.")
            found_subdomains = run_subfinder(item, use_proxychains_for_subfinder)
            
            # Додаємо знайдені субдомени та сам кореневий домен як http та https URL
            for s in found_subdomains:
                all_targets_for_nuclei.add(f"http://{s}")
                all_targets_for_nuclei.add(f"https://{s}")
            
            all_targets_for_nuclei.add(f"http://{current_root_domain}")
            all_targets_for_nuclei.add(f"https://{current_root_domain}")
            
        else:
            # Це вже повний URL або субдомен, додаємо його без змін для Nuclei
            print(f"[Main] Adding '{item}' directly for Nuclei scan.")
            # Переконаємось, що URL має протокол для check_availability та Nuclei
            if not item.startswith(('http://', 'https://')):
                all_targets_for_nuclei.add(f"http://{item}") # За замовчуванням HTTP
                all_targets_for_nuclei.add(f"https://{item}") # Також HTTPS
            else:
                all_targets_for_nuclei.add(item)


    if not all_targets_for_nuclei:
        print("No valid targets collected for Nuclei scan. Exiting.")
        sys.exit(0)

    urls_for_nuclei_scan = sorted(list(all_targets_for_nuclei))

    # Етап 2: Запуск Nuclei для всіх зібраних цілей
    print(f"\n--- Starting Nuclei scans for {len(urls_for_nuclei_scan)} unique URLs ---")

    for url in urls_for_nuclei_scan:
        print(f"\n--- Processing URL: {url} for Nuclei scan ---")
        current_url_root_domain = get_cleaned_root_domain(url)
        if not current_url_root_domain:
            print(f"Skipping URL '{url}' due to invalid root domain after parsing.")
            continue

        report_path = f"{current_url_root_domain}_nuclei_report.json"

        # Виконання сканування Nuclei
        if check_availability(url):
            print(f"Ресурс {url} доступний. Виконуємо сканування.")
            run_nuclei(url, report_path)
        else:
            print(f"Ресурс {url} недоступний. Виконуємо сканування через ProxyChains.")
            run_nuclei_with_proxychains(url, report_path)

        # Перевірка наявності звіту
        if not os.path.exists(report_path) or os.path.getsize(report_path) == 0:
            print(f"Звіт не створений або порожній: {report_path}. Пропускаємо завантаження до DefectDojo.")
            continue

        try:
            engagement_id = get_existing_engagement(defectdojo_url, api_key, current_url_root_domain)

            if engagement_id:
                print(f"Using existing engagement with ID: {engagement_id} for root domain: {current_url_root_domain}")
            else:
                engagement_id = create_engagement(defectdojo_url, api_key, url)

            if engagement_id:
                upload_report_to_defectdojo(defectdojo_url, api_key, engagement_id, report_path, url)
            else:
                print(f"Could not determine engagement ID for {url}. Skipping report upload.")

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

