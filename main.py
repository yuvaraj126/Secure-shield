import logging
import re
import socket
import ssl
from datetime import datetime
import nmap

import dns.resolver
import requests
import tldextract
import whois
from bs4 import BeautifulSoup
from flask import Flask, jsonify, render_template_string, request

app = Flask(__name__)

# Your VirusTotal API key
VIRUSTOTAL_API_KEY = '9b60748bbd51bb738e224856477add6c256944bd9bca04165774747fb0a4d01d'

# List of suspicious substrings commonly found in phishing URLs
SUSPICIOUS_SUBSTRINGS = [
    'login', 'update', 'verify', 'account', 'security', 'bank', 'signin',
    'suspend'
]


def is_suspicious_length(url):
    return len(url) > 100


def contains_suspicious_substrings(url):
    return any(substring in url.lower() for substring in SUSPICIOUS_SUBSTRINGS)


def is_ip_address(url):
    ip_pattern = re.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
    return bool(ip_pattern.search(url))


def is_misleading_domain(url):
    domain = tldextract.extract(url).domain
    return len(domain) < 2 or re.search(r'[^\w\.-]', domain)


def check_url_virustotal(url):
    try:
        encoded_url = requests.utils.quote(url)
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/urls/{encoded_url}',
            headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result['data']['attributes']['last_analysis_stats'][
                    'malicious'] > 0:
                return "Suspicious: Detected by VirusTotal."
        return None
    except Exception as e:
        logging.error(f"VirusTotal API error: {str(e)}")
        return "VirusTotal analysis failed."


def lookup_ip(ip):
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/ip_addresses/{ip}',
            headers=headers)
        if response.status_code == 200:
            result = response.json()
            data = result.get('data', {})
            attributes = data.get('attributes', {})
            return {
                'ip': ip,
                'country': attributes.get('country', 'Unknown'),
                'as_name': attributes.get('as_owner', 'Unknown'),
                'last_analysis_stats': attributes.get('last_analysis_stats',
                                                      {})
            }
        return None
    except Exception as e:
        logging.error(f"IP lookup error: {str(e)}")
        return None


def get_ssl_certificate_info(url):
    try:
        # Ensure URL starts with http:// or https://
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        # Extract hostname from the URL
        extracted = tldextract.extract(url)
        hostname = extracted.domain
        if not hostname:
            return {'error': 'Unable to extract hostname from URL'}

        # Append the top-level domain to the hostname
        full_hostname = f"{hostname}.{extracted.suffix}"

        # Create SSL context and connect to the server
        context = ssl.create_default_context()
        with socket.create_connection((full_hostname, 443)) as sock:
            with context.wrap_socket(sock,
                                     server_hostname=full_hostname) as ssock:
                cert = ssock.getpeercert()

        # Extract certificate details
        issuer = dict(x[0] for x in cert['issuer'])
        issued_by = issuer.get('organizationName', 'Unknown')
        subject = dict(x[0] for x in cert['subject'])
        issued_to = subject.get('commonName', 'Unknown')

        valid_from = cert['notBefore']
        valid_until = cert['notAfter']

        # Check types and format dates
        if isinstance(valid_from, datetime):
            valid_from = valid_from.strftime('%Y-%m-%d %H:%M:%S')
        if isinstance(valid_until, datetime):
            valid_until = valid_until.strftime('%Y-%m-%d %H:%M:%S')

        return {
            'issued_to': issued_to,
            'issued_by': issued_by,
            'valid_from': valid_from,
            'valid_until': valid_until
        }
    except ssl.SSLError as e:
        logging.error(f"SSL connection error: {str(e)}")
        return {'error': f'SSL connection error: {str(e)}'}
    except socket.gaierror as e:
        logging.error(f"Hostname resolution error: {str(e)}")
        return {'error': f'Hostname resolution error: {str(e)}'}
    except Exception as e:
        logging.error(f"SSL certificate info error: {str(e)}")
        return {
            'error': f'Error retrieving SSL certificate information: {str(e)}'
        }


def get_domain_age(url):
    domain = tldextract.extract(url).registered_domain
    try:
        whois_info = whois.whois(domain)
        creation_date = whois_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        return (datetime.now() - creation_date).days
    except Exception as e:
        logging.error(f"Domain age error: {str(e)}")
        return str(e)


def check_redirects(url):
    try:
        response = requests.get(url, allow_redirects=True, timeout=5)
        final_url = response.url
        if final_url != url:
            return f"Redirects to {final_url}"
        return "No redirects detected."
    except requests.RequestException as e:
        logging.error(f"Redirect check error: {str(e)}")
        return f"Error checking redirects: {str(e)}"


def check_domain_reputation(url):
    domain = tldextract.extract(url).registered_domain
    try:
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        response = requests.get(
            f'https://www.virustotal.com/api/v3/domains/{domain}',
            headers=headers)
        if response.status_code == 200:
            result = response.json()
            if result['data']['attributes']['last_analysis_stats'][
                    'malicious'] > 0:
                return "Domain reputation: Poor - Detected as malicious."
            else:
                return "Domain reputation: Good."
        return "Domain reputation check failed."
    except Exception as e:
        logging.error(f"Domain reputation error: {str(e)}")
        return "Domain reputation check failed."


# Configure logging
logging.basicConfig(level=logging.INFO,
                    format='%(asctime)s %(levelname)s %(message)s')


@app.errorhandler(Exception)
def handle_exception(e):
    logging.error(f"Error: {str(e)}")
    return jsonify({'error': 'An unexpected error occurred.'}), 500


@app.route('/')
def home():
    return render_template_string(index_html)


@app.route('/check', methods=['POST'])
def check():
    url = request.form['url']
    logging.info(f"Checking URL: {url}")

    result = {
        'heuristic': None,
        'virustotal': None,
        'ssl': None,
        'domain_age': None,
        'redirects': None,
        'domain_reputation': None
    }

    try:
        if is_ip_address(url):
            ip_info = lookup_ip(url)
            if ip_info:
                result[
                    'heuristic'] = f"IP Address: {ip_info['ip']}, Country: {ip_info['country']}, AS Name: {ip_info['as_name']}"
                result['virustotal'] = ip_info
            else:
                result[
                    'heuristic'] = "IP lookup failed or IP address not found."
                result[
                    'virustotal'] = "VirusTotal analysis indicates no immediate threat."
        else:
            if is_suspicious_length(url):
                result['heuristic'] = "Suspicious: URL length is too long."
            elif contains_suspicious_substrings(url):
                result[
                    'heuristic'] = "Suspicious: URL contains common phishing keywords."
            elif is_misleading_domain(url):
                result[
                    'heuristic'] = "Suspicious: Domain seems misleading or has unusual characters."
            else:
                result['heuristic'] = "URL seems safe."

            virustotal_result = check_url_virustotal(url)
            if virustotal_result:
                result['virustotal'] = virustotal_result
            else:
                result[
                    'virustotal'] = "VirusTotal analysis indicates no immediate threat."

            ssl_cert_info = get_ssl_certificate_info(url)
            result['ssl'] = ssl_cert_info

            domain_age = get_domain_age(url)
            result['domain_age'] = domain_age if isinstance(
                domain_age, int) else "Unable to determine domain age."

            redirect_check = check_redirects(url)
            result['redirects'] = redirect_check

            domain_reputation = check_domain_reputation(url)
            result['domain_reputation'] = domain_reputation
    except Exception as e:
        logging.error(f"Error processing URL '{url}': {str(e)}")
        result[
            'error'] = 'An unexpected error occurred while processing the URL.'

    return jsonify(result)


@app.route('/analyze', methods=['POST'])
def analyze():
    url = request.form.get('url')
    logging.info(f"Analyzing website: {url}")
    result = None

    # Validate and normalize URL
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'http://' + url
    try:
        domain = url.split('/')[2]
    except IndexError:
        return jsonify({'error': 'Invalid URL format'})

    # Initialize results
    title = num_links = num_images = meta_description = meta_keywords = content_length = server = num_js_files = num_css_files = ip_address = dns_provider = whois_info = 'Error'

    # Analyze website
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.content, 'html.parser')

        title = soup.title.string if soup.title else 'No title'
        num_links = len(soup.find_all('a'))
        num_images = len(soup.find_all('img'))
        content_length = len(response.content)

        meta_description = soup.find('meta', attrs={'name': 'description'})
        meta_keywords = soup.find('meta', attrs={'name': 'keywords'})

        meta_description = meta_description[
            'content'] if meta_description else 'No meta description'
        meta_keywords = meta_keywords[
            'content'] if meta_keywords else 'No meta keywords'

        server = response.headers.get('Server', 'Unknown')

        # Count JavaScript and CSS files
        num_js_files = len(soup.find_all('script', src=True))
        num_css_files = len(soup.find_all('link', rel='stylesheet'))

        # Get IP address
        ip_address = socket.gethostbyname(domain)

        # DNS provider (for demonstration, here it’s set to a placeholder)
        dns_provider = 'Placeholder DNS provider'

        # WHOIS info
        whois_info = whois.whois(domain)

        result = {
            'title': title,
            'num_links': num_links,
            'num_images': num_images,
            'meta_description': meta_description,
            'meta_keywords': meta_keywords,
            'content_length': content_length,
            'server': server,
            'num_js_files': num_js_files,
            'num_css_files': num_css_files,
            'ip_address': ip_address,
            'dns_provider': dns_provider,
            'whois_info': whois_info
        }
    except Exception as e:
        logging.error(f"Error analyzing website '{url}': {str(e)}")
        result = {
            'error': 'An unexpected error occurred during website analysis.'
        }

    return jsonify(result)


@app.route('/scan', methods=['POST'])
def scan_ports():
    url = request.form['url']
    logging.info(f"Scanning ports for URL: {url}")

    # Extract domain from URL
    domain = tldextract.extract(url).registered_domain
    logging.info(f"Extracted domain: {domain}")

    # Define the ports to scan (example: 1-1024)
    ports_to_scan = '1-1024'

    scanner = nmap.PortScanner()
    try:
        # Perform the port scan
        scan_result = scanner.scan(hosts=domain,
                                   arguments=f'-p {ports_to_scan}')
        return jsonify(scan_result)
    except Exception as e:
        logging.error(f"Port scanning error: {str(e)}")
        return jsonify({'error': f'Port scanning failed: {str(e)}'})


# Example HTML template
index_html = """
<!DOCTYPE html>
<html>
<head>
    <title>URL Analysis Tool</title>
    <style>
        body {
            height: 100%;
            background: #000;
            color: #0f0;
            margin: 0;
            overflow: hidden; /* Hide scrollbars */
        }

        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            text-align: center;
            position: relative;
            overflow: auto; /* Allow scrolling within the container */
            height: calc(100vh - 40px);
            scrollbar-width: none; /* Hide scrollbar in Firefox */
        }

        /* For WebKit browsers like Chrome and Safari */
        .container::-webkit-scrollbar {
            display: none;
        }

        h1 {
            color: #0f0;
            text-shadow: 0 0 10px #0f0;
            animation: titleAnimation 2s infinite;
        }

        @keyframes titleAnimation {
            0% { transform: translateY(0); }
            50% { transform: translateY(-10px); }
            100% { transform: translateY(0); }
        }

        .developer {
            margin-top: 10px;
            color: #f00;
            font-size: 1.2em;
            text-shadow: 0 0 5px #f00;
            animation: developerAnimation 3s infinite;
        }

        @keyframes developerAnimation {
            0% { opacity: 0; }
            50% { opacity: 1; }
            100% { opacity: 0; }
        }

        input[type="text"] {
            width: 100%;
            padding: 10px;
            margin-bottom: 10px;
            border: 1px solid #0f0;
            background: #000;
            color: #0f0;
            border-radius: 5px;
            box-shadow: 0 0 10px #0f0;
        }

        button {
            padding: 15px;
            background-color: #0f0;
            color: #000;
            border: 1px solid #0f0;
            cursor: pointer;
            border-radius: 5px;
            margin: 5px;
            box-shadow: 0 0 10px #0f0;
            transition: background-color 0.3s, transform 0.3s;
            font-size: 1em;
        }

        button:hover {
            background-color: #0c0;
            transform: scale(1.05);
        }

        button:active {
            transform: scale(0.95);
        }

        .result {
            margin-top: 20px;
            padding: 10px;
            border: 1px solid #0f0;
            border-radius: 5px;
            background: #111;
        }

        #loading {
            display: none;
            text-align: center;
            margin-top: 20px;
        }

        .spinner {
            border: 4px solid #0f0;
            border-radius: 50%;
            border-top: 4px solid #000;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto;
        }

        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }

        pre {
            white-space: pre-wrap;
            word-wrap: break-word;
            color: #0f0;
            background: #000;
            padding: 10px;
            border: 1px solid #0f0;
            border-radius: 5px;
        }

    </style>
</head>
<body>
    <div class="container">
        <h1>URL Analysis Tool</h1>
        <div class="developer">Developed by [TEAM ERROR]</div>
        <form id="analyzeForm">
            <input type="text" id="urlInput" placeholder="Enter URL here" required />
            <button type="submit">Analyze</button>
        </form>
        <form id="scanForm">
            <button type="button" id="scanButton">Scan Ports</button>
            <button type="button" id="checkButton">Security Checker</button>
        </form>
        <div id="loading">
            <div class="spinner"></div>
            <p>Checking... Please wait.</p>
        </div>
        <div id="results" class="result" style="display: none;"></div>
        <div id="scanResults" class="result" style="display: none;"></div>
        <div id="checkResults" class="result" style="display: none;"></div>
    </div>

    <script>
        document.getElementById('analyzeForm').addEventListener('submit', async function (e) {
            e.preventDefault();
            const url = document.getElementById('urlInput').value;

            // Show loading message
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.getElementById('scanResults').style.display = 'none';
            document.getElementById('checkResults').style.display = 'none';

            try {
                const response = await fetch('/analyze', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({ url: url })
                });

                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }

                const data = await response.json();

                let resultsHtml = '<h2>URL Analysis Results</h2>';
                resultsHtml += '<p><strong>Title:</strong> ' + (data.title || 'No title') + '</p>';
                resultsHtml += '<p><strong>Number of Links:</strong> ' + (data.num_links || '0') + '</p>';
                resultsHtml += '<p><strong>Number of Images:</strong> ' + (data.num_images || '0') + '</p>';
                resultsHtml += '<p><strong>Meta Description:</strong> ' + (data.meta_description || 'No meta description') + '</p>';
                resultsHtml += '<p><strong>Meta Keywords:</strong> ' + (data.meta_keywords || 'No meta keywords') + '</p>';
                resultsHtml += '<p><strong>Content Length:</strong> ' + (data.content_length || '0') + '</p>';
                resultsHtml += '<p><strong>Server:</strong> ' + (data.server || 'Unknown') + '</p>';
                resultsHtml += '<p><strong>Number of JS Files:</strong> ' + (data.num_js_files || '0') + '</p>';
                resultsHtml += '<p><strong>Number of CSS Files:</strong> ' + (data.num_css_files || '0') + '</p>';
                resultsHtml += '<p><strong>IP Address:</strong> ' + (data.ip_address || 'N/A') + '</p>';
                resultsHtml += '<p><strong>DNS Provider:</strong> ' + (data.dns_provider || 'Placeholder DNS provider') + '</p>';
                resultsHtml += '<p><strong>WHOIS Info:</strong> ' + (data.whois_info || 'N/A') + '</p>';

                document.getElementById('results').innerHTML = resultsHtml;
                document.getElementById('results').style.display = 'block';

            } catch (error) {
                console.error('Error:', error);
                document.getElementById('results').innerHTML = '<p>An unexpected error occurred: ' + error.message + '</p>';
                document.getElementById('results').style.display = 'block';
            } finally {
                // Hide loading message
                document.getElementById('loading').style.display = 'none';
            }
        });

        document.getElementById('scanButton').addEventListener('click', async function () {
            const url = document.getElementById('urlInput').value;

            // Show loading message
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.getElementById('scanResults').style.display = 'none';
            document.getElementById('checkResults').style.display = 'none';

            try {
                const response = await fetch('/scan', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({ url: url })
                });

                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }

                const data = await response.json();

                let scanResultsHtml = '<h2>Port Scan Results</h2>';

                if (data.error) {
                    scanResultsHtml += '<p>' + data.error + '</p>';
                } else {
                    scanResultsHtml += '<h3>Scan Summary</h3>';
                    scanResultsHtml += '<p><strong>Host:</strong> ' + (data.scan ? Object.keys(data.scan)[0] : 'N/A') + '</p>';
                    scanResultsHtml += '<p><strong>Open Ports:</strong></p>';
                    scanResultsHtml += '<ul>';
                    if (data.scan && data.scan[Object.keys(data.scan)[0]].tcp) {
                        for (const [port, info] of Object.entries(data.scan[Object.keys(data.scan)[0]].tcp)) {
                            scanResultsHtml += '<li>Port ' + port + ' (' + info.name + '): ' + info.state + '</li>';
                        }
                    } else {
                        scanResultsHtml += '<li>No open ports found.</li>';
                    }
                    scanResultsHtml += '</ul>';
                }

                document.getElementById('scanResults').innerHTML = scanResultsHtml;
                document.getElementById('scanResults').style.display = 'block';

            } catch (error) {
                console.error('Error:', error);
                document.getElementById('scanResults').innerHTML = '<p>An unexpected error occurred during scanning: ' + error.message + '</p>';
                document.getElementById('scanResults').style.display = 'block';
            } finally {
                // Hide loading message
                document.getElementById('loading').style.display = 'none';
            }
        });

        document.getElementById('checkButton').addEventListener('click', async function () {
            const url = document.getElementById('urlInput').value;

            // Show loading message
            document.getElementById('loading').style.display = 'block';
            document.getElementById('results').style.display = 'none';
            document.getElementById('scanResults').style.display = 'none';
            document.getElementById('checkResults').style.display = 'none';

            try {
                const response = await fetch('/check', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
                    body: new URLSearchParams({ url: url })
                });

                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }

                const data = await response.json();

                let checkResultsHtml = '<h2>Security Checker Results</h2>';

                checkResultsHtml += '<p><strong>Heuristic Analysis:</strong> ' + (data.heuristic || 'Not Available') + '</p>';
                checkResultsHtml += '<p><strong>VirusTotal Analysis:</strong> ' + (data.virustotal || 'Not Available') + '</p>';
                checkResultsHtml += '<p><strong>Domain Age:</strong> ' + (data.domain_age || 'Not Available') + '</p>';
                checkResultsHtml += '<p><strong>Redirects:</strong> ' + (data.redirects || 'Not Available') + '</p>';
                checkResultsHtml += '<p><strong>Domain Reputation:</strong> ' + (data.domain_reputation || 'Not Available') + '</p>';

                document.getElementById('checkResults').innerHTML = checkResultsHtml;
                document.getElementById('checkResults').style.display = 'block';

            } catch (error) {
                console.error('Error:', error);
                document.getElementById('checkResults').innerHTML = '<p>An unexpected error occurred during security checking: ' + error.message + '</p>';
                document.getElementById('checkResults').style.display = 'block';
            } finally {
                // Hide loading message
                document.getElementById('loading').style.display = 'none';
            }
        });

        // Smooth scrolling functionality
        function scrollToTop() {
            window.scrollTo({ top: 0, behavior: 'smooth' });
        }

        function scrollToBottom() {
            window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' });
        }

        // Optional: Add buttons for scrolling if needed
        // document.body.insertAdjacentHTML('beforeend', '<button onclick="scrollToTop()" style="position: fixed; bottom: 60px; right: 20px;">Scroll to Top</button>');
        // document.body.insertAdjacentHTML('beforeend', '<button onclick="scrollToBottom()" style="position: fixed; bottom: 10px; right: 20px;">Scroll to Bottom</button>');
    </script>
</body>
</html>


"""

if __name__ == '__main__':
    app.run(debug=True)
