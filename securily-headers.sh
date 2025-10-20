#!/usr/bin/env python3
import time
import requests
import json
import re
import datetime
import os
import argparse

# Path to the configuration file
# Use the main configuration.json for all types since it contains all headers
config_file_path="configuration.json"

# Configure argparse for command-line arguments
parser= argparse.ArgumentParser(description="Security Headers Scanner by Securily")
parser.add_argument("-u", "--url-to-scan", type=str, required=True, help="URL to scan")
parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
parser.add_argument("-a", "--authorization-for-api", type=str, help="Authorization Token For APIs")
parser.add_argument("-ai", "--ai-insights", type=str, help="Enable AI insights with Gemini API key")
args = parser.parse_args()

# The URL to Scan
URL = args.url_to_scan
# The Authorization Token for an API Scan
authorization = args.authorization_for_api

print(f"URL to scan: {URL}")

# List of HTTP headers
headers_to_read = []
# Array to store configuration
configuration = []

web_security_headers = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "X-Frame-Options",
    "X-XSS-Protection",
    "Referrer-Policy",
    "Permissions-Policy",
    "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Opener-Policy",
    "Cross-Origin-Resource-Policy",
    "Expect-CT",
    "Feature-Policy"
]

app_security_headers = [
    "Content-Type",
    "Content-Length",
    "Cache-Control",
    "Content-Encoding",
    "ETag",
    "Vary"
]

api_security_headers = [
    "Content-Security-Policy",
    "X-Content-Type-Options",
    "Strict-Transport-Security",
    "X-Frame-Options",
    "Access-Control-Allow-Origin",
    "Access-Control-Allow-Methods",
    "Access-Control-Allow-Headers",
    "Access-Control-Allow-Credentials",
    "Access-Control-Expose-Headers",
    "Access-Control-Max-Age",
    "Cross-Origin-Resource-Policy"
]


def normalizeUrl(url):
    if not re.match('^https?://', url):
        url = 'https://' + url
    return url

def fix_bad_json(json_string):
    try:
        # Try loading the JSON string as is
        json_data = json.loads(json_string)
        return json_data

    except json.JSONDecodeError as e:
        if args.verbose:
          print("Error occurred while decoding JSON: {}".format(str(e)))

        # Remove the invalid control character
        cleaned_json = ''.join(c for c in json_string if c.isprintable())
        try:
            json_data = json.loads(cleaned_json)
            if args.verbose:
              print("Successfully fixed the bad JSON.")
            return json_data

        except json.JSONDecodeError as e:
            if args.verbose:
              print("Error occurred while fixing the bad JSON: {}".format(str(e)))

    return None


def read_headers_from_url(url, test_type='web', authorization=None, payload={}):
    try:
        url = normalizeUrl(url)
        if test_type == 'web' or test_type == 'app':
            payload = {}
            request_headers = {}

            response = requests.request("GET", url, headers=request_headers, data=payload, allow_redirects=True)
        elif test_type == 'api':
            request_headers = {
                'Authorization': 'Bearer ' + authorization
            }
            response = requests.request("GET", url, headers=request_headers, data=payload, allow_redirects=True)
        else:
            response = requests.head(url, allow_redirects=True)

        response_headers = response.headers

        headers = {}
        status_code = response.status_code

        for header in headers_to_read:
            header_value = response_headers.get(header)
            if header_value and (header_value.startswith("http://") or header_value.startswith("https://")):
                try:
                    response = requests.get(header_value, verify=False)
                    if response.status_code == 200:
                        header_value = response.text
                        headers[header] = header_value
                    else:
                        header_value = "Failed to download content"
                except requests.exceptions.RequestException as e:
                    header_value = "Failed to download content: {}".format(str(e))

            if header_value:
                headers[header] = header_value
            else:
                headers[header] = "Not Found"

        return headers, status_code

    except requests.RequestException as e:
        if args.verbose:
          print("Error occurred while reading headers from URL: {}".format(str(e)))
        return None


def compare_headers_configuration(headers_found, source_configuration, status_code, url):
    results = []

    for header in headers_to_read:
        header_config = next((config for config in source_configuration if config['name'] == header), None)

        header_value = headers_found.get(header)

        if header_config:
            if header.lower() == header_config.get('name').lower() and (header_config.get('values') and any(keyword.lower() in header_value.lower() for keyword in header_config['values'].split(', '))):
                results.append({"url": url, "name": header_config.get('name'), "value": (header_value or "n/a"), "severity": header_config.get('severity'), "reason": header_config.get('reason'), "remediation": header_config.get('remediation'), "values": header_config.get('values'), "status": "PASS", "status_code": status_code})
            elif header.lower() == header_config.get('name').lower() and (header_value != 'Not Found'):
                results.append({"url": url, "name": header_config.get('name'), "value": (header_value or "n/a"), "severity": header_config.get('severity'), "reason": header_config.get('reason'), "remediation": header_config.get('remediation'), "values": header_config.get('values'), "status": "PASS", "type": "EXCELLENT", "status_code": status_code})
            else:
                results.append({"url": url, "name": header_config.get('name'), "value": (header_value or "n/a"), "severity": header_config.get('severity'), "reason": header_config.get('reason'), "remediation": header_config.get('remediation'), "values": header_config.get('values'), "directives": header_config.get('directives'), "status": "FAIL", "status_code": status_code})
        else:
            results.append({"url": url, "name": header, "value": (header_value or "n/a"), "severity": "", "reason": "", "remediation": "", "values": "", "directives": "", "status": "FAIL", "status_code": status_code})

    return results


# AI Insights function - provides smart analysis of scan results
def get_ai_insights(results, url, api_key):
    """Generate AI-powered insights based on scan results"""
    try:
        # Prepare context for AI
        failed_headers = [r for r in results if r["status"] == "FAIL"]
        passed_headers = [r for r in results if r["status"] == "PASS"]
        
        # Create a summary of the scan
        summary = f"""
        Website: {url}
        Total Headers Scanned: {len(results)}
        Headers Present: {len(passed_headers)}
        Headers Missing: {len(failed_headers)}
        
        Missing Critical Headers:
        {', '.join([h['name'] for h in failed_headers if h.get('severity') == 'High'])}
        
        Present Headers:
        {', '.join([h['name'] for h in passed_headers])}
        """
        
        # Create the prompt for AI
        prompt = f"""As a security expert, analyze these security header scan results and provide:
        
        1. Overall Security Grade (A+ to F)
        2. Top 3 Priority Actions (be specific to this site)
        3. Risk Assessment (what attacks are they vulnerable to)
        4. Quick Wins (headers that are easy to implement)
        5. Industry Context (how does this compare to best practices)
        
        Scan Summary:
        {summary}
        
        Be concise, practical, and specific. Format as JSON with keys: grade, priority_actions, risk_assessment, quick_wins, industry_context"""
        
        # Call Gemini API
        response = requests.post(
            url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash-exp:generateContent?key={api_key}",
            json = {
                "contents": [{
                    "parts": [{"text": prompt}]
                }]
            },
            headers = {"Content-Type": "application/json"}
        )
        
        if response.status_code == 200:
            try:
                ai_response = response.json()
                insights_text = ai_response['candidates'][0]['content']['parts'][0]['text']
                
                # Try to parse as JSON, fallback to text if needed
                try:
                    # Remove markdown code blocks if present
                    insights_text = insights_text.replace('```json', '').replace('```', '').strip()
                    insights = json.loads(insights_text)
                except:
                    # If not valid JSON, structure it
                    insights = {
                        "analysis": insights_text,
                        "error": "AI response was not in expected JSON format"
                    }
                
                return insights
            except Exception as e:
                if args.verbose:
                    print(f"Error parsing AI response: {e}")
                return None
        else:
            if args.verbose:
                print(f"AI API error: {response.status_code}")
            return None
            
    except Exception as e:
        if args.verbose:
            print(f"Error getting AI insights: {e}")
        return None

# Determine the type of headers based on the URL
URL = normalizeUrl(URL)
testType = ''
if "app" in URL:
    headers_to_read = web_security_headers + app_security_headers
    testType = 'app'
elif "api" in URL:
    # Check if 'authorization' exists and is not None and not empty
    if 'authorization' in locals() and authorization is not None and authorization.strip() != "":
        headers_to_read = api_security_headers
        testType = 'api'
    else:
        # Handle the case where 'authorization' is missing or empty
        headers_to_read = web_security_headers
        testType = 'web'
else:
    headers_to_read = web_security_headers
    testType = 'web'

# Example usage of read_headers_from_url()
status_code = 0
headers, status_code = read_headers_from_url(URL, testType, authorization)
if headers:
    print("Finished reading headers from URL: {}".format(URL))
    if args.verbose:
        print("Headers from URL: {}".format(URL))
        print(json.dumps(headers, indent=4))
        print()

# Function to check if configuration file is valid
def is_config_valid(filepath):
    if not os.path.exists(filepath):
        return False
    try:
        with open(filepath, "r") as file:
            data = json.load(file)
            # Check if configuration is empty or invalid
            if not data or not isinstance(data, list) or len(data) == 0:
                return False
            # Check if first item has required fields
            if not all(key in data[0] for key in ['name', 'severity', 'reason', 'remediation']):
                return False
            return True
    except:
        return False

# Load configuration from file
if is_config_valid(config_file_path):
    # Load the existing valid configuration
    with open(config_file_path, "r") as file:
        configuration = json.load(file)
    print("Finished loading existing configuration from file")
else:
    print(f"ERROR: Configuration file '{config_file_path}' is missing or invalid!")
    print(f"Please ensure '{config_file_path}' exists and contains valid header definitions.")
    exit(1)

# Compare headers and configuration
results = compare_headers_configuration(headers, configuration, status_code, URL)

print("Finished comparing headers and configuration")

# Store the results in a list
results_list = []
for result in results:
    results_list.append(result)

# AI Insights Enhancement (optional)
if args.ai_insights:
    print("\nGenerating AI insights...")
    insights = get_ai_insights(results_list, URL, args.ai_insights)
    if insights:
        # Add insights to results
        enhanced_results = {
            "scan_results": results_list,
            "ai_insights": insights,
            "scan_metadata": {
                "url": URL,
                "timestamp": datetime.datetime.now().isoformat(),
                "headers_scanned": len(results_list),
                "headers_passed": sum(1 for r in results_list if r["status"] == "PASS"),
                "headers_failed": sum(1 for r in results_list if r["status"] == "FAIL")
            }
        }
        results_json = json.dumps(enhanced_results, indent=4)
    else:
        results_json = json.dumps(results_list, indent=4)
else:
    results_json = json.dumps(results_list, indent=4)

# Print the results
print(results_json)

# Write the results to a file
with open("results.json", "w") as file:
    file.write(results_json)

print("\nResults have been saved to results.json")