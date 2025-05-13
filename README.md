# 🔍 SQL Injection Vulnerability Scanner

A Python-based tool that automatically detects **SQL injection vulnerabilities** by crawling websites, testing URL parameters and HTML forms using various SQL payloads, and generating detailed JSON and HTML reports.

## 🚀 Features

* ✅ Automatic **website crawling** for internal pages
* ✅ Tests both **GET parameters** and **HTML form inputs**
* ✅ Uses a variety of **SQL injection payloads**
* ✅ Detects **error-based**, **union-based**, and **time-based blind SQLi**
* ✅ Classifies vulnerabilities by **severity** (Low, Medium, High)
* ✅ Generates structured **JSON log** and a styled **HTML report**
* ✅ Multithreaded scanning for faster execution


## 🧠 Project Objective

> To develop an automated tool that detects SQL injection vulnerabilities in web applications by scanning URLs and forms, injecting crafted payloads, and analyzing server responses for signs of vulnerabilities.


## 🛠️ Technologies Used

* **Python 3**
* `requests` – HTTP requests
* `BeautifulSoup (bs4)` – HTML parsing
* `concurrent.futures` – multithreading
* `urllib.parse` – URL manipulation
* `json` – logging vulnerabilities
* `HTML/CSS/JS` – styled report generation


## 🌐 Tested On

1. `http://testasp.vulnweb.com/` – ASP-based vulnerable site
2. `http://testphp.vulnweb.com/` – PHP-based vulnerable site

> Both are intentionally vulnerable environments for safe security testing.


## 🔁 How It Works

1. **Crawls the website** from a given base URL to discover all internal links.
2. **Detects injection points** in URLs and forms.
3. **Injects SQL payloads** into detected parameters.
4. **Analyzes server response** for SQL error messages or time delays.
5. **Logs vulnerabilities** and generates:

   * `advanced_vuln_log.json` – structured log file
   * `report.html` – human-readable HTML report


## 💉 SQL Injection Payloads

The scanner uses a combination of:

* **Boolean-based**: `' OR 1=1 --`
* **Union-based**: `' UNION SELECT ...`
* **Time-based blind SQLi**: `' OR SLEEP(5)--`

Each payload is tested across all URLs and forms found during crawling.


## 📂 Output

* `report.html`

  > Clean, interactive HTML table showing all detected vulnerabilities, severity, payloads, and full server response.

* `advanced_vuln_log.json`

  > Raw data log of all vulnerabilities in JSON format for developers or automated tools.



## 📉 Severity Levels

| Severity | Description                      |
| -------- | -------------------------------- |
| High     | Time-based attacks succeeded     |
| Medium   | Union-based injections worked    |
| Low      | Basic Boolean injection detected |


## 🧪 Usage

### 1. Install dependencies

```bash
pip install requests beautifulsoup4
```

### 2. Run the scanner

Edit the `base_url` in `scanner.py` to your target, then:

```bash
python scanner.py
```
