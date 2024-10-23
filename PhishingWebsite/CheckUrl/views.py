import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report
from django.shortcuts import render
from CheckUrl.models import UrlModel
from CheckUrl.forms import UrlForm
import tldextract
import requests
from bs4 import BeautifulSoup
import socket
import geoip2.database
import datetime
from urllib.parse import urlparse
from django.utils import timezone
import re

# Load GeoIP database
reader = geoip2.database.Reader(r'C:\Users\sripa\OneDrive\Pictures\Desktop\Mini Project\PhishingWebsite\GeoLite2-City.mmdb')

# Load the dataset
df = pd.read_csv(r'C:\Users\sripa\OneDrive\Pictures\Desktop\Mini Project\phishing.csv')
X = df.iloc[:, :-1]
y = df.iloc[:, -1]
Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, random_state=0)
model = RandomForestClassifier()
model.fit(Xtrain, ytrain)

ypred = model.predict(Xtest)
print(classification_report(ytest, ypred))
print("\n\nAccuracy Score:", round(accuracy_score(ytest, ypred) * 100, 2), "%")

def url_checker(request):
    urlform = UrlForm()
    results = []
    if request.method == 'POST':
        domain_url = UrlForm(request.POST)
        if domain_url.is_valid():
            domain = domain_url.cleaned_data['Url']
            subdomain_urls = extract_subdomain_urls(domain)
            for url in subdomain_urls:
                features = extract_features(url)
                prediction = model.predict([list(features.values())])[0]
                if prediction == 1:
                    result = 'Safe' 
                else :
                 'Phishing'
                ip_address = get_ip_address(url)
                region = get_region(ip_address)
                results.append({'url': url, 'result': result, 'ip_address': ip_address, 'region': region})
            domain_url.save()

    return render(request, 'front.html', {'results': results, 'urlform': urlform})

def extract_subdomain_urls(domain_url):
    subdomain_urls = []
    extracted = tldextract.extract(domain_url)
    domain = extracted.domain
    suffix = extracted.suffix
    subdomains = ['www', 'blog', 'news', 'shop', 'forum', 'support', 'api',
                  'login', 'secure', 'payment', 'update', 'verify', 'account', 'password', 'recovery', 
                  'help', 'mail', 'admin', 'portal', 'gateway', 'auth', 'service', 'info', 'download', 
                  'upload', 'register', 'activate', 'online', 'mobile', 'webmail', 'ftp', 'ssh', 
                  'cpanel', 'whm', 'plesk', 'direct', 'instant', 'express', 'priority', 'premier', 'vip']  
    for subdomain in subdomains:
        subdomain_url = f"{subdomain}.{domain}.{suffix}"
        subdomain_urls.append(subdomain_url)
    return subdomain_urls

def extract_features(url):
    if not urlparse(url).scheme:
        url = 'https://' + url

  
   
        features = {}
        domain = urlparse(url).netloc
        if domain.startswith("www."):
            domain = domain[4:]

        try:
        # Fetch the WHOIS data
            whois_data = whois.whois(domain)
            creation_date = whois_data.creation_date

            if isinstance(creation_date, list):
                creation_date = creation_date[0]

        # Calculate the age of the domain
            if creation_date:
                features['age_of_domain'] = (datetime.now() - creation_date).days
            else:
                features['age_of_domain'] = None

        except Exception as e:
        # Handle any exceptions, e.g., domain not found in WHOIS
            features['age_of_domain'] = None
            print(f"Error fetching WHOIS data for domain {domain}: {e}")

    # Index
          # This feature is not clear, assuming it's a placeholder

    # Using IP
        features['using_ip'] = bool(re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', url))

    # Long URL
        features['long_url'] = len(url) > 54

    # Short URL
        features['short_url'] = len(url) < 17

    # Symbol @
        features['symbol_at'] = '@' in url

    # Redirecting //
        features['redirecting'] = '//' in url

    # Prefix Suffix -
        features['prefix_suffix'] = '-' in url

    # Sub Domains
        features['sub_domains'] = len(urlparse(url).netloc.split('.')) > 2

    # HTTPS
        features['https'] = url.startswith('https')

    # Domain Reg Len
        features['domain_reg_len'] = len(urlparse(url).netloc)

    # Favicon
        features['favicon'] = bool(re.search(r'<link rel="icon"', url))

    # Non Std Port
        features['non_std_port'] = urlparse(url).port not in [80, 443]

    # HTTPS Domain URL
        features['https_domain_url'] = urlparse(url).scheme == 'https' and urlparse(url).netloc == urlparse(url).path

    # Request URL
        features['request_url'] = bool(re.search(r'<form action=', url))

    # Anchor URL
        features['anchor_url'] = bool(re.search(r'<a href=', url))

    # Links In Script Tags
        features['links_in_script_tags'] = bool(re.search(r'<script>.*<a href=', url))

    # Server Form Handler
        features['server_form_handler'] = bool(re.search(r'<form action=".*?" method="post"', url))

    # Info Email
        features['info_email'] = bool(re.search(r'mailto:', url))

    # Abnormal URL
        features['abnormal_url'] = bool(re.search(r'[^a-zA-Z0-9\-\.]', url))

    # Website Forwarding
        features['website_forwarding'] = bool(re.search(r'<meta http-equiv="refresh"', url))

    # Status Bar Cust
        features['status_bar_cust'] = bool(re.search(r'<script>.*window.status=', url))

    # Disable Right Click
        features['disable_right_click'] = bool(re.search(r'<script>.*document.oncontextmenu=', url))

    # Using Popup Window
        features['using_popup_window'] = bool(re.search(r'<script>.*window\.open\(', url))

    # Iframe Redirection
        features['iframe_redirection'] = bool(re.search(r'<iframe src=', url))

    # Age of Domain
        

    # DNS Recording
        features['dns_recording'] = bool(re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$', urlparse(url).netloc))

    # Website Traffic
        features['website_traffic'] = 0  # This feature requires additional data

    # Page Rank
        features['page_rank'] = 0  # This feature requires additional data

    # Google Index
        features['google_index'] = 0  # This feature requires additional data

    # Links Pointing To Page
        features['links_pointing_to_page'] = 0  # This feature requires additional data

    # Stats Report
        features['stats_report'] = 0  # This feature requires additional data

    # Class
        features['class'] = 0  # This feature is the target variable, should be set accordingly

        return features

def is_ip_address(url):
    try:
        socket.inet_aton(url)
        return True
    except socket.error:
        return False

def is_normal_url(url):
    try:
        title = BeautifulSoup(requests.get(url).text, 'html.parser').find('title').text.strip()
        return title != ''
    except:
        return False

def get_ip_address(url):
    try:
        return socket.gethostbyname(url)
    except socket.gaierror:
        return None

import ipaddress

def get_region(ip_address):
    try:
        # Validate the IP address
        ip_address = str(ipaddress.ip_address(ip_address))
        response = reader.city(ip_address)
        return response
    except ValueError as e:
        print(f"Invalid IP address: {ip_address} - {e}")
        return None


def get_domain_age(url):
    try:
        whois_response = requests.get(f"https://whois.net/{url}").text
        creation_date = whois_response.split("Creation Date:")[1].split("\n")[0].strip()
        return (datetime.datetime.now() - datetime.datetime.strptime(creation_date, "%Y-%m-%d")).days
    except:
        return None

def get_page_rank(url):
    try:
        response = requests.get(f"https://www.alexa.com/siteinfo/{url}").text
        page_rank = response.split("Global Rank")[1].split("\n")[0].strip()
        return int(page_rank.replace(",", ""))
    except:
        return None
