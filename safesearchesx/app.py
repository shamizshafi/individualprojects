import os
from flask import Flask, render_template, request, redirect, url_for, jsonify, flash
from dotenv import load_dotenv
from authlib.integrations.flask_client import OAuth
from googleapiclient.discovery import build
import requests
import ssl
import OpenSSL.crypto
from urllib.parse import urlparse
import socket
import whois

app = Flask(__name__)
app.secret_key = os.urandom(24)
app.config["TRAP_BAD_REQUEST_ERRORS"] = True

# Load environment variables
load_dotenv()

# Initialize OAuth
oauth = OAuth(app)

# Configure the Google OAuth provider
google = oauth.register(
    name="google",
    client_id=os.environ.get("GOOGLE_CLIENT_ID"),
    client_secret=os.environ.get("GOOGLE_CLIENT_SECRET"),
    access_token_url="https://accounts.google.com/o/oauth2/token",
    access_token_params=None,
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    api_base_url="https://www.googleapis.com/oauth2/v1/",
    userinfo_endpoint="https://openidconnect.googleapis.com/v1/userinfo",
    client_kwargs={"scope": "openid email profile"},
)
def get_pagespeed(url):
    pagespeed_url = f"https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url={url}"
    result = requests.get(pagespeed_url)
    return result.json()["lighthouseResult"]["categories"]["performance"]["score"]

@app.route('/results')
def results():
    url = request.args.get('url')
    if not url:
        flash("URL parameter is missing.", category="error")
        return redirect(url_for("index"))

    parsed_url = urlparse(url)
    if not parsed_url.scheme:
        url = 'http://' + url
        parsed_url = urlparse(url)

    # Your API key for the Google Safe Browsing API
    GOOGLE_API_KEY = os.environ.get("GOOGLE_SAFE_BROWSING_API_KEY")

    # Check if the website is safe
    safe_browsing_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_API_KEY}'
    payload = {
        "client": {
            "clientId": "yourcompanyname",
            "clientVersion": "1.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
            "platformTypes": ["WINDOWS"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }
    response = requests.post(safe_browsing_url, json=payload)
    is_safe = response.json() == {}

    # Check SSL certificate
    try:
        cert = ssl.get_server_certificate((parsed_url.hostname, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)
        x509.get_issuer()
        has_ssl = True
    except (ssl.SSLError, ValueError, OpenSSL.crypto.Error):
        has_ssl = False

    # Check server IP
    try :
        ip_address = socket.gethostbyname(parsed_url.hostname)   
    except socket.gaierror:
        ip_address = None

    # Check Whois information
    # domain_info = whois.whois(parsed_url.hostname)
    domain_info = None  # We can set domain_info to None as we are not using the whois module

    # Check speed score
    speed_score = get_pagespeed(url)

    return render_template('results.html', url=url, is_safe=is_safe, has_ssl=has_ssl, ip_address=ip_address, domain_info=domain_info, speed_score=speed_score)

def search_web(query, api_key, cx):
    print(f"Query: {query}, API Key: {api_key}, CX: {cx}")
    service = build("customsearch", "v1", developerKey=api_key)
    result = service.cse().list(q=query, cx=cx).execute()
    return result.get("items", [])

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'query' in request.form:
            query = request.form['query']
            search_results = search_web(query, os.environ.get("GOOGLE_SEARCH_API_KEY"), os.environ.get("GOOGLE_SEARCH_CX"))
            return render_template('search_results.html', search_results=search_results)
        elif 'login' in request.form:
            return redirect(url_for("login"))
    return render_template('index.html')

# Login route
@app.route("/login")
def login():
    redirect_uri = url_for("auth_callback", _external=True)
    return google.authorize_redirect(redirect_uri)

# OAuth callback route
@app.route("/auth_callback")
def auth_callback():
    token = google.authorize_access_token()
    userinfo = google.get("userinfo").json()
    # You can store the userinfo in your database or session here
    flash("Logged in successfully.", category="success")
    return jsonify(userinfo)

if __name__ == '__main__':
    app.run(debug=True)
