from flask import Flask, redirect, url_for, session, request, jsonify, render_template
from authlib.integrations.flask_client import OAuth
import re, requests, base64, pytz
from datetime import datetime
from zoneinfo import ZoneInfo
import json

app = Flask(__name__)
app.secret_key = 'secret_key'  # todo:

with open('google_api.json', 'r') as f:
    google_api = json.loads(f.read())
client_id = google_api['web']['client_id']
client_secret = google_api['web']['client_secret']

# Google OAuth
# Scope: readonly
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=client_id,         
    client_secret=client_secret,  
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile https://www.googleapis.com/auth/gmail.readonly'
    }
)

# todo: Microsoft OAuth
# microsoft = 


#############################################
# User login and OAuth callback
#############################################
@app.route('/')
def homepage():
    return render_template('index.html')

@app.route('/login/google')
def login_google():
    redirect_uri = url_for('authorize_google', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/google')
def authorize_google():
    token = google.authorize_access_token()
    session['google_token'] = token  
    # get OpenID Connect user info
    metadata = google.load_server_metadata()
    user_info_endpoint = metadata.get('userinfo_endpoint')
    if not user_info_endpoint or not user_info_endpoint.startswith('http'):
        user_info_endpoint = 'https://openidconnect.googleapis.com/v1/userinfo'
    user_info = google.get(user_info_endpoint).json()
    session['user_info'] = user_info
    return redirect(url_for('dashboard'))


#############################################
# dashboard & email parse
#############################################
@app.route('/dashboard')
def dashboard():
    user_info = session.get('user_info')
    user_tz = session.get('user_timezone', None)
    return render_template('dashboard.html', user_info=user_info, user_timezone=user_tz)


# fetch Gmail from specified sender
@app.route('/fetch-emails')
def fetch_emails():
    token = session.get('google_token')
    if not token:
        return redirect(url_for('homepage'))
    headers_req = {'Authorization': 'Bearer ' + token['access_token']}
   
    sender_list = [
        "customerservice@ealerts.bankofamerica.com",
        "onlinebanking@ealerts.bankofamerica.com"
    ]

    query = " OR ".join([f"from:{sender}" for sender in sender_list])
    url = "https://gmail.googleapis.com/gmail/v1/users/me/messages"
    params = {"q": query}
    response = requests.get(url, headers=headers_req, params=params)
    if response.status_code != 200:
        return jsonify({"error": response.json()}), response.status_code
    messages = response.json().get('messages', [])
    parsed_results = []
    user_tz = session.get('user_timezone', None)
    for msg in messages:
        msg_id = msg['id']
        msg_url = f"https://gmail.googleapis.com/gmail/v1/users/me/messages/{msg_id}?format=full"
        msg_response = requests.get(msg_url, headers=headers_req)
        if msg_response.status_code != 200:
            continue
        msg_json = msg_response.json()
        snippet = msg_json.get("snippet", "")
        # classify emails
        if "sent you" in snippet:
            parsed = parse_incoming_email(msg_json)
            parsed['type'] = 'incoming'
        elif "has been sent" in snippet:
            parsed = parse_outgoing_email(msg_json)
            parsed['type'] = 'outgoing'
        else: 
            continue
        # If the user has set a time zone preference, convert the time in the email
        if user_tz and parsed.get("transfer_time"):
            original_time = parsed["transfer_time"]
            converted_time = convert_time(original_time, user_tz)
            parsed["converted_transfer_time"] = converted_time
        parsed_results.append(parsed)
    return jsonify({"parsed_emails": parsed_results})


#############################################
# parse email
#############################################
def extract_transfer_time(headers):
    for header in headers:
        if header.get('name', '').lower() == 'received':
            parts = header.get('value', '').split(';')
            if len(parts) > 1:
                date_str = parts[-1].strip()
                date_str = re.sub(r'\s*\(.*\)$', '', date_str)
                return date_str
    return None


def parse_outgoing_email(email_json):
    snippet = email_json.get("snippet", "")
    trans_info_pattern = r"(Zelle.*?)(?=Your message|View your balance)"
    trans_info_match = re.search(trans_info_pattern, snippet)
    if trans_info_match:
        trans_info = trans_info_match.group(1)
    else:
        trans_info = None
    
    message_pattern = r"Your message(.+)View your balance"
    message_match = re.search(message_pattern, snippet)
    if message_match:
        message = message_match.group(1) 
    else:
        message = None
        
    headers = email_json.get("payload", {}).get("headers", [])
    transfer_time = extract_transfer_time(headers)
    return {"transfer_info": trans_info, "message": message,  "transfer_time": transfer_time}


def parse_incoming_email(email_json):
    snippet = email_json.get("snippet", "")
    m = re.search(r"^(?P<sender>[A-Za-z\s]+)\s+sent you\s+(?P<amount>\$\d+(?:\.\d+)?)", snippet)
    sender = m.group("sender").strip() if m else None
    amount = m.group("amount") if m else None
    headers = email_json.get("payload", {}).get("headers", [])
    transfer_time = extract_transfer_time(headers)
    message = None
    return {"sender": sender, "amount": amount, "transfer_time": transfer_time, "message": message}


#############################################
# Time zone conversion
#############################################
def convert_time(original_time_str, target_tz):
    """Convert a raw time string to the target time zone

    Args:
        original_time_str: raw time string (eg. "Mon, 17 Mar 2025 14:12:04 -0700")
        target_tz: target time zone in IANA format (eg. "America/New_York") 

    Returns:
        str: converted time string
    """

    try:
        dt = datetime.strptime(original_time_str, "%a, %d %b %Y %H:%M:%S %z")
        target = ZoneInfo(target_tz)
        converted = dt.astimezone(target)
        return converted.strftime("%a, %d %b %Y %H:%M:%S %z")
    except Exception as e:
        return f"Conversion Error: {e}"


def search_timezones(prefix):
    """
    return a list of matching IANA timezones given the timezone prefix entered by the user.
    """
    return [tz for tz in pytz.all_timezones if tz.lower().startswith(prefix.lower())]


@app.route('/search-timezone')
def search_timezone():
    prefix = request.args.get('prefix', '')
    matches = search_timezones(prefix)
    return jsonify(matches)


# user sets the time zone preference
@app.route('/set_timezone', methods=['GET', 'POST'])
def set_timezone():
    if request.method == 'POST':
        target_tz = request.form.get('target_tz')
        session['user_timezone'] = target_tz
        return redirect(url_for('dashboard'))
    current_tz = session.get('user_timezone', '')
    return render_template('set_timezone.html', current_tz=current_tz)


if __name__ == '__main__':
    app.run(debug=True)
