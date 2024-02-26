from __future__ import division, print_function
import requests
from scapy.all import IP, TCP, UDP, RandShort, DNS, DNSQR
import pandas as pd
from keras.models import load_model
import math

# Flask utils
from flask import Flask, request,render_template, jsonify

# Define a flask app
app = Flask(__name__)

# Load your trained model
MODEL_PATH = './models/my_h5_model.h5'
model = load_model(MODEL_PATH)

#빈 데이터프레임 만들기
def new_df():
    df = pd.DataFrame(columns= ['URL_LENGTH', 'NUMBER_SPECIAL_CHARACTERS',
       'CONTENT_LENGTH','TCP_CONVERSATION_EXCHANGE',
       'DIST_REMOTE_TCP_PORT', 'REMOTE_IPS', 'APP_BYTES', 'DNS_QUERY_TIMES'])
    return df

def url_preprocess(url):
    df = new_df()
    response = requests.get(url)

    # url_length // 0~숫자값이므로 전처리 불필요
    url_length = len(url)
    df.at[0, 'URL_LENGTH'] = url_length

    # NUMBER_SPECIAL_CHARACTERS // 0~숫자값이므로 전처리 불필요
    NUMBER_SPECIAL_CHARACTERS = 0
    for i in url:
        if not i.isalnum():
            NUMBER_SPECIAL_CHARACTERS += 1
    df.at[0, 'NUMBER_SPECIAL_CHARACTERS'] = NUMBER_SPECIAL_CHARACTERS

    # CHARSET
    content_type = response.headers.get('content-type')
    if 'charset' in content_type:
        charset = content_type.split('charset=')[-1]

    # 결측치 처리
    allowed_charsets = ['ISO-8859', 'ISO-8859-1', 'UTF-8', 'iso-8859-1', 'us-ascii', 'utf-8', 'windows-1251',
                        'windows-1252']
    for allowed_charset in allowed_charsets:
        df.at[0, 'CHARSET_' + allowed_charset] = 0

    # 주어진 charset이 허용된 charset 중 어떤 것과 일치하는지 확인하여 해당 열을 1로 설정
    if charset in allowed_charsets:
        df.at[0, 'CHARSET_' + charset] = 1

    # server
    server_header = response.headers.get('Server')
    if server_header:
        server = server_header
    else:
        server = "other"  # 결측치 처리

    allowed_servers = ['ATS', 'Apache', 'Apache-Coyote/1.1', 'Apache/2',
                        'Apache/2.2.14 (FreeBSD) mod_ssl/2.2.14 OpenSSL/0.9.8y DAV/2 PHP/5.2.12 with Suhosin-Patch',
                        'Apache/2.2.15 (CentOS)', 'Apache/2.2.15 (Red Hat)',
                        'Apache/2.2.22 (Debian)', 'Apache/2.4.7 (Ubuntu)', 'GSE',
                        'Microsoft-HTTPAPI/2.0', 'Microsoft-IIS/6.0', 'Microsoft-IIS/7.5',
                        'Microsoft-IIS/8.5', 'Server', 'YouTubeFrontEnd', 'cloudflare-nginx',
                        'nginx', 'nginx/1.12.0']
    flag=0
    df.at[0, 'SERVER_other']=0
    for allowed_server in allowed_servers:
        df.at[0, 'SERVER_' + allowed_server] = 0
        if server==allowed_server:
            df.at[0, 'SERVER_' + allowed_server] = 1
            flag=1
    if flag==0:
        df.at[0, 'SERVER_other']=1

    # content_length
    content_length = len(response.text)
    df.at[0, 'CONTENT_LENGTH'] = content_length

    # whois_country
    import whois
    domain_info = whois.whois(url)
    country = domain_info.get('country')
    # 주어진 국가 목록에서 WHOIS_COUNTRY_ 뒤에 있는 값 추출
    allowed_countries = ['AU', 'CA', 'CH', 'CN', 'CZ', 'ES', 'FR', 'GB', 'IN', 'JP', 'NL', 'PA', 'UK', 'US']

    flag=0
    df.at[0, 'WHOIS_COUNTRY_other']=0
    for allowed_country in allowed_countries:
        df.at[0, 'WHOIS_COUNTRY' + allowed_country] = 0
        if country in allowed_countries:
            df.at[0, 'WHOIS_COUNTRY' + allowed_country] = 1
            flag=1
        
    if flag==0:
        df.at[0, 'WHOIS_COUNTRY_other']=1

    # TCP CONVERSTATION EXCHANGE
    ip_packets = IP(response.content)
    tcp_conversation_exchange = len(response.content)
    df.at[0, 'TCP_CONVERSATION_EXCHANGE'] = tcp_conversation_exchange

    # DIST REMOTE TCP PORT
    dist_remote_tcp_port = len(set(pkt[TCP].dport for pkt in ip_packets.payload if TCP in pkt))
    df.at[0, 'DIST_REMOTE_TCP_PORT'] = dist_remote_tcp_port

    # REMOTE IPS
    remote_ips = len(set(pkt[IP].src for pkt in ip_packets if IP in pkt))
    df.at[0, 'REMOTE_IPS'] = remote_ips

    # APP_BYTES
    app_bytes = len(response.content)
    df.at[0, 'APP_BYTES'] = app_bytes

    # DNS QUERY TIMES
    dns_query_times = len(IP() / UDP(sport=RandShort(), dport=53) / DNS(qd=DNSQR(qname=url)))
    df.at[0, 'DNS_QUERY_TIMES'] = dns_query_times
    df.fillna(0)
    df = df.astype(float)
    return df

@app.route('/templates/index.html', methods =["GET", "POST"])
def index():
    if request.method == "POST":
       return predict(request.form.get("url"))
    return render_template("index.html")

@app.route('/predict', methods =["GET", "POST"])
def predict():
    url = request.form.get("url")
    df = url_preprocess(url)
    #predictions = model_predict(df, model)
    result=model.predict(df)
    result=float(result)
    result = (math.floor(result * 100000) / 100000)
    malicious_probability = result * 100
    if result >= 0.8:
        website_status = "MALICIOUS!!!"
    else:
        website_status = "BENIGN!!!"

    # Create a dictionary containing the data to send to the frontend
    result = {
        "website_status": website_status,
        "malicious_probability": malicious_probability
    }

    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, use_reloader=False)
