
from flask import Flask, request, jsonify
import pandas as pd
import ipaddress
import requests
import json
import os

app = Flask(__name__)

global_start_ip = None
global_end_ip = None

try:
    df = pd.read_csv('data.csv', on_bad_lines='skip')
    print(df.columns) 
except pd.errors.ParserError as e:
    print(f"Error reading CSV: {e}")
    df = pd.DataFrame() 

def convert_to_cidr(start_ip, end_ip):
    start_ip = ipaddress.ip_address(start_ip)
    end_ip = ipaddress.ip_address(end_ip)

    if start_ip > end_ip:
        raise ValueError("Start IP must be less than or equal to End IP")

    network = ipaddress.summarize_address_range(start_ip, end_ip)

    return [str(prefix) for prefix in network]

def load_missing_ips():
    file_path = 'missing_ips.json'

    if not os.path.exists(file_path):
        return []

    with open(file_path, 'r') as f:
        return json.load(f)

def save_missing_ip_json(ip):
    file_path = 'missing_ips.json'

    if not os.path.exists(file_path):
        with open(file_path, 'w') as f:
            json.dump([], f)

    with open(file_path, 'r') as f:
        missing_ips = json.load(f)

    if ip not in missing_ips:
        missing_ips.append(ip)

        with open(file_path, 'w') as f:
            json.dump(missing_ips, f, indent=4)


@app.route('/iplookup', methods=['GET'])
def ip_lookup():
    global global_start_ip, global_end_ip 

    ip = request.args.get('ip')
    if not ip:
        return jsonify({"error": "IP address is required"}), 400

    try:
        ip_obj = ipaddress.ip_address(ip)
    except ValueError:
        return jsonify({"error": "Invalid IP address"}), 400

    missing_ips = load_missing_ips()

    if ip in missing_ips:
        return jsonify({"error": " IP is in missing list, please check later"}), 404

    for _, row in df.iterrows():
        try:
            start_ip = ipaddress.ip_address(row['start_ip'])
            end_ip = ipaddress.ip_address(row['end_ip'])
        except ValueError:
            continue  

        if (ip_obj.version == start_ip.version == end_ip.version and
            start_ip <= ip_obj <= end_ip):
            result = {
                "ip_address": ip,
                "start_ip": str(start_ip),
                "end_ip": str(end_ip),
                "asn": row['asn'],
                "as_name": row['as_name'],
                "as_domain": row['as_domain']
            }

            global_start_ip = str(start_ip)
            global_end_ip = str(end_ip)

            cidr_prefixes = convert_to_cidr(global_start_ip, global_end_ip)
            
            result['prefixes'] = cidr_prefixes 
            
            send_to_netbox(result)

            return jsonify(result)
            
    save_missing_ip_json(ip)
    return jsonify({"error": "IP not found in database"}), 404

def send_to_netbox(lookup_data):
    description = f"{lookup_data['as_name']} ({lookup_data['asn']}), {lookup_data['as_domain']}"

    netbox_api_url = "http://localhost:8000/api/ipam/prefixes/"

    for prefix in lookup_data.get('prefixes', []):
        netbox_data = {
            "prefix": prefix,
            "description": description,
            "status": "active"
        }

        headers = {
            "Authorization": "Token xxxxxxxx",
            "Content-Type": "application/json"
        }

        response = requests.post(netbox_api_url, json=netbox_data, headers=headers)

        if response.status_code == 201:
            print(f"Prefix {prefix} berhasil ditambahkan ke NetBox!")
        else:
            print(f"Gagal menambahkan prefix {prefix}: {response.text}")

if __name__ == '__main__':
    app.run(debug=True, port=5000)
