#!/usr/bin/python
import json
import subprocess
import requests

# File paths
input_file = 'missing_ips.json'
processed_file = 'processed_ips.json'  
netbox_url = 'http://localhost:8000/api/ipam/prefixes/'  
netbox_token = 'xxxxxxxx'  

# Headers for authentication with NetBox API
headers = {
    'Authorization': f'Token {netbox_token}',
    'Content-Type': 'application/json'
}

# Function to post prefix to NetBox IPAM
def post_prefix_to_netbox(prefix, description):
    data = {
        'prefix': prefix,
        'description': description
    }
    try:
        response = requests.post(netbox_url, headers=headers, json=data)
        if response.status_code == 201:
            print(f"Successfully added prefix: {prefix}")
            return True
        else:
            print(f"Failed to add prefix: {prefix}. Error: {response.status_code}, {response.text}")
            return False
    except Exception as e:
        print(f"Exception occurred while sending prefix {prefix} to NetBox: {e}")
        return False

# Load missing IPs from the JSON file
with open(input_file, 'r') as file:
    missing_ips = json.load(file)

# Load processed IPs from the processed file, or create an empty list if the file doesn't exist
try:
    with open(processed_file, 'r') as file:
        processed_ips = json.load(file)
        if not isinstance(processed_ips, list):
            raise ValueError("Processed IPs data is not a list")
except (FileNotFoundError, json.JSONDecodeError, ValueError) as e:
    print(f"Error reading processed IPs file: {e}")
    processed_ips = []

# Convert processed_ips list to a dictionary for easy lookup
processed_ips_dict = {entry['ip']: entry['comment'] for entry in processed_ips}

for ip in missing_ips:
    # Skip the IP if it has already been processed
    if ip in processed_ips_dict:
        print(f"IP {ip} has already been processed. Skipping.")
        continue

    try:
        # Run the whois command directed at Cymru for each IP
        result = subprocess.run(['whois', '-h', 'whois.cymru.com', f" -v {ip}"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        
        # Check if whois command was successful
        if result.returncode == 0:
            lines = result.stdout.splitlines()
            if len(lines) > 1:
                # Example: "15169   | 8.8.8.8          | 8.8.8.0/24          | US | arin     | 2023-12-28 | GOOGLE, US"
                data_parts = lines[1].split('|')
                as_number = data_parts[0].strip()
                ip_address = data_parts[1].strip()
                prefix = data_parts[2].strip()
                as_name = data_parts[6].strip()

                # Skip IP if AS number is "NA" or missing
                if as_number == "NA" or not prefix or not as_name:
                    print(f"Skipping IP {ip} due to invalid data.")
                    processed_ips_dict[ip] = 'Not processed due to invalid data'
                    continue

                # Create a description: AS Name (AS Number)
                description = f"{as_name} (AS{as_number})"
                
                # Send the prefix and description to NetBox
                success = post_prefix_to_netbox(prefix, description)

                if success:
                    # Add the IP to the processed IPs list with a comment
                    processed_ips_dict[ip] = 'Processed successfully'
                else:
                    processed_ips_dict[ip] = 'Not processed due to NetBox error'

                # Save the updated processed IPs back to the file
                processed_ips = [{'ip': ip, 'comment': comment} for ip, comment in processed_ips_dict.items()]
                with open(processed_file, 'w') as file:
                    json.dump(processed_ips, file, indent=4)
        else:
            print(f"Error retrieving Cymru whois data for IP: {ip}. {result.stderr}")
            processed_ips_dict[ip] = 'Not processed due to whois error'
            # Save the updated processed IPs back to the file
            processed_ips = [{'ip': ip, 'comment': comment} for ip, comment in processed_ips_dict.items()]
            with open(processed_file, 'w') as file:
                json.dump(processed_ips, file, indent=4)
    except Exception as e:
        print(f"Exception occurred for IP: {ip}: {e}")
        processed_ips_dict[ip] = 'Not processed due to exception'
        # Save the updated processed IPs back to the file
        processed_ips = [{'ip': ip, 'comment': comment} for ip, comment in processed_ips_dict.items()]
        with open(processed_file, 'w') as file:
            json.dump(processed_ips, file, indent=4)
