"""
Parses IP addresses from .pcap and returns how many times each address showed up
Downloads files from .pcap to a specific directory
  - Secure directory
Show address referrers for HTTP GET requests
GUI for program I/O
"""
import json
import requests
from scapy.all import *
from config.config import APIkeys

headers = {
    "accept": "application/json",
    "x-apikey": APIkeys.apikeys
}

ips_from_pcap = []


def get_file_id():
    url = "https://www.virustotal.com/api/v3/files"
    file_path = input("Enter path of file: ")
    files = {"file": open(file_path, "rb")}
    response = requests.post(url, files=files, headers=headers)
    text = response.text
    parse_json = json.loads(text)

    active_case = parse_json['data']['id']
    return active_case


def parse_id():
    """Retrieves only the VT ID of the file, decodes it from Base64, and appends the ID (SHA-256 hash) to file"""
    linux_decode = 'echo ' + get_file_id() + '| base64 -d > decoded_b64.txt'
    linux_create_file = 'touch file_id'
    os.system(linux_decode)
    os.system(linux_create_file)
    final_id = []
    sliced_id = []
    with open('decoded_b64.txt', 'r') as file_id:
        lines = file_id.read()
        data = lines.split(":")
        final_id.append(data[0])
    with open("decoded_b64.txt", 'r+') as hash_id:
        for i in hash_id:
            sliced_id.append(i[:-11])
    with open('file_id', 'r+') as file_id2:
        for j in sliced_id:
            file_id2.write(j)


def get_file_report():
    """Gets the file report from VT and returns the JSON response. Returned values:
        file_type, popular_threat_category, malicious"""
    parse_id()
    file_hash_array = []
    report_contents = []
    with open("file_id", "r") as hash_file:
        for i in hash_file:
            file_hash_array.append(i)
    get_report_url = "https://www.virustotal.com/api/v3/files/" + file_hash_array[0]
    response = requests.get(get_report_url, headers=headers)
    text_response = response.text
    parse_report_json = json.loads(text_response)
    file_hits = parse_report_json['data']['attributes']['last_analysis_stats']['malicious']
    file_type = parse_report_json['data']['attributes']['trid'][0]['file_type']
    threat_category = parse_report_json['data']['attributes']['popular_threat_classification']['popular_threat_category'][0]['value']
    threat_name = parse_report_json['data']['attributes']['popular_threat_classification']['popular_threat_name'][1]['value']
    report_contents.extend([file_hits, file_type, threat_category, threat_name])
    for i in report_contents:
        print(i)


def pcap_extractor():
    """Extracts IPs from selected .pcap and stores in the separate_ips list"""

    packets = rdpcap("/home/kali/Downloads/2014-11-16-traffic-analysis-exercise.pcap")

    first_pass_list = []
    for p in packets:
        temp = p.sprintf("%IP.src%,%IP.dst%,")
        first_pass_list.append(temp)
        for i in first_pass_list:
            ips_from_pcap.append(i)
    res = [*set(ips_from_pcap)]  # removes duplicate IPs from list
    separate_ips = [y for x in res for y in x.split(',')]
    while "" in separate_ips:  # removes unresolved IPs from the list
        separate_ips.remove("")
    if '??' in separate_ips:  # prevents Python from crashing when '??' is not present
        while '??' in separate_ips:
            separate_ips.remove('??')
    separate_ips = list(dict.fromkeys(separate_ips))  # removes duplicates from list since dicts can have dupes
    user_ip = os.system("ifconfig >/dev/null")
    if user_ip in separate_ips:
        separate_ips.remove(user_ip)
    return separate_ips


if __name__ == "__main__":
    new_ips = pcap_extractor()
    print(new_ips)
# /home/kali/Downloads/2014-pcap-exercise/malJar.jar
# /home/kali/Downloads/2014-11-16-traffic-analysis-exercise.pcap
