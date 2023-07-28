import address_enumerator
import requests
import json
import time
import ipaddress

headers = {
    "accept": "application/json",
    "x-apikey": "82ebfaa8f75ef18f3b561b67191796c68b32f697a5c356154512cafe0ebff08a"
}


# TODO: negate the lookup of special IPs (private IPs are continued past)
def get_whois_report():
    """Generates a WHOIS report from VT"""
    ip_address = address_enumerator.pcap_extractor()
    for ip in ip_address:
        if ipaddress.ip_address(ip).is_private:
            continue
        else:
            url = "https://www.virustotal.com/api/v3/ip_addresses/" + ip
            response = requests.get(url, headers=headers)
            # time.sleep(20)  # sleep for 20 seconds to stay within bounds of public API usage
            text = response.text
            parse_json = json.loads(text)

            # TODO: error handling; return valid values, even if API objects do not exist

        try:
            ip_country = parse_json['data']['attributes']['country']
            isp = parse_json['data']['attributes']['as_owner']
            certificate_name = parse_json['data']['attributes']['last_https_certificate']['subject']['CN']
            alternative_names = parse_json['data']['attributes']['last_https_certificate']['extensions'][
                'subject_alternative_name']
            print(f"IP: {ip}\nCountry: {ip_country}\nISP: {isp}\nCert name: {certificate_name}\nKnown names: {alternative_names}\n")
        except KeyError as key:
            print(f"Error parsing {ip}\n\t" + str(key) + " not found in the API response.")
            continue


if __name__ == "__main__":
    get_whois_report()
