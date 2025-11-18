import sys
import os

# -----------------------
# FIX PYTHONPATH FOR PROJECT
# -----------------------
ROOT_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, ROOT_DIR)

# -----------------------
# STANDARD IMPORTS
# -----------------------
import json
import subprocess

# -----------------------
# IMPORT PARSER
# -----------------------
from parser.xml_parser import parse_nmap_xml

# -----------------------
# IMPORT CPE + CVE MAPPERS
# -----------------------
from cpe_mapper.cpe_mapper import guess_cpe
from cve_mapper.cve_mapper import find_cves_for_cpe

# -----------------------
# CONFIG FILE PATH
# -----------------------
CONFIG_PATH = os.path.join(ROOT_DIR, "config", "scan_profiles.json")
print("CONFIG PATH =", CONFIG_PATH)

# -----------------------
# LOAD PROFILES
# -----------------------
def load_profiles():
    print("Looking for:", CONFIG_PATH)
    print("Exists? ", os.path.exists(CONFIG_PATH))

    if not os.path.exists(CONFIG_PATH):
        raise FileNotFoundError(f"Config not found: {CONFIG_PATH}")

    with open(CONFIG_PATH, "r") as f:
        return json.load(f)

# -----------------------
# RUN NMAP SCAN
# -----------------------
def run_scan(target, profile_name):
    profiles = load_profiles()

    if profile_name not in profiles:
        raise ValueError(f"Profile '{profile_name}' not found.")

    profile = profiles[profile_name]
    nmap_cmd = f"nmap {profile['command']} -oX scan_output.xml {target}"

    print("\n[+] Running Nmap scan:")
    print("    Command:", nmap_cmd)

    subprocess.run(nmap_cmd, shell=True)
    print("\n[+] Scan completed. Output saved to scan_output.xml")

# -----------------------
# MAIN EXECUTION
# -----------------------
if __name__ == "__main__":
    target = input("Enter target IP or CIDR: ")
    profile = input("Choose profile (fast/full_tcp/lab_udp): ")

    # STEP 1: RUN SCAN
    run_scan(target, profile)

    # STEP 2: PARSE XML
    print("\n[+] Parsing results...")
    parsed_data = parse_nmap_xml("scan_output.xml")

    # STEP 3: ENRICH WITH CPE + CVE
    print("\n[+] Enriching results with CPE and CVE data...\n")
    enriched = []

    for item in parsed_data:
        service = item.get("service", "")
        product = item.get("product", "")

        # Predict CPE
        cpe = guess_cpe(service, product)
        item["cpe"] = cpe

        # Get CVEs ONLY IF CPE EXISTS
        if cpe:
            cves = find_cves_for_cpe(cpe)
        else:
            cves = []

        item["vulnerabilities"] = cves
        enriched.append(item)

    # STEP 4: PRINT FINAL RESULTS
    print("\n================ FINAL REPORT ================\n")

    for entry in enriched:
        print(f"IP:        {entry['ip']}")
        print(f"Port:      {entry['port']}")
        print(f"Service:   {entry['service']}")
        print(f"Product:   {entry['product']}")
        print(f"CPE:       {entry['cpe']}")

        if entry["vulnerabilities"]:
            print("CVE Matches:")
            for c in entry["vulnerabilities"]:
                print(f" - {c['id']} | {c['severity']} | Score: {c['score']}")
        else:
            print("No CVEs found.")

        print("-" * 60)
