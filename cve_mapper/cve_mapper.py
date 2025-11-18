import os
import json
import glob

# -----------------------------------------------------
# NVD 2.0 Loader
# -----------------------------------------------------

NVD_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "nvd")

def load_nvd_20():
    cve_list = []
    files = glob.glob(os.path.join(NVD_DIR, "*.json"))

    for fp in files:
        try:
            with open(fp, "r", encoding="utf-8") as f:
                data = json.load(f)

            # VULNERABILITIES LIST
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                if "cve" in item:
                    cve_list.append(item["cve"])

        except Exception as e:
            print(f"[ERROR] Failed to parse {fp}: {e}")

    print(f"[+] Loaded {len(cve_list)} CVEs from NVD 2.0")
    return cve_list

# Load once
NVD_DATA = load_nvd_20()


# -----------------------------------------------------
# Extract all CPEs (recursively)
# -----------------------------------------------------
def extract_cpes_v20(nodes):
    cpes = []

    for node in nodes:

        # direct matches
        for match in node.get("cpeMatch", []):
            if match.get("vulnerable", False):
                uri = match.get("criteria")
                if uri:
                    cpes.append(uri)

        # recursive children
        if "children" in node:
            cpes.extend(extract_cpes_v20(node["children"]))

    return cpes


# -----------------------------------------------------
# CPE → CVE Matching
# -----------------------------------------------------
def find_cves_for_cpe(cpe):
    if not cpe:
        return []

    matches = []

    for cve in NVD_DATA:

        # ----------------------------
        # FIX: configurations may be dict OR list OR missing
        # ----------------------------
        configs = cve.get("configurations", [])

        # Normalize to list
        if isinstance(configs, dict):
            configs = [configs]
        elif not isinstance(configs, list):
            configs = []

        # Extract nodes safely
        all_nodes = []
        for cfg in configs:
            nodes = cfg.get("nodes", [])
            if isinstance(nodes, list):
                all_nodes.extend(nodes)

        # Extract CPE URIs from all nodes (recursive)
        cpe_list = extract_cpes_v20(all_nodes)

        # ----------------------------
        # Match guessed CPE
        # ----------------------------
        for cpe_uri in cpe_list:
            if cpe.lower() in cpe_uri.lower():

                # CVE ID
                cve_id = cve.get("id", "UNKNOWN")

                # Description
                desc = ""
                if "descriptions" in cve:
                    desc = cve["descriptions"][0].get("value", "")

                # Severity + Score
                severity = "UNKNOWN"
                score = 0.0
                metrics = cve.get("metrics", {})

                if "cvssMetricV31" in metrics:
                    block = metrics["cvssMetricV31"][0]
                    severity = block["cvssData"]["baseSeverity"]
                    score = block["cvssData"]["baseScore"]

                matches.append({
                    "id": cve_id,
                    "description": desc,
                    "severity": severity,
                    "score": score
                })

    return matches
