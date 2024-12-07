# PRACTICA-VISUALITZACIO - Codi per generar dades random
import pandas as pd
import numpy as np
import random
from datetime import datetime, timedelta
import os

# Ensure we are in the correct directory
print("Current working directory:", os.getcwd())

# Update these paths with the correct file locations
vuln_data_path = 'Vuln Data.csv'
os_data_path = 'OS.csv'

# Load the data
try:
    vuln_data = pd.read_csv(vuln_data_path)
    os_data = pd.read_csv(os_data_path)
    print("Files loaded successfully.")
except FileNotFoundError as e:
    print("Error loading files:", e)
    exit()

# Function to generate a random IPv4 address
def generate_random_ip():
    return ".".join(map(str, (random.randint(0, 255) for _ in range(4))))

# Function to generate random vulnerabilities dataset
def create_vulnerability_dataset(vuln_data, os_data, num_entries=200000):
    # Prepare data structures
    countries = ["Spain", "France", "Germany", "Italy", "UK", "USA", "Canada", "Japan", "Australia", "India"]
    networks = ["{}.Network.CompanyA".format(country) for country in countries]
    tracking_methods = ["IP Scan", "QUALYS Agent"]
    
    data = []
    
    # Generate unique IPs and corresponding attributes
    unique_ips = [generate_random_ip() for _ in range(num_entries // 80)]
    ip_vulnerability_counts = [random.randint(1, 80) for _ in unique_ips]
    
    # Create mapping of IP to network, DNS, and tracking method
    ip_metadata = {
        ip: {
            "Network": random.choice(networks),
            "Report": random.choice(countries),  # Extract country for the report column
            "DNS": "DNS.{}".format(random.randint(100000, 999999)),
            "Tracking Method": random.choice(tracking_methods),
            "OS": random.choice(os_data["OS"].tolist())
        } for ip in unique_ips
    }
    
    # Create vulnerabilities
    for ip, count in zip(unique_ips, ip_vulnerability_counts):
        for _ in range(count):
            # Select a random vulnerability
            vuln = vuln_data.sample(1).iloc[0]
            
            # Generate dates
            first_detected = datetime(2020, 1, 1) + timedelta(days=random.randint(0, 1460))
            last_detected = first_detected + timedelta(days=random.randint(0, (datetime(2024, 12, 31) - first_detected).days))
            
            # Create a row
            row = {
                "IP": ip,
                "Network": ip_metadata[ip]["Network"],
                "Report": ip_metadata[ip]["Report"],  # Add the report column
                "DNS": ip_metadata[ip]["DNS"],
                "NetBIOS": ip_metadata[ip]["DNS"].replace("DNS.", ""),
                "Tracking Method": ip_metadata[ip]["Tracking Method"],
                "OS": ip_metadata[ip]["OS"],
                "IP Status": "host scanned, found vuln",
                "QID": vuln["QID"],
                "Title": vuln["Title"],
                "Vuln Status": vuln["Vuln Status"],
                "Severity": vuln["Severity"],
                "Type": vuln["Type"],
                "First Detected": first_detected.strftime("%Y-%m-%d"),
                "Last Detected": last_detected.strftime("%Y-%m-%d"),
                "Times Detected": random.randint(1, 100),
                "CVE ID": vuln["CVE ID"],
                "CVSS": vuln["CVSS"],
                "Threat": vuln["Threat"],
                "PCI Vuln": vuln["PCI Vuln"]
            }
            data.append(row)
    
    # Convert to DataFrame
    return pd.DataFrame(data)

# Generate the dataset
print("Generating randomized dataset...")
randomized_dataset = create_vulnerability_dataset(vuln_data, os_data, num_entries=1050000)

# Save to CSV (to handle large files efficiently)
output_path = 'Sheet1.csv'
randomized_dataset.to_csv(output_path, index=False)

