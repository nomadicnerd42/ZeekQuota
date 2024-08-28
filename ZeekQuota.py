import os
import csv
import datetime
import ipaddress
import json
import gzip
import shutil
import sys
import subprocess
from concurrent.futures import ThreadPoolExecutor # Used to concurrently extract Zeek archive files.

# Function to install required packages
def install(package):
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Check and install dependencies
try:
    from tqdm import tqdm
except ImportError:
    install("tqdm")
    from tqdm import tqdm

# Configuration
base_directory = os.getcwd()  # Start from the current directory
csv_file = os.path.join(base_directory, "data_usage.csv")
internal_networks = [
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
]

# Log types to parse
log_prefixes = ["conn", "dns", "http", "ssl"]

# Function to determine if IP is internal
def is_internal(ip):
    try:
        ip_obj = ipaddress.ip_address(ip)
        is_internal_ip = any(ip_obj in network for network in internal_networks)
        return is_internal_ip
    except ValueError:
        print(f"Invalid IP address format: {ip}")
        return False

# Function to reset data usage CSV at the beginning of the month
def reset_monthly_usage():
    if os.path.exists(csv_file):
        last_modified = datetime.datetime.fromtimestamp(os.path.getmtime(csv_file))
        current_month = datetime.datetime.now().month
        if last_modified.month != current_month:
            print(f"Resetting monthly usage file: {csv_file}")
            os.remove(csv_file)
    else:
        print(f"No existing CSV file found. Proceeding without reset.")

# Function to load current usage from the CSV file
def load_usage():
    usage = {}
    if os.path.exists(csv_file):
        print(f"Loading usage data from {csv_file}")
        with open(csv_file, mode="r") as file:
            reader = csv.reader(file)
            for row in reader:
                ip, total_data, last_time = row
                usage[ip] = [float(total_data), last_time]
    else:
        print(f"CSV file {csv_file} not found. Starting with empty usage data.")
    return usage

# Function to save usage to the CSV file
def save_usage(usage):
    if not usage:
        print("No data to save.")
    else:
        print(f"Saving {len(usage)} entries to {csv_file}")
    
    with open(csv_file, mode="w", newline="") as file:
        writer = csv.writer(file)
        for ip, data in usage.items():
            # Convert data amount to gigabytes
            gb_data = data[0] / (1024 ** 3)
            writer.writerow([ip, gb_data, data[1]])

# Function to update or add IP data in usage dictionary
def update_usage(usage, ip, data_amount, timestamp):
    if ip in usage:
        usage[ip][0] += data_amount  # Accumulate data
        usage[ip][1] = timestamp  # Update last data transfer time
        print(f"Updated existing IP {ip}: {usage[ip]}")
    else:
        usage[ip] = [data_amount, timestamp]
        print(f"Added new IP {ip}: {usage[ip]}")

# Function to parse Zeek logs
def parse_zeek_log(file_path, usage):
    print(f"Parsing log file: {file_path}")
    with open(file_path, "r") as log_file:
        for line in log_file:
            try:
                # Attempt to parse as JSON
                record = json.loads(line)
                orig_ip = record.get("id.orig_h")
                resp_ip = record.get("id.resp_h")

                # Validate and process only valid IP addresses
                if is_valid_ip(orig_ip) and is_valid_ip(resp_ip):
                    if is_internal(orig_ip) and not is_internal(resp_ip):
                        data_amount = record.get("orig_bytes", 0) + record.get("resp_bytes", 0)
                        update_usage(usage, orig_ip, data_amount, record.get("ts", ""))
                    elif is_internal(resp_ip) and not is_internal(orig_ip):
                        data_amount = record.get("orig_bytes", 0) + record.get("resp_bytes", 0)
                        update_usage(usage, resp_ip, data_amount, record.get("ts", ""))

            except json.JSONDecodeError:
                print(f"Skipping line due to JSON decode error: {line.strip()}")
                continue

# Function to validate if a string is a valid IP address
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        print(f"Invalid IP address format: {ip}")
        return False

# Function to extract gzip files in a separate thread
def extract_gzip(file_path):
    base_name = os.path.splitext(file_path)[0]  # Remove the .gz extension
    if base_name.endswith(".log"):
        log_file_path = base_name  # If it already ends with .log, keep it
    else:
        log_file_path = base_name + ".log"  # Otherwise, add .log
    
    print(f"Extracting {file_path} to {log_file_path}")
    with gzip.open(file_path, "rb") as f_in:
        with open(log_file_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)
    
    return log_file_path  # Return the path of the extracted log file

# Function to handle gzip files using a thread pool
def extract_gzip_files_in_parallel(gzip_files):
    extracted_files = []

    if gzip_files:
        print(f"Found {len(gzip_files)} gzip files to extract.")
        with ThreadPoolExecutor() as executor:
            future_to_file = {executor.submit(extract_gzip, file): file for file in gzip_files}
            for future in tqdm(future_to_file, desc="Extracting .gz files"):
                try:
                    extracted_files.append(future.result())
                except Exception as e:
                    print(f"Failed to extract {future_to_file[future]}: {e}")
    else:
        print("No gzip files found for extraction.")

    return extracted_files

# Function to find all log files within a directory and its subdirectories
def find_log_files(base_dir, max_depth=5):
    log_files = []
    gzip_files = []

    print(f"Searching for log files in {base_dir} (max depth: {max_depth})")
    for root, dirs, files in os.walk(base_dir):
        # Calculate the depth of the current directory
        depth = root[len(base_dir):].count(os.sep)

        if depth > max_depth:
            continue  # Skip directories deeper than max_depth

        for file in files:
            # Only include files that start with conn, dns, http, ssl and end with .log
            if any(file.startswith(prefix) and file.endswith(".log") for prefix in log_prefixes):
                log_files.append(os.path.join(root, file))
            elif any(file.startswith(prefix) and file.endswith(".log.gz") for prefix in log_prefixes):
                gzip_files.append(os.path.join(root, file))

    print(f"Found {len(log_files)} log files and {len(gzip_files)} gzip files.")
    return log_files, gzip_files

# Function to parse Zeek logs
def parse_logs(usage):
    log_files, gzip_files = find_log_files(base_directory)

    # Extract gzip files before parsing
    extracted_files = extract_gzip_files_in_parallel(gzip_files)
    log_files.extend(extracted_files)  # Add extracted files to log files list

    for file_path in tqdm(log_files, desc="Parsing log files"):
        parse_zeek_log(file_path, usage)

# Main function to monitor the logs and update the usage
def monitor_zeek_logs():
    reset_monthly_usage()
    usage = load_usage()  # Load current usage from CSV
    parse_logs(usage)  # Parse logs and update usage dictionary
    save_usage(usage)  # Save updated usage to CSV

if __name__ == "__main__":
    print("Starting Zeek log monitoring script...")
    monitor_zeek_logs()
    print("Zeek log monitoring script completed.")
