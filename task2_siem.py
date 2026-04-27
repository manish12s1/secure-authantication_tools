import re
import sys
import json
from datetime import datetime


def extract_failed_ip(line):

    # This function checks whether a log line contains a failed password attempt.
    # If yes, it extracts the IP address and returns it. If not, it returns None.

    pattern = r"Failed password.*from ((?:\d{1,3}\.){3}\d{1,3})"
    match = re.search(pattern, line)

    if match:
        return match.group(1)

    return None


def read_log_file(filename="auth.log"):
    # This function opens the log file and reads it line by line.
    # It returns all lines in a list.

    try:
        with open(filename, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        print("Error: Log file not found.")
        return []
    except Exception as e:
        print("Error while reading file:", e)
        return []


def display_log_details(lines):
    # This function prints all lines from the log file with line numbers
    # So the user can see the full content of the log file

    print("\n========== Full Log File Details ==========")
    print(f"Total lines found: {len(lines)}")
    print("=" * 44)

    for index, line in enumerate(lines, start=1):
        print(f"[Line {index:>4}] {line}", end="")

    print("\n" + "=" * 44)


def count_failed_attempts(lines):

    # This function goes through all lines in the log file.
    # It returns a dictionary with IPs as a key and contains the count of failure attempts as value.

    ip_counts = {}

    for line in lines:
        ip = extract_failed_ip(line)
        if ip:
            if ip in ip_counts:
                ip_counts[ip] += 1
            else:
                ip_counts[ip] = 1

    return ip_counts


def find_suspicious_ips(ip_counts, threshold):

    # This function filters the IP addresses and keeps only the ones
    # whose failed attempt count is greater than or equal to the threshold.

    suspicious = {}

    for ip, count in ip_counts.items():
        if count >= threshold:
            suspicious[ip] = count

    return suspicious


def generate_alerts(suspicious_ips, threshold):
    # This function generates alert messages for each suspicious IP
    # that has exceeded the failed attempt threshold

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n SECURITY ALERTS")
    print(f"Alert Generated At : {timestamp}")
    print("-" * 38)

    if not suspicious_ips:
        print("No alerts. No suspicious IPs detected.")
        print("=" * 38)
        return

    for ip, count in suspicious_ips.items():
        print(f"[ALERT] BRUTE FORCE DETECTED!")
        print(f"        Time           : {timestamp}")
        print(f"        IP Address     : {ip}")
        print(f"        Failed Attempts: {count}")
        print(f"        Threshold Set  : {threshold}")
        print(f"        Action         : Block this IP immediately!")
        print("-" * 38)

    print("=" * 38)


def save_to_json(suspicious_ips, threshold, output_file):

    # This function saves suspicious IPs into a JSON file.
    # The format is clean and easy to read.

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    data = {
        "timestamp": timestamp,
        "threshold": threshold,
        "malicious_ips": []
    }

    for ip, count in suspicious_ips.items():
        data["malicious_ips"].append({
            "ip": ip,
            "failed_attempts": count
        })

    try:
        with open(output_file, "w") as file:
            json.dump(data, file, indent=4)
        print("Results saved to", output_file)
    except Exception as e:
        print("Error while saving JSON file:", e)


def main():
    if len(sys.argv) != 3:
        print("Usage: python3 task2_siem.py <logfile> <threshold>")
        return

    logfile = sys.argv[1]

    try:
        threshold = int(sys.argv[2])
    except ValueError:
        print("Error: Threshold must be a number.")
        return

    lines = read_log_file(logfile)

    if not lines:
        print("No log data available.")
        return

    display_log_details(lines)

    ip_counts = count_failed_attempts(lines)
    suspicious_ips = find_suspicious_ips(ip_counts, threshold)

    if suspicious_ips:
        print("\nSuspicious IPs found:")
        for ip, count in suspicious_ips.items():
            print(ip, "->", count, "failed attempts")
    else:
        print("\nNo suspicious IPs found.")

    generate_alerts(suspicious_ips, threshold)

    save_to_json(suspicious_ips, threshold, "malicious_ips.json")


if __name__ == "__main__":
    main()