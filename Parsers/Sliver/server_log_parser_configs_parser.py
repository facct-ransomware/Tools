import re
import csv
import argparse
from datetime import datetime, timezone

pattern = r'{"level":"warning","msg":"{\\\"(Beacon|Session)\\\":{.*?}}","time":"(.*?)"}'

def safe_search(pattern, string, default=""):
    match = re.search(pattern, string)
    return match.group(1) if match else default

def format_backslashes(value):
    return value.replace('\\\\\\\\', '\\')

def parse_log_file(file_path):
    unique_entries = {}

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        log_data = file.read()
    
    matches = re.finditer(pattern, log_data)
    
    for match in matches:
        full_string = match.group(0).replace('\\"', '"')

        record_type = match.group(1)
        record_id = safe_search(r'"ID":"(.*?)"', full_string)
        name = safe_search(r'"Name":"(.*?)"', full_string)
        hostname = safe_search(r'"Hostname":"(.*?)"', full_string)
        username = safe_search(r'"Username":"(.*?)"', full_string)
        os = safe_search(r'"OS":"(.*?)"', full_string)
        version = safe_search(r'"Version":"(.*?)"', full_string)
        transport = safe_search(r'"Transport":"(.*?)"', full_string)
        remote_address = safe_search(r'"RemoteAddress":"(.*?)"', full_string)
        filename = safe_search(r'"Filename":"(.*?)"', full_string)
        last_checkin = safe_search(r'"LastCheckin":(.*?)(,|})', full_string)
        active_c2 = safe_search(r'"ActiveC2":"(.*?)"', full_string)
        locale = safe_search(r'"Locale":"(.*?)"', full_string)
        first_contact = safe_search(r'"FirstContact":(.*?)(,|})', full_string)

        def convert_timestamp(ts):
            if ts.isdigit():
                dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
                return dt.strftime('%d.%m.%Y %H:%M:%S')
            return ""

        last_checkin_converted = convert_timestamp(last_checkin)
        first_contact_converted = convert_timestamp(first_contact)

        entry = {
            "Type": record_type,
            "ID": record_id,
            "Name": name,
            "Hostname": hostname,
            "Username": format_backslashes(username),
            "OS": os,
            "Version": version,
            "Transport": transport,
            "RemoteAddress": remote_address,
            "Filename": format_backslashes(filename),
            "LastCheckin": last_checkin_converted,
            "ActiveC2": active_c2,
            "Locale": locale,
            "FirstContact": first_contact_converted
        }

        if record_id in unique_entries:
            existing_last_checkin = unique_entries[record_id]["LastCheckin"]
            if last_checkin_converted > existing_last_checkin:
                unique_entries[record_id] = entry
        else:
            unique_entries[record_id] = entry
    
    return list(unique_entries.values())

def save_to_csv(output_file, parsed_data):
    headers = ["Type", "ID", "Name", "Hostname", "Username", "OS", "Version", "Transport", "RemoteAddress", "Filename", "LastCheckin", "ActiveC2", "Locale", "FirstContact"]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(parsed_data)

def main():
    parser = argparse.ArgumentParser(description="Parse log file and extract data into CSV")
    parser.add_argument("input_file", help="Path to the input log file")
    parser.add_argument("output_file", help="Path to the output CSV file")
    
    args = parser.parse_args()
    
    parsed_data = parse_log_file(args.input_file)
    
    save_to_csv(args.output_file, parsed_data)
    
    print(f"Parsed data has been saved to {args.output_file}")

if __name__ == "__main__":
    main()