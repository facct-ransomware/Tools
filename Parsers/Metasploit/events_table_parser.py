import csv
import base64
import argparse
import re
from datetime import datetime, timezone

def clean_text(text):
    return re.sub(r'[\x00-\x1F\x7F]', '', text)

def convert_timestamp(ts):
    try:
        dt = datetime.strptime(ts, '%Y-%m-%d %H:%M:%S.%f')
        return dt.strftime('%d.%m.%Y %H:%M:%S')
    except ValueError:
        return ""

def extract_important_data(decoded_value):
    data = {}

    patterns = {
        'module_name': r'(module_name)(?:.{1,2})(.*?):',
        'module_uuid': r'(module_uuid).(.*?)(?:"|:)',
        'exception': r'(exception)(?:.{2})(.*?)\.$',
        'command': r'(command)"(.*?)$',
        'arg': r'(command|output|local_path)..:?[^a-zA-Z]?(.*?);T',
        'arg2': r'(remote_pathI)\"[^a-zA-Z]?(.*?);T',
        'rhost': r'\"\"(RHOSTSI)\"(.*?)(:|;)',
        'srvhost': r'(SRVHOST).(?:T@.\")?(.*?)(@|\"|I)',
        'payload': r'\"(payloadI)\".(.*?);',
        'session_info': r'(?:session_info)\"[^a-zA-Z]?(?!session_uuid)(.*?):',
        'session_uuid': r'(session_uuid)\"(.*?):',
        'session_type': r'(session_type)\"(.*?):',
        'username': r'(username)\"(.*?):',
        'target_host': r'(target_hostI)\"(.*?):',
        'via_exploit': r'(via_exploit)\"[^a-zA-Z]?(.*?):',
        'via_payload': r'(via_payload)\"[^a-zA-Z]?(.*?):'
    }

    for key, pattern in patterns.items():
        matches = re.findall(pattern, decoded_value)
        if matches:
            data[key] = ', '.join([match[1] for match in matches])

    data['combined_payload'] = ', '.join(filter(None, [data.get('via_payload', ''), data.get('payload', '')]))
    data['combined_command'] = ', '.join(filter(None, [data.get('command', ''), data.get('arg', ''), data.get('exception', ''), data.get('module_name', '')]))

    return data

def main(input_file, output_file):
    with open(input_file, mode='r', newline='', encoding='utf-8') as infile, \
         open(output_file, mode='w', newline='', encoding='utf-8') as outfile:

        reader = csv.reader(infile)
        writer = csv.writer(outfile)

        header = next(reader)
        header_indices_to_keep = [
            header.index('created_at'),
            header.index('name'),
            header.index('host_id'),
            header.index('username'),
            header.index('info1')
        ]
        new_header = ['created_at', 'method', 'command', 'args'] + [
            'session_uuid', 'session_type', 'target_host', 'host_id', 'username', 'srvhost', 'srvhost', 'combined_payload', 'via_exploit'
        ]
        writer.writerow(new_header)

        for row in reader:
            try:
                new_row = [row[index] for index in header_indices_to_keep[:-1]]
                new_row[0] = convert_timestamp(new_row[0])
                decoded_value = base64.b64decode(row[header_indices_to_keep[-1]]).decode('utf-8', errors='ignore')
                cleaned_value = clean_text(decoded_value)
                important_data = extract_important_data(cleaned_value)
                new_row.insert(2, important_data.get('combined_command', ''))
                new_row.insert(3, important_data.get('arg2', ''))
                new_row.insert(4, important_data.get('session_uuid', ''))
                new_row.insert(5, important_data.get('session_type', ''))
                new_row.insert(6, important_data.get('target_host', ''))
                new_row += [
                    important_data.get('rhost', ''),
                    important_data.get('srvhost', ''),
                    important_data.get('combined_payload', ''),
                    important_data.get('session_info', ''),
                    important_data.get('via_exploit', '')
                ]
            except Exception as e:
                new_row += [''] * 8
            writer.writerow(new_row)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Decode Base64 strings in a CSV file, clean control characters, and extract important data.')
    parser.add_argument('input_file', type=str, help='Path to the input CSV file')
    parser.add_argument('output_file', type=str, help='Path to the output CSV file')

    args = parser.parse_args()

    main(args.input_file, args.output_file)