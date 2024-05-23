import re
import argparse
from collections import defaultdict
import os

pattern = r'Recv stream msg: Data:"(.*?)".*?SessionID:"(.*?)"'

def parse_log_file(file_path):
    data_by_session = defaultdict(list)
    
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        log_data = file.read()
    
    matches = re.findall(pattern, log_data)
    
    for data, session_id in matches:
        data_by_session[session_id].append(data)
    
    for session_id, data_list in data_by_session.items():
        combined_data = ''.join(data_list)
        actual_data = (combined_data
        				.replace(r'\r\n', '\r\n')
        				.replace(r'\t', '\t')
        				.replace(r'\r', '\r')
        				.replace(r'\n', '\n'))
        data_by_session[session_id] = actual_data
    
    return data_by_session

def save_parsed_data(output_dir, grouped_data):
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
        
    for session_id, data in grouped_data.items():
        output_file_path = os.path.join(output_dir, f"{session_id}.txt")
        with open(output_file_path, 'w', encoding='utf-8') as file:
            file.write(f"SessionID: {session_id}\nData:\n")
            for line in data.splitlines():
                if line.strip():
                    file.write(line + '\n')

def main():
    parser = argparse.ArgumentParser(description="Parse log file and group data by SessionID")
    parser.add_argument("input_file", help="Path to the input log file")
    parser.add_argument("output_dir", help="Path to the output directory")
    
    args = parser.parse_args()
    
    grouped_data = parse_log_file(args.input_file)
    
    save_parsed_data(args.output_dir, grouped_data)
    
    print(f"Parsed data has been saved to the directory {args.output_dir}")

if __name__ == "__main__":
    main()
