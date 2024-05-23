import re
import csv
import argparse
import os
import base64
import gzip
import hashlib
import binascii
from datetime import datetime, timezone

# Define the provided regex pattern
pattern = re.compile(
    r'\{\"level\":\"info\",\"msg\":\"\{\\\"request\\\":\\\"\{(\\\\\\\"C2s\\\\\\\":\[\\\\\\\"(.*?)\\\\\\\"\])?(\\\\\\\"(Path)\\\\\\\":(?:\\\\\\\")?(.*?)(\\\\\\\",)?(\\\\\\\"(ATime)\\\\\\\":(.*?),\\\\\\\"(MTime)\\\\\\\":(.*?))?(\\\\\\\"(Uid)\\\\\\\":(?:\\\\\\\")?(.*?)(\\\\\\\",)?\\\\\\\"(Gid)\\\\\\\":(?:\\\\\\\")?(.*?)(\\\\\\\",)?)?(\\\\\\\"(FileMode)\\\\\\\":(\\\\\\\")(.*?))?(\\\\\\\")?,)?(\\\\\\\"(BeaconInterval)\\\\\\\":(.*?),\\\\\\\"(BeaconJitter)\\\\\\\":(.*?),)?(\\\\\\\"Output\\\\\\\":(.*?),)?((\\\\\\\"Encoder\\\\\\\":(\\\\\\\")?(.*?)(\\\\\\\")?,)?(\\\\\\\"Architecture\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?(\\\\\\\"Iterations\\\\\\\":(.*?),)?\\\\\\\"Data\\\\\\\":\\\\\\\"(.*?)\\\\\\\",?)?((\\\\\\\"EnablePTY\\\\\\\":(.*?),)?\\\\\\\"TunnelID\\\\\\\":(.*?),)?(\\\\\\\"Pid\\\\\\\":(.*?),)?(\\\\\\\"Config\\\\\\\":\{(.*?)(\\\\\\\"URL\\\\\\\":\\\\\\\"(.*?)\\\\\\(.*?)?)?},)?(\\\\\\\"BindAddress\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"forwardAddress\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?(\\\\\\\"TCP\\\\\\\":(.*?),\\\\\\\"IP4\\\\\\\":(.*?),(\\\\\\\"Listening\\\\\\\":(.*?),)?)?(\\\\\\\"ID\\\\\\\":(.*?),)?(\\\\\\\"Src\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Dst\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?(\\\\\\\"Username\\\\\\\":\\\\\\\"(.*?)(?:\\\\\\\")?,)?(\\\\\\\"Hostname\\\\\\\":\\\\\\\"(.*?)\",)?(\\\\\\\"Name\\\\\\\":\\\\\\\"(.*?)\\\\\\\",(\\\\\\\"(Data|Args)\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?(\\\\\\\"OS\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?(\\\\\\\"Export\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?)?(\\\\\\\"Payload\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"LHost\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"LPort\\\\\\\":(.*?),\\\\\\\"Iterations\\\\\\\":(.*?),)?(?:\\\\\\\"(HostingProcess|Pid)\\\\\\\":(\\\\\\\")?(.*?)(\\\\\\\")?,\\\\\\\"Config\\\\\\\":\{\\\\\\\"GOOS\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"GOARCH\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Name\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Debug\\\\\\\":(.*?),\\\\\\\"ReconnectInterval\\\\\\\":(.*?),\\\\\\\"MaxConnectionErrors\\\\\\\":(.*?),\\\\\\\"C2\\\\\\\":\[\{\\\\\\\"URL\\\\\\\":\\\\\\\"(.*?)\\\\\\\"\}\],\\\\\\\"Format\\\\\\\":(.*?),\\\\\\\"IsSharedLib\\\\\\\":(.*?)\})?(\\\\\\\"Args\\\\\\\":\[\\\\\\\"(.*?)(?:\\)?\"\](,\\\\\\\"Output\\\\\\\":(.*?))?)?(\\\\\\\"Assembly\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Arguments\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Process\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Arch\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"ProcessArgs\\\\\\\":\[\\\\\\\"(.*?)\\\\\\\"\],)?,?(\\\\\\\"Request\\\\\\\":\{(\\\\\\\"Async\\\\\\\":(.*?),)?\\\\\\\"Timeout\\\\\\\":(.*?),\\\\\\\"(SessionID|BeaconID)\\\\\\\":\\\\\\\"(.*?)\\\"\})?\}\\\",\\\"method\\\":\\\"\/rpcpb\.SliverRPC\/(((?!GetJobs|GetBeacons|GetSessions|GetVersion|CloseSocks|GenerateUniqueIP|GenerateWGClientConfig|GetCompiler|GetOperators|Hosts|ImplantBuilds|Websites).)*?)(\\\",\\\"(session|beacon)\\\":\\\"\{\\\\\\\"ID\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Name\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Hostname\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"UUID\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Username\\\\\\\":(\\\\\\\")?(.*?)\\\\\\\",\\\\\\\"UID\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"GID\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"OS\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Arch\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"Transport\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"RemoteAddress\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"PID\\\\\\\":(.*?),\\\\\\\"Filename\\\\\\\":\\\\\\\"(.*?)\\\\\\\",\\\\\\\"LastCheckin\\\\\\\":(.*?),\\\\\\\"ActiveC2\\\\\\\":\\\\\\\"(.*?)\\\\\\\",(\\\\\\\"Version\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?(\\\\\\\"IsDead\\\\\\\":(.*?),)?\\\\\\\"ReconnectInterval\\\\\\\":(.*?),(\\\\\\\"Interval\\\\\\\":(.*?),\\\\\\\"Jitter\\\\\\\":(.*?),\\\\\\\"NextCheckin\\\\\\\":(.*?),)?(\\\\\\\"PeerID\\\\\\\":(.*?),)?(\\\\\\\"Locale\\\\\\\":\\\\\\\"(.*?)\\\\\\\",)?\\\\\\\"FirstContact\\\\\\\":(.*?)\}\\\"\})?(:?\\\"})?\",\"time\":\"(.*?)\"\}'
)


def sanitize_filename(filename):
    # Remove any path components and sanitize the filename
    return os.path.basename(filename).replace(":", "_").replace("/", "_").replace("\\", "_").replace(" ", "_")

def format_backslashes(value):
    if value is None:
        return value
    value = value.replace('\\\\\\\\', '\\')
    return value.replace('\\\\', '\\')

def format_args(input_string):
    formatted_string = re.sub(r'(\\\\\",)', ' ', input_string)
    formatted_string = re.sub(r'(^\")|(\\\\\"$)|(\\\\\")|(\\$)', '', formatted_string)
    return formatted_string

def decode_unicode_escapes(input_string):
    def replace_unicode(match):
        return bytes(match.group(0), "utf-8").decode("unicode_escape")
    
    return re.sub(r'\\u[0-9A-Fa-f]{4}', replace_unicode, input_string)

def convert_to_utc(input_time):
    local_time = datetime.fromisoformat(input_time)
    utc_time = local_time.astimezone(timezone.utc)
    formatted_time = utc_time.strftime('%d.%m.%Y %H:%M:%S')
    return formatted_time

def convert_unix_timestamp(ts):
    if ts is None:
        return ts
    else: 
        ts.isdigit()
        dt = datetime.fromtimestamp(int(ts), tz=timezone.utc)
        return dt.strftime('%d.%m.%Y %H:%M:%S')
    
def nanoseconds_to_seconds(nanoseconds):
    seconds = int(nanoseconds) / 1000000000
    return int(seconds)

def generate_sequential_filename(base_filename, count, ext=""):
    return f"{base_filename}_{count:02d}{ext}"

def calculate_sha1(file_path):
    sha1 = hashlib.sha1()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha1.update(chunk)
    return sha1.hexdigest()

def parse_log_file(file_path, output_dir):
    # List to store parsed data
    parsed_data = []

    # Create the binaries directory inside the output directory
    binaries_dir = os.path.join(output_dir, 'binaries')
    os.makedirs(binaries_dir, exist_ok=True)

    # Counter to track sequential filenames
    file_counter = 1

    # List to store SHA-1 hashes
    sha1_list = []

    # Read the log file with UTF-8 encoding, ignoring errors
    with open(file_path, 'r', encoding='utf-8', errors='ignore') as file:
        log_data = file.read()
    
    # Find all matches in the log data
    matches = re.finditer(pattern, log_data)
    
    # Process each match
    for match in matches:
        groups = match.groups()
        
        binary_filename = None
        
        # Decode the base64 content from data group
        if groups[39]:
            base_filename = sanitize_filename(groups[4] if groups[4] else "unnamed")
            base64_content = groups[39]
            binary_content = base64.b64decode(base64_content)
            binary_filename = ""

            # Check if the content is gzip
            if groups[33] == 'gzip':
                decompressed_content = gzip.decompress(binary_content)
                binary_filename = generate_sequential_filename(base_filename, file_counter)
                binary_path = os.path.join(binaries_dir, binary_filename)
                with open(binary_path, 'wb') as decompressed_file:
                    decompressed_file.write(decompressed_content)
            else:
                binary_filename = generate_sequential_filename(base_filename, file_counter)
                binary_path = os.path.join(binaries_dir, binary_filename)
                with open(binary_path, 'wb') as binary_file:
                    binary_file.write(binary_content)

            file_counter += 1  # Increment the file counter for each processed file
            
            # Calculate SHA-1 for binary file
            sha1_hash = calculate_sha1(binary_path)
            sha1_list.append(f"{binary_filename},{sha1_hash}")
        
        # Handle group for extensions
        if groups[69] and groups[72]:
            base_filename = sanitize_filename(groups[69])
            binary_content = base64.b64decode(groups[72])
            binary_filename = generate_sequential_filename(base_filename, file_counter)
            binary_path = os.path.join(binaries_dir, binary_filename)
            with open(binary_path, 'wb') as binary_file:
                binary_file.write(binary_content)

            file_counter += 1  # Increment the file counter for each processed file

            # Calculate SHA-1 for binary file
            sha1_hash = calculate_sha1(binary_path)
            sha1_list.append(f"{binary_filename},{sha1_hash}")

        # Handle groups for assembly
        if groups[100]:
            base_filename = sanitize_filename(groups[4] if groups[4] else "unnamed")
            base64_content = groups[100]
            try:
                binary_content = base64.b64decode(base64_content)
            except binascii.Error:
                print(
                    f"Error with base64 decoding, possibly due to zero bytes in string. "
                    f"Try to extract it manually. String with timestamp: \"{groups[146]}\""
                )
                binary_content = None

            if binary_content is not None:
                binary_filename = generate_sequential_filename(base_filename, file_counter)
                binary_path = os.path.join(binaries_dir, binary_filename)
                with open(binary_path, 'wb') as binary_file:
                    binary_file.write(binary_content)
            else:
                print(f"Skipping file due to decoding error")


            file_counter += 1  # Increment the file counter for each processed file

            # Calculate SHA-1 for binary file
            sha1_hash = calculate_sha1(binary_path)
            sha1_list.append(f"{binary_filename},{sha1_hash}")

        chtimes = None
        if groups[8] and groups[10] is not None:
            atime = convert_unix_timestamp(groups[8])
            mtime = convert_unix_timestamp(groups[10])
            chtimes = f"{groups[7]}:{atime}, {groups[9]}:{mtime}"
        
        chown = None
        if groups[13] and groups[16] is not None:
            chown = f"{groups[12]}:{groups[13]}, {groups[15]}:{groups[16]}"


        reconfigure = None
        if groups[25] and groups[27] is not None:
            interval = nanoseconds_to_seconds(groups[25])
            jitter = nanoseconds_to_seconds(groups[27])
            reconfigure = f"{groups[24]}:{interval}s, {groups[26]}:{jitter}s"

        msf = None
        if groups[79] and groups[80] is not None:
            msf = f"LHost:{groups[79]}, LPort:{groups[80]}"

        pid = None
        if groups[45] is not None:
            pid = f"Pid:{groups[45]}"

        bind_adress = None
        forward_adress = None
        if groups[52] and groups[53] is not None:
            bind_adress = f"BindAdress:{groups[52]}"
            forward_adress = f"ForwardAdress:{groups[53]}"

        parsed_data.append({
            "Time": convert_to_utc(groups[146]),
            "Method": groups[111],
            "Path/Command": decode_unicode_escapes(format_backslashes(" ".join(sorted(set(filter(None, [groups[4], bind_adress, groups[69], groups[78]])))))),
            "Args": decode_unicode_escapes(format_args(format_backslashes(" ".join(sorted(set(filter(None, [forward_adress, groups[96], chown, chtimes, reconfigure, msf, groups[21], groups[1], pid, groups[76]]))))))),
            "Hostname": groups[117],
            "PossibleVictimIP": groups[126],
            "C2s": " ".join(sorted(set(filter(None, [groups[1], groups[130]])))),
            "Type": groups[114],
            "ImplantID": groups[115],
            "SliverName": groups[116],
            "ImplantFileName": format_backslashes(groups[128]),
            "RelativeBinaryPath": os.path.join('binaries', binary_filename) if binary_filename else None
        })
    
    # Save SHA-1 hashes to file
    sha1_file_path = os.path.join(binaries_dir, "!files_sha1.csv")
    with open(sha1_file_path, 'w', encoding='utf-8') as sha1_file:
        for line in sha1_list:
            sha1_file.write(line + "\n")
    
    return parsed_data

def save_to_csv(output_file, parsed_data):
    # Define the CSV headers
    headers = [
        "Time", "Method", "Path/Command", "Args", "Hostname", "PossibleVictimIP", "C2s", "Type", "ImplantID", "SliverName", "ImplantFileName", "RelativeBinaryPath"
    ]
    
    with open(output_file, 'w', newline='', encoding='utf-8') as file:
        writer = csv.DictWriter(file, fieldnames=headers)
        writer.writeheader()
        writer.writerows(parsed_data)

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(description="Parse log file and extract data into CSV")
    parser.add_argument("input_file", help="Path to the input log file")
    parser.add_argument("output_dir", help="Path to the output directory")
    
    args = parser.parse_args()
    
    # Parse the log file
    parsed_data = parse_log_file(args.input_file, args.output_dir)
    
    # Save the parsed data to a CSV file
    output_csv_file = os.path.join(args.output_dir, 'parsed_data.csv')
    save_to_csv(output_csv_file, parsed_data)
    
    print(f"Parsed data has been saved to {output_csv_file}")
    print(f"Binary files have been saved to {args.output_dir}\\binaries")
    print(f"SHA-1 hashes have been saved to {args.output_dir}\\binaries\\!files_sha1.csv")

if __name__ == "__main__":
    main()