import argparse
import subprocess
import re
import csv
import os
from datetime import datetime, timezone

def deserialize_java_object(filepath):
    try:
        java_class_file = 'DeserializerWithCommonsIO.class'
        if not os.path.isfile(java_class_file):
            raise FileNotFoundError(f"Java class file '{java_class_file}' not found.")

        result = subprocess.run(
            ["java", "-cp", ".", "DeserializerWithCommonsIO", filepath],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            raise Exception(result.stderr)

        output = result.stdout
        print("Raw Java output:\n", output)

        pattern = re.compile(r',?(.*?)\{(password)=(.*?), (added)=(.*?), (host)=(.*?), (realm)=(.*?), (source)=(.*?), (user)=(.*?)\}')
        matches = pattern.findall(output)

        if matches:
            parsed_data = []
            for match in matches:
                try:
                    unix_timestamp = int(match[4]) / 1000
                    utc_datetime = datetime.fromtimestamp(unix_timestamp, tz=timezone.utc).strftime('%d.%m.%Y %H:%M:%S')
                except (ValueError, OSError) as e:
                    utc_datetime = 'Invalid timestamp'

                parsed_data.append({
                    "password": match[2],
                    "added": utc_datetime,
                    "host": match[6],
                    "realm": match[8],
                    "source": match[10],
                    "user": match[12]
                })

            csv_filename = 'deserialized_output.csv'
            with open(csv_filename, mode='w', newline='') as csv_file:
                fieldnames = ["password", "added", "host", "realm", "source", "user"]
                writer = csv.DictWriter(csv_file, fieldnames=fieldnames)

                writer.writeheader()
                writer.writerows(parsed_data)
            
            print(f"Parsed data saved to {csv_filename}")
        else:
            print("No match found in the deserialized output.")
        
    except FileNotFoundError as fnf_error:
        print(fnf_error)
    except Exception as e:
        print("Error during deserialization:", e)

def main():
    parser = argparse.ArgumentParser(description="Deserialize Java serialized binary file and save output as CSV")
    parser.add_argument("filepath", type=str, help="Path to the Java serialized binary file")
    
    args = parser.parse_args()
    filepath = args.filepath
    
    if not os.path.isfile(filepath):
        print(f"Error: The file '{filepath}' does not exist.")
        return
    
    deserialize_java_object(filepath)

if __name__ == "__main__":
    main()