import re

# Regular expression pattern to match the MAC address and the manufacturer
pattern = r"^([0-9A-Fa-f]{2}[:-]){2}([0-9A-Fa-f]{2})\s+\(hex\)\s+Dell Inc\.$"

# Function to filter and extract the matching lines
def filter_dell_entries(file_path):
    dell_entries = []
    with open(file_path, 'r', encoding='utf-8') as file:
        for line in file:
            line = line.strip()  # Remove leading/trailing whitespace
            match = re.match(pattern, line)
            if match:
                mac_address = match.group(0)[:8]  # Extract the MAC address part
                manufacturer = "Dell Inc."
                formatted_entry = f'{{ "{mac_address}", "{manufacturer}" }},'
                dell_entries.append(formatted_entry)
    return dell_entries

file_path = 'ieee-oui-database.txt'  # Adjust this path according to your file location

# Call the function to get the filtered Dell entries
dell_entries = filter_dell_entries(file_path)

# Print the filtered Dell entries
for entry in dell_entries:
    print(entry)
