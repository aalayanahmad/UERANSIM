import os

def update_yaml():
    # Directory containing the YAML files
    directory = '.'

    # Range of file numbers to process
    start = 1100
    end = 1149

    # Old and new line content
    old_line = '  - 127.0.0.1\n'
    new_line = '  - 10.5.0.103\n'

    # Iterate over the specified range of files
    for i in range(start, end + 1):
        filename = f"/Users/ahmad/Desktop/UERANSIM/config/ue{i}.yaml"
        filepath = os.path.join(directory, filename)
        
        if os.path.isfile(filepath):
            # Read the contents of the file
            with open(filepath, 'r') as file:
                lines = file.readlines()
            
            # Modify line 23 if it matches the old line content
            if lines[22] == old_line:
                lines[22] = new_line
                
                # Write the modified contents back to the file
                with open(filepath, 'w') as file:
                    file.writelines(lines)

            print(f"Processed {filename}")
        else:
            print(f"{filename} does not exist")

print(update_yaml())
