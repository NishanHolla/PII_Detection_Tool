import os
import json
import requests

# Define the folder containing the JSON files and the endpoint URL
folder_path = './test_files'  # Change this to your folder path
scan_endpoint = 'http://localhost:8000/scan'  # Replace with your actual endpoint

# Function to read JSON files and send them to the scan endpoint
def send_json_files():
    # List all files in the folder
    files = os.listdir(folder_path)
    
    # Filter out only JSON files
    json_files = [file for file in files if file.endswith('.json')]
    
    # Limit to the first 10 JSON files
    json_files = json_files[:10]
    
    if not json_files:
        print("No JSON files found in the folder.")
        return
    
    # Iterate through each JSON file
    for file in json_files:
        file_path = os.path.join(folder_path, file)
        
        try:
            # Read the content of the JSON file
            with open(file_path, 'r') as f:
                content = json.load(f)  # Get the content as a dictionary

            # Prepare the payload for the scan endpoint
            payload = {
                "file_name": file,
                "content": json.dumps(content)  # Ensure content is sent as a string
            }
            
            # Send the JSON data to the scan endpoint
            response = requests.post(scan_endpoint, json=payload)
            
            # Check if the request was successful
            if response.status_code == 200:
                print(f"Successfully sent {file} to the scan endpoint.")
            else:
                print(f"Failed to send {file}. Status code: {response.status_code}")
        except Exception as e:
            print(f"Error processing file {file}: {str(e)}")

# Call the function to start sending files
if __name__ == '__main__':
    send_json_files()
