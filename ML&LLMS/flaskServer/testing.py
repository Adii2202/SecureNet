'''Sends requests to server defined in testing_requests.json'''

# import requests
# import json

# with open('testing_req.json', 'r') as f:
#     reqs = json.load(f)

# for req in reqs:
#     requests.request(**req)




import json
from classifier import ThreatClassifier  # Adjust import if necessary

def test_classifier(json_file_path):
    # Initialize the ThreatClassifier
    classifier = ThreatClassifier()
    
    # Load testing data from the JSON file
    with open(json_file_path, 'r') as file:
        logs = json.load(file)

    # Process and classify logs
    classified_logs = classifier.process_logs(json_file_path)
    
    # Print or save the classified results
    for log_entry in classified_logs:
        print(json.dumps(log_entry, indent=4))

# Run the test with your testing data
if __name__ == "__main__":
    test_classifier('testing_req.json')
