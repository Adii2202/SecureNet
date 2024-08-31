# '''Defines a class for threat classification.
# This class impelemnts some methods for cleaning of the inputs and uses trained classifiers for prediction.'''

# import joblib
# # from request import Request
# import urllib.parse
# import json

# class ThreatClassifier(object):
#     def __init__(self):
#         self.clf = joblib.load('../Classifier/predictor.joblib')
#         self.pt_clf = joblib.load('../Classifier/pt_predictor.joblib')
        
#     def __unquote(self, text):
#         k=0
#         uq_prev = text
#         while(k < 100):
#             uq = urllib.parse.unquote_plus(uq_prev)
#             if uq == uq_prev:
#                 break
#             else:
#                 uq_prev = uq
    
#         return uq_prev
    
#     def __remove_new_line(self, text):
#         text = text.strip()
#         return ' '.join(text.splitlines())
    
#     def __remove_multiple_whitespaces(self, text):
#         return ' '.join(text.split())
    
#     def __clean_pattern(self, pattern):
#         pattern = self.__unquote(pattern)
#         pattern = self.__remove_new_line(pattern)
#         pattern = pattern.lower()
#         pattern = self.__remove_multiple_whitespaces(pattern)

#         return pattern
    
#     def __is_valid(self, parameter):
#         return parameter != None and parameter != ''
    
#     def classify(self, req):
#         if not isinstance(req, Request):
#             raise TypeError("Object should be a Request!!!")
        
#         parameters = []
#         locations = []
        
#         if self.__is_valid(req.request):
#             parameters.append(self.__clean_pattern(req.request))
#             locations.append('Request')

#         if self.__is_valid(req.body):
#             parameters.append(self.__clean_pattern(req.body))
#             locations.append('Body')

#         if 'Cookie' in req.headers and self.__is_valid(req.headers['Cookie']):
#             parameters.append(self.__clean_pattern(req.headers['Cookie']))
#             locations.append('Cookie')

#         if 'User_Agent' in req.headers and self.__is_valid(req.headers['User_Agent']):
#             parameters.append(self.__clean_pattern(req.headers['User_Agent']))
#             locations.append('User Agent')

#         if 'Accept_Encoding' in req.headers and self.__is_valid(req.headers['Accept_Encoding']):
#             parameters.append(self.__clean_pattern(req.headers['Accept_Encoding']))
#             locations.append('Accept Encoding')

#         if 'Accept_Language' in req.headers and self.__is_valid(req.headers['Accept_Language']):
#             parameters.append(self.__clean_pattern(req.headers['Accept_Language']))
#             locations.append('Accept Language')

#         req.threats = {}

#         if len(parameters) != 0:
#             predictions = self.clf.predict(parameters)

#             for idx, pred in enumerate(predictions):
#                 if pred != 'valid':
#                     req.threats[pred] = locations[idx]

#         request_parameters = {}
#         if self.__is_valid(req.request):
#             request_parameters = urllib.parse.parse_qs(self.__clean_pattern(req.request))

#         body_parameters = {}
#         if self.__is_valid(req.body):
#             body_parameters = urllib.parse.parse_qs(self.__clean_pattern(req.body))

#             if len(body_parameters) == 0:
#                 ###Check if it is JSON data
#                 try:
#                     body_parameters = json.loads(self.__clean_pattern(req.body))
#                 except:
#                     pass

#         parameters = []
#         locations = []

#         for name, value in request_parameters.items():
#             for elem in value:
#                 parameters.append([len(elem)])
#                 locations.append('Request')

#         for name, value in body_parameters.items():
#             if isinstance(value, list):
#                 for elem in value:
#                     parameters.append([len(elem)])
#                     locations.append('Body')
#             else:
#                 parameters.append([len(value)])
#                 locations.append('Body')

#         if len(parameters) != 0:
#             pt_predictions = self.pt_clf.predict(parameters)

#             for idx, pred in enumerate(pt_predictions):
#                 if pred != 'valid':
#                     req.threats[pred] = locations[idx]

#         if len(req.threats) == 0:
#             req.threats['valid'] = ''
        
        
import joblib
import urllib.parse
import json
import pandas as pd 

class ThreatClassifier(object):
    def __init__(self):
        self.clf = joblib.load('../Classifier/predictor.joblib')
        self.pt_clf = joblib.load('../Classifier/pt_predictor.joblib')
        
    def __unquote(self, text):
        k = 0
        uq_prev = text
        while k < 100:
            uq = urllib.parse.unquote_plus(uq_prev)
            if uq == uq_prev:
                break
            else:
                uq_prev = uq
        return uq_prev
    
    def __remove_new_line(self, text):
        text = text.strip()
        return ' '.join(text.splitlines())
    
    def __remove_multiple_whitespaces(self, text):
        return ' '.join(text.split())
    
    def __clean_pattern(self, pattern):
        pattern = self.__unquote(pattern)
        pattern = self.__remove_new_line(pattern)
        pattern = pattern.lower()
        pattern = self.__remove_multiple_whitespaces(pattern)
        return pattern
    
    def __is_valid(self, parameter):
        return parameter is not None and parameter != ''
    
    def classify_log(self, log_entry):
        parameters = []
        locations = []
        
        if self.__is_valid(log_entry.get('request')):
            parameters.append(self.__clean_pattern(log_entry['request']))
            locations.append('Request')

        if self.__is_valid(log_entry.get('body')):
            parameters.append(self.__clean_pattern(log_entry['body']))
            locations.append('Body')

        # Handle headers if available
        if 'headers' in log_entry:
            headers = log_entry['headers']
            if 'Cookie' in headers and self.__is_valid(headers['Cookie']):
                parameters.append(self.__clean_pattern(headers['Cookie']))
                locations.append('Cookie')

            if 'User_Agent' in headers and self.__is_valid(headers['User_Agent']):
                parameters.append(self.__clean_pattern(headers['User_Agent']))
                locations.append('User Agent')

            if 'Accept_Encoding' in headers and self.__is_valid(headers['Accept_Encoding']):
                parameters.append(self.__clean_pattern(headers['Accept_Encoding']))
                locations.append('Accept Encoding')

            if 'Accept_Language' in headers and self.__is_valid(headers['Accept_Language']):
                parameters.append(self.__clean_pattern(headers['Accept_Language']))
                locations.append('Accept Language')

        log_entry['threats'] = {}
        
        if len(parameters) != 0:
            predictions = self.clf.predict(parameters)
            for idx, pred in enumerate(predictions):
                if pred != 'valid':
                    log_entry['threats'][pred] = locations[idx]

        # Handle additional processing as needed

        return log_entry
    
    def process_logs(self, json_file_path):
        with open(json_file_path, 'r') as file:
            logs = json.load(file)

        classified_logs = []
        for log_entry in logs:
            classified_log = self.classify_log(log_entry)
            classified_logs.append(classified_log)
        
        return classified_logs

# Example usage
# Assuming your JSON logs are stored in 'logs.json'
# classifier = ThreatClassifier()
# processed_logs = classifier.process_logs('logs.json')
