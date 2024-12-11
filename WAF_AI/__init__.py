from flask import request
import joblib
import numpy as np
import pickle
from abc import ABC, abstractmethod
import json
import os
import subprocess
import ctypes

base_dir = os.path.dirname(os.path.abspath(__file__))

# Custom Unpickler to load the custom tokenizer
class CustomUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == 'custom_tokenizer':
            return custom_tokenizer
        return super().find_class(module, name)
    
# Custom tokenization function 
def custom_tokenizer(text):
    return text.split()

def is_admin():
    try:
        if os.name == 'nt':
            return ctypes.windll.shell32.IsUserAnAdmin()
        else:
            return os.geteuid() == 0
    except:
        return False

class WAF_AI(ABC):
    def __init__(self,model_path,vectorizer_path):
        # Load the saved model and vectorizer
        self.model_path=model_path
        self.vectorizer_path=vectorizer_path
        self.admin_privileges = is_admin()
        try:
            self.model = joblib.load(model_path)
            print("Model loaded successfully.")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None

        try:
            with open(vectorizer_path, 'rb') as f:
                self.vectorizer = CustomUnpickler(f).load()
            print("Vectorizer loaded successfully.")
        except Exception as e:
            print(f"Error loading vectorizer: {e}")
            self.vectorizer = None
    
    def block_ips_feature(self, client_ip):
        if not self.admin_privileges:
            print("Admin privileges not available. IP blocking feature is disabled.")
            return

        config_path = os.path.join(base_dir, 'models', 'config.json')
        with open(config_path, 'r') as f:
            config = json.load(f)

        if client_ip not in config['whitelisted_ips']:
            print(f"Blocking IP: {client_ip}")
            if os.name == 'nt':  # Windows
                try:
                    subprocess.run(['netsh', 'advfirewall', 'firewall', 'add', 'rule', 'name=BlockIP', 'dir=in', 'action=block', 'remoteip=' + client_ip], check=True)
                    print(f"IP {client_ip} blocked successfully on Windows.")
                except subprocess.CalledProcessError as e:
                    print(f"Error blocking IP on Windows: {e}")
            else:  # Linux
                try:
                    subprocess.run(['iptables', '-A', 'INPUT', '-s', client_ip, '-j', 'DROP'], check=True)
                    print(f"IP {client_ip} blocked successfully on Linux.")
                except subprocess.CalledProcessError as e:
                    print(f"Error blocking IP on Linux: {e}")
        else:
            print(f"IP {client_ip} is whitelisted.")        


    @abstractmethod
    def detect(self, path):
        pass

class SQLInjectionWAF_AI(WAF_AI):
    def detect(self, path,ip):
        if path is None:
            return False  # No meaningful tokens, assume no SQL injection
        try:
            prediction = self.model.predict(path) if self.model else [0]
            print(f"Prediction: {prediction}")  # Debugging
            if prediction[0] == 1:
                self.block_ips_feature(ip)
                return True  # Assuming 1 indicates SQL injection
        except Exception as e:
            print(f"Error during prediction: {e}")
            return False
        