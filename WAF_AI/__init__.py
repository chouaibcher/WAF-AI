import joblib
import numpy as np
import pickle
from abc import ABC, abstractmethod


# Custom Unpickler to load the custom tokenizer
class CustomUnpickler(pickle.Unpickler):
    def find_class(self, module, name):
        if name == 'custom_tokenizer':
            return custom_tokenizer
        return super().find_class(module, name)
    
# Custom tokenization function 
def custom_tokenizer(text):
    return text.split()

class WAF_AI(ABC):
    def __init__(self,model_path,vectorizer_path):
        # Load the saved model and vectorizer
        self.model_path=model_path
        self.vectorizer_path=vectorizer_path
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

    @abstractmethod
    def detect(self, path):
        pass

class SQLInjectionWAF_AI(WAF_AI):
    def detect(self, path):
        if path is None:
            return False  # No meaningful tokens, assume no SQL injection
        try:
            prediction = self.model.predict(path) if self.model else [0]
            print(f"Prediction: {prediction}")  # Debugging
            return prediction[0] == 1  # Assuming 1 indicates SQL injection
        except Exception as e:
            print(f"Error during prediction: {e}")
            return False