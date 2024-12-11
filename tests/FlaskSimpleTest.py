import os
import sys
import ctypes
from flask import Flask, jsonify
from WAF_AI import WAF4Flask 


## runing the flask app as admin -- start
'''
def is_admin():
    if os.name == 'nt':  # Windows
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except:
            return False
    elif os.name == 'posix':  # Linux/Unix
        return os.geteuid() == 0
    else:
        raise RuntimeError("Unsupported operating system")

def elevate_privileges():
    if os.name == 'nt':  # Windows
        # Re-run the script with admin rights
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, __file__, None, 1)
        sys.exit()
    elif os.name == 'posix':  # Linux/Unix
        # Re-run the script with sudo
        os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
    else:
        raise RuntimeError("Unsupported operating system")

if not is_admin():
    elevate_privileges()
'''
## runing the flask app as admin -- end

# Create Flask App
app = Flask(__name__)

# Adding WAF_AI to Flask App -- start
WAF4Flask.rusicadeWAF_AI(app)

# Adding WAF_AI to Flask App -- end

# Define Flask Routes
@app.route('/')
def home():
    return "Welcome to the Flask App!"

@app.route('/user/<username>')
def user_profile(username):
    # Example route to simulate user profile response
    return jsonify({"user": username})

# Run Flask Application
if __name__ == "__main__":
    app.run(port=5000, debug=True)