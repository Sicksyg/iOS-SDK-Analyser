from pathlib import Path
import json
import os

# Load the config file
with open(Path("helpers", "config.json")) as config_file:
    config = json.load(config_file)
    EMAIL = config.get("email")
    PASSWORD = config.get("password")
    
def setup():
    # Check if the ipafolder exists if not create it
    if "ipafolder" not in os.listdir():
        os.mkdir("ipafolder")