"""
Code for making dynamic analyses of ios apps   
 
"""

import os
from pathlib import Path
import subprocess as sub
import frida
from time import sleep
from datetime import date
import pandas as pd
import json
import sys


# Load the config file
with open(Path("helpers", "config.json")) as config_file:
    config = json.load(config_file)
    EMAIL = config.get("email")
    PASSWORD = config.get("password")

# Global variable for storing the domains
domains = set()


def get_UDID(): # Get the UDID of the connected device
    udid = sub.run(["idevice_id"], stdout=sub.PIPE).stdout.decode("utf-8")
    return udid[:-7]

def auth():
    # authenticate the user in the ipatool app
    sub.run([
        "ipatool",
        "auth",
        "login",
        "--email", EMAIL,
        "--password", PASSWORD])


# This function uses the openurl.js script as inline script
def manualDownload(storelink, appname, bundleID):
    print(f"[*] START Manually download the app: {appname} ({bundleID})")
    device = frida.get_usb_device()
    safariPID = get_pid("com.apple.mobilesafari", device)
    
    if safariPID == 0: # If the safari app is not running then start it 
        device.spawn("com.apple.mobilesafari")
        sleep(1)
        safariPID = get_pid("com.apple.mobilesafari", device) 
    
    device.resume(safariPID) # Resume the safari app if it is paused
    
    session = device.attach(safariPID)
    with open("./frida_scripts/openurl.js", encoding="utf-8") as f:
        openurl = f.read()
        
    script = session.create_script(openurl)
    script.load()
    api = script.exports_sync
    print(api.openurl(storelink))


# TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST TEST
def download(bundleID, appname, storelink):
    if bundleID + ".ipa" not in os.listdir("./ipafolder"):
        result = sub.run(
            [
                "ipatool",
                "download",
                "-b",
                bundleID,
                "--purchase",
                "-o",
                "./ipafolder/" + bundleID + ".ipa",
                "--non-interactive"
            ],
            stdout=sub.PIPE,
            stderr=sub.PIPE
        )
        if "failed to purchase item with param 'STDQ'" in result.stderr.decode("utf-8"):
            print(f"[*] Failed to purchase app: {appname} ({bundleID})")
            # start the manual download of the app from the appstore
            manualDownload(storelink, appname, bundleID)
            # Wait for the user to download the app
            input("Press Enter to continue...")
    else:
        print(f"[*] {appname} : {bundleID} is already downloaded")


def ideviceinstall(bundleID, udid, install=True):
    ipafolder = "./ipafolder/"
    if install == True:  # Installs the app
        sub.run(
            ["ideviceinstaller", "-u", udid, "-i", ipafolder + bundleID + ".ipa", "-w"])
    else:  # Uninstalls the app
        sub.run(["ideviceinstaller", "-u", udid, "-U", bundleID, "-w"])


def get_pid(application, device):
    for a in device.enumerate_applications():
        pid = 0
        if a.identifier == application:
            print(f"PID : {a.pid}")
            return a.pid


def make_dump(app, bundleID, storelink, pathToDB):
    global domains
    dstruct = {}
    dstruct[bundleID] = {
        "entryDate": str(date.today()),
        "bundleID": bundleID,
        "appName": app,
        "storelink": storelink,
        "domains_count": len(domains),
        # Removes the path from the domain if there is more than 2 slashes
        "domains_simple": list({d[:d.index("/", 10)] if d.count("/") > 2 else d for d in domains}),
        "domains_full": list(domains),
    }

    # The data structure for the app entry
    print("[*] Opens Database file")
    if os.path.exists(pathToDB):
        with open(pathToDB) as fp:
            curdb = json.load(fp)
    else:
        iniDB = {"apps": {}}
        with open(pathToDB, "w+", encoding="UTF-8") as f_ini:
            json.dump(iniDB, f_ini, indent=4)
        with open(pathToDB) as fp:
            curdb = json.load(fp)

    # Pushes the instance into the database
    curdb["apps"].update(dstruct)
    with open(pathToDB, "w", encoding="UTF-8") as f:
        json.dump(curdb, f, indent=4)

    if len(domains) >= 0:
        domains = set()


def on_message(message, _data):
    global domains
    if message["type"] == "send":
        # print(message["payload"])
        domains.add(message["payload"])


def counter(timeToCount):
    for remaining in range(timeToCount, 0, -1):
        sys.stdout.write("\r")
        sys.stdout.write("{:2d} seconds remaining.".format(remaining))
        sys.stdout.flush()
        sleep(1)


def main(applist_FP, pathToDB, start=0):
    setup() # Setup the environment
    auth() # Authenticate the user
    df1 = pd.read_csv(Path(applist_FP))
    applist = df1.to_dict(orient="records")
    print(f"Connected to device UID: {frida.get_usb_device()}")

    for i, app in enumerate(applist[start:]): # Change the range to the desired range of apps
        app_name = app["apps"]
        bundle_id = app["bundleID"]
        if app["links"] == "":
            store_link = "" #Apple apps is missing links
        else:
            store_link = app["links"]

        print(f"[*]------  Analysing the app:   {str(app_name).upper()}   #{start+i} of {len(applist)-start}] ------[*]")
        try:
            if "com.apple" not in str(bundle_id):
                global domains
                make_dump(app_name, bundle_id, store_link, pathToDB)
                download(bundle_id, app_name, store_link)
                ideviceinstall(bundle_id, get_UDID(), install=True)

                with open("./frida_scripts/dump-ios-url-scheme.js") as f:
                    findDynamicJS = f.read()

                device = frida.get_usb_device()
                print(f"[*] Spawns app: {bundle_id}")
                device.spawn(bundle_id)
                sleep(2)
                appPid = get_pid(bundle_id, device)
                print(f"[*] Attach to app - pid: {appPid}")
                session = device.attach(appPid)
                script = session.create_script(findDynamicJS)
                print("[*] Setup message handler")
                script.on("message", on_message)

                print("[*] Load Script")
                script.load()
                device.resume(appPid)

                counter(10)

                device.kill(appPid)
                session.detach()
                print("[*] Frida Analysis Finished")
                ideviceinstall(bundle_id, get_UDID(), install=False)
                make_dump(app_name, bundle_id, store_link, pathToDB)
                device.kill(appPid)
            else:
                print(f"[*] APPLE native app: {app_name} : {bundle_id}")
                make_dump(app_name, bundle_id, store_link, pathToDB)
                pass
        except Exception as e:
            print(f"[*] Error: {e}")
            with open("fails.csv", "a") as f:
                f.write(f"{app_name},{bundle_id}, {e}\n")
    print("[*] Finished")


if __name__ == "__main__":
    print("[*] Starting ...")
    # dynamic_main(["subwaysurfer","com.kiloo.subwaysurfers"])
    main("./applists/DFL_All_iOS.csv", "./dfl_dyn_db.json", start=220)
