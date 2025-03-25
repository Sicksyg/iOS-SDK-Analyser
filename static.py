import os
import subprocess as sub
import pandas as pd
import json
import time
from datetime import date
import re
import itertools
import frida
from zipfile import ZipFile, BadZipFile
import plistlib
import shutil
import argparse
from pathlib import Path


with open(Path("helpers", "config.json")) as config_file:
    config = json.load(config_file)
    EMAIL = config.get("email")
    PASSWORD = config.get("password")

""" Main Analysis """


class MainAnalysis:
    def __init__(self, appname, bundleID, ipafolder, database):
        """Main Analysis Class initater
        Args:
            appname (string): the app to be analyzed
            bundleID (string): the bundleID for the app
            ipafolder (string - path): path to the folder with ipafiles for the Ipatool downloader
            database (string - path): path to the output db file in json format
        """
        self.date = str(date.today())
        self.appname = appname
        self.ipafolder = ipafolder
        self.database = database
        # self.bundleID = self.resolveAppName()
        self.bundleID = bundleID

        self.logfolder = self.makeLogfolder()
        self.app_logfolder = self.makeApplogfolder()
        self.logfile = ""
        self.download()

        self.fridaAnalysis()
        self.sdk = self.detectSDK(self.openSig(), self.logfile)
        self.permissions = self.detectPermissions()
        self.constructData()

    def authenticate(self) -> None:
        sub.run([
            "ipatool",
            "auth",
            "login",
            "--email", EMAIL,
            "--password", PASSWORD])

    def download(self):
        if self.bundleID + ".ipa" not in os.listdir(self.ipafolder):
            try:
                sub.run([
                    "ipatool",
                    "download",
                    "-b", self.bundleID,
                    "--purchase",
                    "-o", self.ipafolder + self.bundleID + ".ipa",
                    "--verbose"])
            except:
                self.authenticate()
                sub.run([
                    "ipatool",
                    "download",
                    "-b", self.bundleID,
                    "--purchase",
                    "-o", self.ipafolder + self.bundleID + ".ipa"])
        else:
            print(f"[*] {self.appname} : {self.bundleID} is already downloaded")

    def makeLogfolder(self):
        # Creates the directory "logfolder" for the frida logs, Only runs once per instance
        logfolder = "iOS_log_" + date.today().strftime("%d-%m-%Y")
        if "Logfolder" not in os.listdir("./"):
            os.mkdir("./Logfolder")
        if logfolder in os.listdir("./Logfolder"):
            return logfolder
        else:
            print(
                f"[*] Creating a directory called {logfolder} for Frida logs")
            os.mkdir("./Logfolder/" + logfolder)
        return logfolder

    def makeApplogfolder(self):
        """ From here, make a folder, return the folder path, the folder should be initiated each app, the logfolder dest.,
        should be replaced by this in the install_analysis"""
        app_logfolder = "./Logfolder/" + self.logfolder + "/" + self.bundleID + "/"
        if self.bundleID not in os.listdir("./Logfolder/" + self.logfolder):
            os.mkdir(app_logfolder)
        else:
            return app_logfolder
        return app_logfolder

    def getUDID(self):
        # Returns the UDID of the connected device
        udid = sub.run(["idevice_id"], stdout=sub.PIPE).stdout.decode("utf-8")
        return udid[:-7]

    def ideviceinstall(self, udid, install=True):
        # Installs the app on the connected device and uninstalls it if the install flag is set to False
        if install == True:  # Installs the app
            sub.run(["ideviceinstaller", "-u", udid, "-i",
                    self.ipafolder + self.bundleID + ".ipa", "-w"])
        else:               # Uninstalls the app
            sub.run(["ideviceinstaller", "-u", udid, "-U", self.bundleID, "-w"])

    def makeLogfile(self, classlist):
        # Creates a log file with the classes found in the app
        print(f"[*] Creating log file with #classes = {len(classlist)}")
        logfile_ = "./" + self.app_logfolder + self.bundleID + "_log.txt"
        with open(logfile_, "w") as logfile:
            for item in classlist:
                try:
                    logfile.write(item + "\n")
                except:
                    print(f"[*] !! COULD NOT WRITE LOGFILE !!")
        self.logfile = logfile_

    def onMessage(self, message, _data):
        # CHANGE TO SELF.APPFOLDER
        # Sets the message handler for the frida script - The frida script returns an list of classes
        if message['type'] == 'send':
            # print(message["payload"])
            self.makeLogfile(message["payload"])

        # with open("./" + self.app_logfolder + self.bundleID + "_log.txt", "a") as logfile:
        #     if message['type'] == 'send':
        #         logfile.write(message["payload"] + "\n")

    def getPID(self, application, device):
        for a in device.enumerate_applications():
            pid = 0
            if a.identifier == application:
                print(f"[*] PID : {a.pid}")
                return a.pid

    def fridaAnalysis(self, iOSnative=False, native=False):
        #https://github.com/rubaljain/frida-jb-bypass <- Check this out
        try:
            udid = self.getUDID()
            # if the iOSnative flag is set to False, install, analyse with frida and uninstall the app.
            # if iOSnative == False:
            if "com.apple" in str(self.bundleID):
                self.ideviceinstall(udid, install=False)
                print(
                    f"[*] Starting Frida on Apple native app:  {self.bundleID}")

                with open("./helpers/frida_findallclass.js") as f:
                    findClassesJS = f.read()

                device = frida.get_usb_device()  # Grap the device connected by USB
                # Spawns the app with the bundleID
                device.spawn(self.bundleID)
                time.sleep(4)  # Wait or crash
                appPid = self.getPID(self.bundleID, device)
                # Attach to the resolved PID, set up message port and load script
                session = device.attach(appPid)
                script = session.create_script(findClassesJS)
                script.on("message", self.onMessage)
                script.load()
                # sys.stdin.read()
                time.sleep(1)
                # device.kill(appPid)
                session.detach()
                print("[*] Frida Analysis Finished")
                # Quits the loop if sucessfull

            else:  # if the iOSnative flag is set to True, only run frida on the apps without the install
                if native == False:
                    self.ideviceinstall(udid, install=True)
                time.sleep(1)
                print("[*] Starting Frida")

                with open("./helpers/frida_findallclass.js") as f:
                    findClassesJS = f.read()
                device = frida.get_usb_device()  # Grap the device connected by USB
                # Spawns the app with the bundleID
                print("[*] Spawn App")
                device.spawn(self.bundleID)
                time.sleep(2)  # Wait or crash
                appPid = self.getPID(self.bundleID, device)
                # Attach to the resolved PID, set up message port and load script
                print(f"[*] Attach to app - pid: {appPid}")
                session = device.attach(appPid)
                script = session.create_script(findClassesJS)
                #script2=session.create_script("""console.log("i ran")""")

                print("[*] Setup message handler")
                script.on("message", self.onMessage)

                print("[*] Load Script")
                script.load()
                #script2.load()
                
                device.resume(appPid)
                # sys.stdin.read()
                time.sleep(5)
                device.kill(appPid)
                session.detach()
                print("[*] Frida Analysis Finished")

        except Exception as e:
            print("[*] !! Could not run Install and analysis !!")
            print(e)
            # self.ideviceinstall(udid, install=False)
            # time.sleep(2)
            
            
    def fridaDynamicAnalysis(self):
        print("[*] Finding URLs")
        with open(Path("helpers", "frida_findURLs")) as f:
            findURLs = f.read()
        

    def openSig(self):
        with open("./helpers/ios_signatures.json", encoding="utf-8") as tf:
            signatures = json.load(tf)
        print("[*] SDK signature definitions loaded")
        return signatures

    def detectSDK(self, signatures, classlogfile):  # Takes the logfile with classes
        """
        Args:
            signatures: self.openSig()
            classlogfile: self.app_logfolder + self.bundleID + "_log.txt"

        Returns:
           List of trackers
        """
        print("[*] Compiling and detecting SDKs")
        # signatures = self.openSig()
        regexs = []
        # classlogfile = self.app_logfolder + self.bundleID + "_log.txt"
        try:
            with open(classlogfile, "r") as cf:
                lines = cf.readlines()
            class_list = []
            for line in lines:
                class_list.append(line.rstrip())
            # print(f"this is a class list {class_list[-10:]}")
            for signature in signatures:
                regexs.append(signature['regex'])
            # taken from: https://github.com/Exodus-Privacy/exodus-core
            compiled_tracker_signature = [re.compile(
                signature['regex'], flags=re.MULTILINE | re.UNICODE) for signature in signatures]

            args = [(compiled_tracker_signature[index], tracker, class_list)
                    for (index, tracker) in enumerate(signatures)]

            def _detect_tracker(sig, tracker, class_list):
                for clazz in class_list:
                    # print(f" this is each class {clazz}")
                    if sig.search(clazz):
                        return tracker
                return None

            results = []
            for res in itertools.starmap(_detect_tracker, args):
                if res:
                    results.append(res)
            # print(results)
            trackers = [t["name"] for t in results if t is not None]
            # print(trackers)
            return trackers  # Returns a list of trackers in the log file
        except:
            print("[*] !! No log file exists !!")

    def extractPlist(self):
        print("Extracting Info.plist file")
        ipadir = self.ipafolder + "/" + self.bundleID + ".ipa"
        try:
            with ZipFile(ipadir, "r") as ipa_file:
                for zip_i in ipa_file.namelist():
                    if "Info.plist" in zip_i:
                        # print(self.app_logfolder)
                        with ipa_file.open(zip_i) as fscr, open(self.app_logfolder + "Info.plist", 'wb') as fdst:
                            # Copy file from ipa to logfolder
                            shutil.copyfileobj(fscr, fdst)
                        break
            ipa_file.close()
        except (BadZipFile, FileNotFoundError):
            pass

    def openPersmissionDB(self):
        with open("./helpers/ios_ProtectedResources.json") as f:
            return json.load(f)

    def detectPermissions(self):
        self.extractPlist()
        permissions = {}
        print("[*] Finding permissions")
        permission_db = self.openPersmissionDB()
        try:
            with open(self.app_logfolder + "/Info.plist", "rb") as pl:
                plparsed = plistlib.load(pl)
                for idx in permission_db["permissions"].values():
                    # print(idx["plkey"])
                    if idx["plkey"] in plparsed:
                        # print(f'{str(idx["plkey"])}  -- {idx["commonName"]}')
                        permissions[idx["plkey"]] = idx["commonName"]
                return permissions
        except FileNotFoundError:
            print("[*] !! Could not find a plist file !!")
            pass

    def constructData(self):
        # print(self.database)
        dstruct = {}
        dstruct[self.bundleID] = {
            "entryDate": self.date,
            "bundleID": self.bundleID,
            "appName": self.appname,
            "sdk": self.sdk,
            "permissions": self.permissions,
            "domains_simple": [],
            "domains_full": []
            }

# The data structure for the app entry
        print("[*] Opens Database file")
        if os.path.exists(self.database):
            with open(self.database) as fp:
                curdb = json.load(fp)
        else:
            iniDB = {"apps": {}}
            with open(self.database, "w+") as f_ini:
                json.dump(iniDB, f_ini, indent=4)
            with open(self.database) as fp:
                curdb = json.load(fp)
        # Pushes the instance into the database

        curdb["apps"].update(dstruct)

        # Uploads the new results into the database file
        with open(self.database, "w") as f:
            json.dump(curdb, f, indent=4)

# Initiate app analysis
def analyseListApps(applist, ipafolder, databaseFile):
    for i, app in enumerate(applist):
        print(
            f"  [*]------  Analysing the app: {app['apps']}  [#{i+1} of {len(applist)}] ------[*]  ")
        sa = MainAnalysis(app['apps'], app['bundleID'],
                            ipafolder, databaseFile)







def main():
    # Add parser for Auth, Running findMissing(), Normal operation, Supply filename
    parser = argparse.ArgumentParser(
        prog="Analysis on iOS", description="Analyses apps on iOS - Example of use: DFL_analysis.py './IPR_offentlig.csv' -i '/IPA files_off' -d 'ipr.json' -a")

    parser.add_argument("-a", "--analysis", action="store_true",
                        help="Normal analysis on a list of apps")
    parser.add_argument("-f", "--findmissing", action="store_true",
                        help="Running the FindMissing function")
    parser.add_argument("--exportmissing", action="store_true",
                        help="Export the apps with no sdks in the database")

    parser.add_argument("inputfile", type=str,
                        help="CSV file with apps structured as [apps,bundleID]")

    parser.add_argument("-o", "--ondevice", required=False,
                        help="Run the analysis on apps already on the device")
    parser.add_argument("-ipa", "--ipafolder", required=False,
                        type=str, help="A predefined folder with the ipa files")
    parser.add_argument("-d", "--database", required=False,
                        type=str, help="Name of the database file")
    parser.add_argument("-l", "--logfolder", required=False,
                        type=str, help="ONLY for logfiles analysis")
    parser.add_argument("--forceipa", action="store_true",
                        help="forces the download of a new ipa file")
    parser.add_argument("--auth", action="store_true",
                        help="Force authentication with AppStore")

    args = parser.parse_args()

    if args.ipafolder:
        print(f"IPA folder provided: {args.ipafolder}")

    if args.database:
        print(f"Database file provided: {args.database}")

    if args.logfolder:
        print(f"Log folder provided: {args.logfolder}")

    if args.auth:
        print("Forcing authentication with AppStore")

    if args.analysis:
        df1 = pd.read_csv(args.inputfile)
        analyseListApps(df1.to_dict(orient="records"),
                        args.ipafolder, args.database)
    if args.ondevice:
        print("Running on device")
        MainAnalysis(args.ondevice, args.ondevice, args.ipafolder, args.database)
    if args.auth:
        MainAnalysis.authenticate()


if __name__ == "__main__":
    main()


# CLI arguments:

# python3 DFL_analysis.py "./test/IPR_offentlig.csv", -i "/Users/qlf290/Desktop/Datafied/IPR apps/IPA files_off", -d "ipr.json", -a  s


# _______________________________ Helper Functions _________________________________ #
"""
# Analyse apps with no SDK reported
def findMissing(databaseFile) -> list:
    with open(databaseFile) as db:
        x = json.load(db).get("apps")
    missing = []
    for app in x.values():
        if app["sdk"] == None:
            if "apple" not in app["bundleID"]:
                tmpDict = {}
                tmpDict["apps"] = app.get("appName")
                tmpDict["bundleID"] = app.get("bundleID")
                missing.append(tmpDict)
    print(missing)
    print(len(missing))
    return missing


def exportMissing(databaseFile):
    with open(databaseFile) as db:
        x = json.load(db).get("apps")
    missing = []
    for app in x.values():
        if app["sdk"] == None:
            if "apple" not in app["bundleID"]:
                tmpDict = {}
                tmpDict["apps"] = app.get("appName")
                tmpDict["bundleID"] = app.get("bundleID")
                missing.append(tmpDict)
    with open("./MissingApps.json", "w") as missingList:
        json.dump(missing, missingList, indent=4)

# Can't remeber whi i made this -__(^_^')__-


def buildDB(databaseFile):
    ipafolder = "./IPA files/"
    with open(databaseFile) as db:
        resDB = json.load(db).get("apps")

    appDB_df = pd.read_excel("./DFL_All_iOS.xlsx")
    loaddict = appDB_df.to_dict(orient="records")
    print(resDB.keys())
    for i, app in enumerate(loaddict):
        if app["bundleID"] not in resDB.keys():
            print(
                f"[*]------------  Analysing the app: {app['apps']}  [#{i+1} of {len(loaddict)}]  ------------[*]")
            sa = StaticAnalysis(app['apps_lower'],
                                app['bundleID'], ipafolder, databaseFile)

# def analyseLogfolder(applist, logfolder):
#     for i, app in enumerate(applist):
#         print(f"  [*]------  Analysing the app: {app['apps']}  [#{i+1} of {len(applist)}] ------[*]  ")
#         logfile = logfolder + app['bundleID'] +"/"+ app['bundleID'] + "_log.txt"
#         print(logfile)
#         sigs = StaticAnalysis.openSig
#         sdks = StaticAnalysis.detect_sdk(sigs, str(logfile))
#         print(sdks)

"""
