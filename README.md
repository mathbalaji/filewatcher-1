Suggested platform: Ubuntu 14.04
Usage: python filewatcherv3.py

The intent of this program was to auto analyze a batch of pcaps copied into a specific directory.
This script functions as a framework for this project where modules can be easily added and triggered by certain events.
Compressed files will be uncompressed and subdirectories recurisvely scanned for the target extensions. 

1) Install the python watchdog library to listen for events:
    sudo pip install watchdog
    sqlite3 should come with the python library. Else, install sudo apt-get install sqlite3
    * Will be adding a dependency checker so it auto installs everything.
    
2) In filewatcherv3.py, change the file path to the folder you want to monitor. 
    - Drag contents from pyinotifyTest to triggerFile. TriggerFile is the filepath being monitored.
    
3) ParseForAck.py will scan all pcaps for fragmented packets. 

4) Open activity monitor to track distributed cpu usage for efficiency. 

