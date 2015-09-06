#!/bin/usr/env python

import os, sys, subprocess, datetime, time, signal, tarfile, sqlite3, json, urllib2
from watchdog.observers import Observer  
from watchdog.events import PatternMatchingEventHandler  
from collections import deque
import multiprocessing
import parseForAck

file_path           = '/home/andrew/Desktop/filewatcher/triggerFile'
extensions          = ('.pcap', '.doc', '.txt', '.tar', '.tar.gz', '.gz', '')
#errorFile           = open('FileErrors.txt', "wb") # Write all returned errors from processed files
badExtensionCounter = 0 # Number of files who's extension was not accepted
badExtension        = open('BadExtension.txt', "wb") # Write all files who's extension was not accepted
failedProcessCounter= 0 # Counter for files that failed to be analyzed
failedFlag          = 0 # Set to 1 if process fails
taskDoneFlag        = 0 # Signal a task has completed
processQueue        = multiprocessing.JoinableQueue() # Set up queue to process elements from
#POST_URL            = "http://127.0.0.1:8000/cms"
POST_URL            = "http://test.com"

# If the extension isn't in the pattern field, it will be ignored. Feature of watchdog library.

######################
### Output Colors  ###
######################
class tcolors:
    OKBLUE    = '\033[94m'
    OKGREEN   = '\033[92m'
    YELLOW    = '\033[93m' # Warning
    RED       = '\033[91m' # Fail
    ENDC      = '\033[0m'  # End of coloring signal
    BOLD      = '\033[1m'
    UNDERLINE = '\033[4m'
    HEADER    = '\033[95m' # Salmon (not pink)
    
######################
### Analyze Files  ###
######################
class AnalyzeFiles:
    def __init__(self, nextFile):
        self.nextFile = nextFile
    
    def processing(self, nextFile):
        print(tcolors.YELLOW + "[~] Processing {}".format(nextFile) + tcolors.ENDC)
        
#######################
### Export to JSON  ###
#######################
class JsonData:
    def __init__(self, filenamedb, extdb, ffdb, timestampdb):
        self.filenamedb  = filenamedb
        self.extdb       = extdb
        self.ffdb        = ffdb
        self.timestampdb = timestampdb
      
    # Print Object Data  
    def __str__(self):
        return "\nFilename: %s\nExtension: %s\nStatus: %s\nTimestamp: %s\n\n"%(self.filenamedb, self.extdb, self.ffdb, self.timestampdb)


######################
###  File Checker  ###
######################
  
def fileChecker(pathName): 
    global badExtensionCounter 
    
    if os.path.isdir(pathName): 
        print "Directory found" 
        fileNum = len(os.listdir(pathName))
        process = multiprocessing.current_process()
        #print process
        print fileNum
        checkForDirectory(pathName)
        #sys.exit(1) # For debugging purposes
        
    # Control gate for non directories
    _, ext = os.path.splitext(pathName) 
    if ext in extensions: # Check file extension for validity
        processQueue.put(str(pathName)) # Add to process queue
    
    # Check file extensions for all non-directories  
    elif (ext not in extensions) and (os.path.isdir(pathName) == False):
        print(tcolors.BOLD + tcolors.RED + "[!] Invalid File Extension {}".format(pathName) + tcolors.ENDC)
        badExtensionCounter += 1 # Increment number of rejected files for end of process report
        badExtension.write("[!] Invalid File Extension {}\n".format(pathName)) 

def checkForDirectory(pathName):
    for pathname, pathnames, filenames in os.walk(pathName):
        for filename in filenames:
            path = os.path.join(pathName, filename)
            print path
            fileChecker(path) # Recursively scan for new subdirectories/files.

    
# Analyze files provided by worker function
def processFiles(nextFile):   
    global failedFlag, taskDoneFlag, failedProcessCounter
    af = AnalyzeFiles(nextFile)
        
    _, ext = os.path.splitext(nextFile) # Check file extension
    print ext
    
    if ext in extensions: # Run certain actions based on file extension
        if (ext == '.pcap'):
            af.processing(nextFile) # Print processing text
            try:
                response = parseForAck.main(nextFile)
  
            except:
                failedFlag = 1
                #failedProcessCounter += 1
                #print "\nFailed Process Counter: %d\n" %(failedProcessCounter)
                #failedProcess.write("[X] Unable To Process the following: {}\n".format(nextFile))
                
        if (ext == '.doc'):
            af.processing(nextFile) # Print processing text
            
        if (ext == '.txt'):
            af.processing(nextFile) # Print processing text
            process = multiprocessing.current_process()
            print "TXT: ", process 
           
        if ((ext == '.gz') or (ext == '.tar')):
            af.processing(nextFile) # Print processing text
            print "Found a g-zipped file"
            try:
                extract = tarfile.open(str(nextFile))
                extract.extractall("triggerFile")
                extract.close()
                taskDoneFlag = 1 # For debugging purposes
                process = multiprocessing.current_process() # For debugging purposes
                #print ".GZ: ", process
            except IOError, err:
                print err

#############################
### Multi CPU processing  ###
#############################
# Worker function to handle all processes    
def worker(processQueue):
  global failedFlag, taskDoneFlag, failedProcessCounter
  while True:
    try:
        for nextFile in iter( processQueue.get, None ):
            processFiles(nextFile)
            processQueue.task_done() # Individual process has completed
            if (taskDoneFlag == 1): # Only corresponds to .gz extension
                taskDoneFlag = 0
                process = multiprocessing.current_process()
                print "PQ: ", process
                #print(tcolors.OKGREEN + "[*] Processing Complete {}".format(nextFile) + tcolors.ENDC)
                #break
                
            exportToSQL(nextFile, failedFlag)

            if (failedFlag == 0):
                print "made it here"
                print(tcolors.OKGREEN + "[*] Processing Complete {}".format(nextFile) + tcolors.ENDC)
                
            elif failedFlag == 1:
                failedFlag = 0
                failedProcessCounter += 1
                print "\nFailed Process Counter: %d\n" %(failedProcessCounter)
                print(tcolors.BOLD + tcolors.RED + "[X] Failed to process {}".format(nextFile) + tcolors.ENDC)
                
            time.sleep(2)
    except KeyboardInterrupt:
        break      

#####################
### Export To SQL ###
#####################
def exportToSQL(nextFile, failedFlag):
    #global db
    db = sqlite3.connect('analysis.db', detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
    #db = sqlite3.connect(':memory:')
    cursor = db.cursor()
    filenamedb = str(nextFile) # Stores full filepath
    _, ext = os.path.splitext(nextFile) # Check file extension
    print ext
    extdb = str(ext) 
    
    if failedFlag == 1:
        ffdb = 'Failed'
    elif failedFlag == 0:
        ffdb = 'Succeeded'
    
    #timestampdb = time.strftime('%Y-%m-%d %H:%M:%S')
    timestampdb = datetime.datetime.now()
    
    cursor.execute(''' INSERT INTO files(filename, extension, status, timestampdb)
                        VALUES(?,?,?,?)''', (filenamedb, extdb, ffdb, timestampdb))
    db.commit()
    db.close()
    
    JsonDataObj = JsonData(filenamedb, extdb, ffdb, timestampdb)
    print JsonDataObj
    exportToJson(JsonDataObj) 
    
######################
### Export To JSON ###
######################
# Display each scanned file.
def exportToJson(JsonDataObj):
    json_data = json.dumps([{
        "Filename"  : JsonDataObj.filenamedb,
        "Extension" : JsonDataObj.extdb,
        "Status"    : JsonDataObj.ffdb,
        "Timestamp" : JsonDataObj.timestampdb.isoformat()}])
        
    url = urllib2.Request(POST_URL)
    url.add_header('Content-Type', 'application/json')
    response = urllib2.urlopen(url, json_data)
 
###########################
### Set-up SQL Database ###
###########################
# Set-up a different table for each file type?
# Data we want to capture?
def sql_setup():
    #global db
    try:
        # Creates or opens a sql file called mydb with a SQLite3 DB
        db = sqlite3.connect('analysis.db', detect_types=sqlite3.PARSE_DECLTYPES|sqlite3.PARSE_COLNAMES)
        # Create a database in RAM
        #db = sqlite3.connect(':memory:')
        
        # Get a cursor object
        cursor = db.cursor()
        # Check if table users does not exist and create it
        cursor.execute('''CREATE TABLE IF NOT EXISTS
                      files(filename TEXT, extension TEXT, status TEXT, timestampdb TEXT)''')
        # Commit the change
        db.commit()
        
    # Catch the exception
    except Exception as e:
        # Roll back any change if something goes wrong
        db.rollback()
        raise e
        
    finally:
        # Close the db connection
        db.close() 
     
######################
### Event Handlers ###
######################
               
class MyHandler(PatternMatchingEventHandler):
    patterns = ["*.txt", "*.gz", "*.pcap", "* ", "*.csv", "*.doc", "*tar"]

    def process(self, event):
        """
        event.event_type 
            'modified' | 'created' | 'moved' | 'deleted'
        event.is_directory
            True | False
        event.src_path
            path/to/observed/file
        """
        # the file will be processed there
        #print event.src_path, event.event_type  # print now only for degug

    def on_modified(self, event):
        self.process(event)
        pathName = event.src_path
        print "\nOn_modified\n"
        #print(tcolors.OKBLUE + "[+] New File Added: {}".format(pathName) + tcolors.ENDC)
        #fileChecker(pathName)

    def on_created(self, event):
        self.process(event)
        pathName = event.src_path
        print "\non_Created\n" 
        print(tcolors.OKBLUE + "[+] New File Added: {}".format(pathName) + tcolors.ENDC)
        fileChecker(pathName)
        
############################
###  Check Dependencies  ###
############################     
# Add check for watchdog    
def check_dependencies():   
    if not os.path.isfile('/usr/lib/python2.7/sqlite3'):
        install = raw_input('['+T+'*'+W+'] sqlite3 configuration files not found in /usr/lib/python2.7/sqlite3, install now? [y/n] ')
        if install == 'y':
            os.system('apt-get -y install sqlite3')
        else:
            sys.exit('['+R+'-'+W+'] sqlite3 configuration files not found in /usr/lib/python2.7/sqlite3')
        
###########################
### Shutdown Procedures ###
###########################
def shutdown():
    #errorFile.close()
    badExtension.close()
    finalOutput()
    #sys.exit(2)

def init_worker():
    signal.signal(signal.SIGINT, signal.SIG_SIGTERM)

def finalOutput(): # Add number of processed files
    print "\n******************************************"
    print "\tBad File Extensions:             %d" %(badExtensionCounter)
    print "\tFiles Unable to Process:         %d" %(failedProcessCounter)
    print "******************************************"    
    
           
############
### MAIN ###
############
def main(): 
    global badExtensionCounter, failedFlag, pool, failedProcessCounter#, db
    
    sql_setup() # Set-up SQL Database/check to see if exists
    
    # Initiate File Path Handler
    observer = Observer()
    observer.schedule(MyHandler(), path=file_path, recursive=True)
    observer.start()
    
    cpuCount = multiprocessing.cpu_count() # Count all available CPU's
    print "\nTotal CPU Count: %d"%(cpuCount)
    pool = multiprocessing.Pool(4, worker,(processQueue,)) # Create 4 child processes to handle all queued elements
    active = multiprocessing.active_children() # All active child processes
    print "Total number of active child processes: %s\n"%(str(active))
    
    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        pool.terminate() # Stop all child processes
        pool.join() # Join the processes with parent and terminate
        active = multiprocessing.active_children() # All active child processes, list should be empty at this point.
        print "\nTotal number of active child processes: %s\n"%(str(active))
        shutdown() # Run shutdown sequence        
        observer.stop()
        observer.join()
        sys.exit(1)
        
    
if __name__=="__main__":
    main()
    
    
    
    
