#!/usr/bin/python3

# VT Comment Upload
from virustotal_python import Virustotal
import glob
import os
from filehash import FileHash
import time

#API KEY Goes here
vtotal = Virustotal("key123")
#Messages
existing_sample_message = "#Malware #HP sample observed in the wild, Uploaded with use of VirusTotal-MultiFile-Uploader"
new_sample_message = "#Malware #HP new sample found in the wild, Uploaded with the use of VirusTotal-MultiFile-Uploader"
  
#Populating list of Samples
dionaea_bin_path = "~/tpotce/data/dionaea/binaries/*"
adbhoney_bin_path = "~/tpotce/data/adbhoney/downloads/*"
dionaea_listglob = glob.glob(dionaea_bin_path)
adbhoney_listglob = glob.glob(adbhoney_bin_path)
listglob = dionaea_listglob + adbhoney_listglob

sha256hasher = FileHash('sha256')
timestr = time.strftime("%Y%m%d")

#Log File paths
output_file = "~/tpotce/VTupload"+timestr+".txt"
patherror =  "~/tpotce/VTuploaderror" + timestr + ".txt"

# iterate each file
for filename in listglob:
    #check Sample Size
    fsize = os.stat(filename)
    #ignore samples of file size: 5267459 as these are WannaCry, Getting to much of these. 
    #take this if statement out if you want to upload WC samples.
    if fsize.st_size == 5267459:
        continue

    print("[*] Found file: " + filename)
    #Get hash of file
    hash = sha256hasher.hash_file(filename)
    #Query VT for Hash Upload
    try:
        file_report = vtotal.file_report([hash])
        #need timer in here as standard API key only allows 4 requests per minute.
        time.sleep(16)
    except Exception as e:
        f= open(patherror,"a+")
        f.write(file + " Failed to check: " + str(e) + "\n")
        f.close()
        print("Failed to check: "+ hash)
    # if the response code is 1, it means the file exists. In this case add comment 
    if file_report['json_resp']['response_code'] == 1:
        resp = vtotal.put_comment(hash,comment=existing_sample_message)
        print("[*] Sample already exists, Moving on")
        time.sleep(16)
    # if the response code of the file report is 0, it means the file does not exist, Lets upload the sample.
    elif file_report['json_resp']['response_code'] == 0:
        try:
            vt_upload = vtotal.file_scan(filename)
            print("[*] NEW Sample Found - " + hash)
        except Exception as e:
            f= open(patherror,"a+")
            f.write(file + " Failed to upload: " + str(e) + "\n")
            f.close()
            print("Failed to upload: " + hash)
        #Wait for the Scan Results
        time.sleep(60)
        try:
            # Add a comment to the new uploaded sample.
            vt_comment = vtotal.put_comment(hash,comment=new_sample_message)
        except Exception as e:
            f= open(patherror,"a+")
            f.write(file + " Failed to comment: " + str(e) + "\n")
            f.close()
            print("Failed to comment: " + hash)
        # add new upload entry to log.
        if vt_upload['status_code'] == 200:
            f= open(output_file,"a+")
            f.write("Hash Uploaded: - " + hash + "\n")
            f.close()
