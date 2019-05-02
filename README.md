# VirusTotal-MultiFile-Uploader
A script to upload multiple samples to Virustotal via its api with Python3.

This uploader was created to upload samples captured by the Dionaea and Adbhoney pots installed with the TPot Framework (https://github.com/dtag-dev-sec/tpotce)
This Framework deploys a range of honeypots targeted to capture and analyse traffic. The two honeypots, Dionaea and Adbhoney also capture Malware samples.

Combining this script with a cron job, all samples for each day will be checked against Virus Total and will upload the samples if required.

To operate the Uploader, follow the instructions:

1. Clone this Repo: git clone https://github.com/PR3R00T/VirusTotal-MultiFile-Uploader.git

You will need a Free Virus Total account (https://www.virustotal.com/#/join-us)
Once completed navigate to the User Settings -> API key and copy the key.
2.Place the key into the variable: vtotal in the VTupload.py script. (nano VTupload.py)

3.Install the requirements.txt: pip3 install -r Requirements.txt

4.Give the file execute permissions: chmod +x VTupload.py

5.run the script: ./VTupload.py

Log files are created within: /data/ folder if any issues occur, check the VTuploaderror log.

If you would like to automate this script add a cron job:

1. launch crontab with: crontab -e

2. append to the end (change the times if required): 

# m h  dom mon dow   command
20 2 * * * /full/path/to/VirusTotal-MultiFile-Uploader/VTupload.py

