import sys
import os
import hashlib
import argparse
import logging
import requests
import json
import time

def sha256sum(filename):

    with open(filename, 'rb') as f:
        m = hashlib.sha256()
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

def file_lists(path):

    assert os.path.isfile(path) or os.path.isdir(path)

    if os.path.isfile(path):
        return [path]
    else:
        return filter(os.path.isfile, map(lambda x: '/'.join([os.path.abspath(path), x]), os.listdir(path)))

class VirusTotal(object):
    def __init__(self):
        self.apikey = ""
        self.URL_BASE = "https://www.virustotal.com/vtapi/v2/"
        self.HTTP_OK = 200

        self.is_public_api = True
        self.has_sent_retrieve_req = False
        self.PUBLIC_API_SLEEP_TIME = 20

        self.logger = logging.getLogger("virt-log")
        self.logger.setLevel(logging.INFO)
        self.scrlog = logging.StreamHandler()
        self.scrlog.setFormatter(logging.Formatter("[%(levelname)s] %(message)s"))
        self.logger.addHandler(self.scrlog)
        self.is_verboselog = False

    def send_files(self, filenames):

        url = self.URL_BASE + "file/scan"
        attr = {"apikey": self.apikey}

        for filename in filenames:
            files = {"file": open(filename, 'rb')}
            res = requests.post(url, data=attr, files=files)

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if not self.is_verboselog:
                    self.logger.info("sent: %s, HTTP: %d, response_code: %d, scan_id: %s",
                            os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_id"])
                else:
                    self.logger.info("sent: %s, HTTP: %d, content: %s", os.path.basename(filename), res.status_code, res.text)
            else:
                self.logger.warning("sent: %s, HTTP: %d", os.path.basename(filename), res.status_code)

    def retrieve_files_reports(self, filenames):

        for filename in filenames:
            res = self.retrieve_report(sha256sum(filename))

            if res.status_code == self.HTTP_OK:
                resmap = json.loads(res.text)
                if not self.is_verboselog:
                    self.logger.info("\nretrieve report: %s, \nHTTP: %d, \nresponse_code: %d, \nscan_date: %s, \npositives/total: %d/%d, \nscans: %s,",
                            os.path.basename(filename), res.status_code, resmap["response_code"], resmap["scan_date"], resmap["positives"], resmap["total"], json.dumps(resmap["scans"], indent=4, sort_keys=True))
                else:
                    self.logger.info("\nretrieve report: %s, \nHTTP: %d, \ncontent: %s", os.path.basename(filename), res.status_code, res.text)
            else:
                self.logger.warning("\nretrieve report: %s, \nHTTP: %d", os.path.basename(filename), res.status_code)
    
    def retrieve_report(self, chksum):

        if self.has_sent_retrieve_req and self.is_public_api:
            time.sleep(self.PUBLIC_API_SLEEP_TIME)

        url = self.URL_BASE + "file/report"
        params = {"apikey": self.apikey, "resource": chksum}
        res = requests.post(url, data=params)
        self.has_sent_retrieve_req = True
        return res

if __name__ == "__main__":
    vt = VirusTotal()
    vt.apikey = "___YOUR API KEY___"

    file_path = "___YOUR DIRECTORY___"
    vt.send_files(file_lists(file_path))
    vt.retrieve_files_reports(file_lists(file_path))
