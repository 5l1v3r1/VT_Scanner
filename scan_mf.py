import sys
import os
import hashlib
import argparse
import logging
import requests
import json
import time
import pandas as pd 
import re

path = os.path.dirname(os.path.abspath(__file__))

def sha256sum(filename):

    with open(filename, 'rb') as f:
        m = hashlib.sha256()
        while True:
            data = f.read(8192)
            if not data:
                break
            m.update(data)
        return m.hexdigest()

def read_generics(generics_file):
    '''Read generic token set from given file'''
    gen_set = set()
    with open(generics_file) as gen_fd:
        for line in gen_fd:
            if line.startswith('#') or line == '\n':
                continue
            gen_set.add(line.strip())
    return gen_set

def read_aliases(alfile):
    '''Read aliases map from given file'''
    if alfile is None:
        return {}
    almap = {}
    with open(alfile, 'r') as fd:
        for line in fd:
            alias, token = line.strip().split()[0:2]
            almap[alias] = token
    return almap

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
                    print (str(os.path.basename(filename)) + " Number of Positives : " + str(resmap["positives"]))
                    print ("===============================")
                    number = 0
                    index = []
                    data = []
                    res = []
                    for i in resmap["scans"]:
                        if (str(resmap["scans"][i]["detected"]) == "True"): # if one of virus total engine detect a malware, print it, if no skip
                            ret = []
                            result_final = re.split("[^0-9a-zA-Z]", str(resmap["scans"][i]["result"])) # Suffix Removal (Split by .)
                            for token in result_final:
                                # Convert to lowercase
                                token = token.lower() # Tokenization (Lower Letter)
                                if len(token) < 4:
                                    continue
                                end_len = len(re.findall("\d*$", token)[0]) # Tokenization (End with number)
                                if end_len:
                                    continue
                                if token in gen_set: # Remove generic tokens
                                    continue
                                # Replace alias
                                token = aliases_map[token] if token in aliases_map \
                                                           else token
                                ret.append(token)

                            if (ret in res): #Remove Duplicates
                                continue
                            else:
                                if ret:
                                    number += 1
                                    index.append(str(number))
                                    res.append(ret)
                                    data.append([str(i), ret])
                                else:
                                    continue
                        else:
                            continue

                    pd_ = pd.DataFrame(data, index=index, columns=["AV Engine","Result"])   
                    print (pd_)
                    pd_.to_csv("/home/ariefhakimaskar/Desktop/VT_Scanner_MF/PE_CSV/" + str(os.path.basename(filename)) + '.csv', sep = '.', encoding = 'utf-8')
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
    vt.apikey = "___YOUR VIRUS TOTAL API KEY___"

    file_path = "___YOUR MALWARE FILES DIRECTORY___"
    gen_file = os.path.join(path, "data/default.generics")
    # Read generic token set from file
    gen_set = read_generics(gen_file) if gen_file else set()
    alias_file = os.path.join(path, "data/default.aliases")
    # Read aliases map from file
    aliases_map = read_aliases(alias_file) if alias_file else {}
    vt.send_files(file_lists(file_path))
    vt.retrieve_files_reports(file_lists(file_path))  


