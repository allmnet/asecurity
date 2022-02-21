import json
import time
import argparse
import pandas as pd
import logging
import re
import validators
import random
import urllib.parse
from urllib3.util.retry import Retry
import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

with open('./conf/conf.json', 'r') as f:
    conf = json.load(f)

LOGLEVEL = conf['dev']['log']

MDE_TENANT = conf['mde']['tenant']
MDE_APP = conf['mde']['app']
MDE_SECRET = conf['mde']['secret']
MDE_URL = "https://login.microsoftonline.com/%s/oauth2/token" % (MDE_TENANT)

if LOGLEVEL == 'dev':
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.DEBUG)
else:
    logging.basicConfig(format='%(asctime)s : %(levelname)s : %(message)s', level=logging.WARNING)

def requests_retry_session(
    retries=10,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def http_request(address, hr_jsondata, hr_headers = None):
    trycount = 0
    number = random.randint(1,3)
    while True:
        try:
            if trycount == 10:
                logging.warning('http_request try over 10')
                break
            else:
                trycount += 1
            time.sleep(number)
            if hr_jsondata:
                res = requests_retry_session().post(url=address, data=hr_jsondata, headers=hr_headers, verify=False)
            else:
                res = requests_retry_session().get(url=address, headers=hr_headers, verify=False)
            if res.status_code == 200:
                break
            else:
                print(res.text)
        except Exception as httpRequest_e:
            httpRequest_error = str(httpRequest_e)
            logging.warning('http_request: %s', httpRequest_error)
            time.sleep(1)
    return res

def mde_search(search_q):
    try:
        mde_search_result = ''

        resourceAppIdUri = 'https://api.securitycenter.microsoft.com'
        body = {
            'resource' : resourceAppIdUri,
            'client_id' : MDE_APP,
            'client_secret' : MDE_SECRET,
            'grant_type' : 'client_credentials'
        }
        data = urllib.parse.urlencode(body).encode("utf-8")
        req = http_request(MDE_URL, data).json()
        aadToken = req["access_token"]

        url = "https://api.securitycenter.microsoft.com/api/advancedqueries/run"
        headers = {
            'Content-Type' : 'application/json',
            'Accept' : 'application/json',
            'Authorization' : "Bearer " + aadToken
        }
        data = json.dumps({ 'Query' : search_q }).encode("utf-8")
        req = http_request(url, data, headers).json()
        if len(req['Results']) > 1:
            df_result = pd.DataFrame(req['Results'])
            mde_search_result = df_result.to_string()
    except Exception as main_mde_e:
        main_mde_error = str(main_mde_e)
        mde_search_result = main_mde_error
        logging.warning('main_mde_error: %s', main_mde_error)
        time.sleep(1)
    return mde_search_result

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-q', '--query', help="search query", required=True)
    args = parser.parse_args()

    ip_regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"
    md5_regex = r"\b(?!^[\d]*$)(?!^[a-fA-F]*$)([a-f\d]{32}|[A-F\d]{32})\b"
    sha256_regex = r"[A-Fa-f0-9]{64}"
    domain_regex = r"^((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\.(xn--)?([a-z0-9\-]{1,61}|[a-z0-9-]{1,30}\.[a-z]{2,})$"
    account_regex = r"^(?![-._])(?!.*[_.-]{2})[\w.-]{6,30}(?<![-._])$"

    hashdata = args.query
    hashdata = hashdata.replace("\n", " ")
    hashlist = []
    if hashdata.startswith('take '):
        hashdata = hashdata.replace('take ','')
        main_result = ''
        search_event = ''
        search_query = ''
        search_result_file = ''
        if ' ' in hashdata:
            splitlist = hashdata.split(' ')
            for s in splitlist:
                s = s.strip()
                hashlist.append(s)
        else:
            hashdata = hashdata.strip()
            hashlist.append(hashdata)
        for search_item in hashlist:
            if bool(re.match(ip_regex, search_item)):
                search_event = '`Network, Process, Registry Events`\n- Search RemoteIP, LocalIP'
                search_query = 'find in (DeviceNetworkEvents, DeviceProcessEvents, DeviceRegistryEvents) where Timestamp > ago(30d) and (RemoteIP contains "{0}" or LocalIP contains "{0}") | summarize by DeviceName, LocalIP, RemoteIP, InitiatingProcessFileName | project-rename device=DeviceName, local=LocalIP, remoteip=RemoteIP, processname=InitiatingProcessFileName| take 10000'.format(search_item) # Paste your own query here
            elif bool(re.match(md5_regex, search_item)):
                search_event = '`File, Process, ImageLoad Events`\n- Search MD5, InitiatingProcessMD5'
                search_query = 'find in (DeviceFileEvents, DeviceProcessEvents, DeviceImageLoadEvents) where Timestamp > ago(30d) and (MD5 == "{0}" or InitiatingProcessMD5 == "{0}") | summarize by DeviceName, InitiatingProcessFileName | project-rename device=DeviceName, processname=InitiatingProcessFileName| take 10000'.format(search_item)
            elif bool(re.match(sha256_regex, search_item)):
                search_event = '`File, Process, Device, Registry, Network, ImageLoad Events`\n- Search SHA256, InitiatingProcessSHA256'
                search_query = 'find in (DeviceFileEvents, DeviceProcessEvents, DeviceEvents, DeviceRegistryEvents, DeviceNetworkEvents, DeviceImageLoadEvents) where Timestamp > ago(30d) and (SHA256 == "{0}" or InitiatingProcessSHA256 == "{0}") | summarize by DeviceName, InitiatingProcessFileName | project-rename device=DeviceName, processname=InitiatingProcessFileName| take 10000'.format(search_item)
            elif bool(validators.url(search_item)):
                search_event = '`Network, File Events`\n- Search RemoteUrl, FolderPath'
                search_query = 'find in (DeviceNetworkEvents, DeviceFileEvents) where Timestamp > ago(30d) and (RemoteUrl contains "{0}" or FolderPath contains "{0}") | summarize by DeviceName, RemoteUrl, FolderPath, InitiatingProcessFileName | project-rename device=DeviceName, remoteurl=RemoteUrl, folder=FolderPath, processname=InitiatingProcessFileName| take 10000'.format(search_item)
            elif bool(re.match(domain_regex, search_item)):
                search_event = '`Network, File Events`\n- Search RemoteUrl, FolderPath'
                search_query = 'find in (DeviceNetworkEvents, DeviceFileEvents) where Timestamp > ago(30d) and (RemoteUrl contains "{0}" or FolderPath contains "{0}") | summarize by DeviceName, RemoteUrl, FolderPath, InitiatingProcessFileName | project-rename device=DeviceName, remoteurl=RemoteUrl, folder=FolderPath, processname=InitiatingProcessFileName| take 10000'.format(search_item)
            elif search_item.startswith('cve-'):
                search_event = '`SoftwareVulnerabilities`\n- Search CveId'
                search_query = 'find in (DeviceTvmSoftwareVulnerabilities) where (CveId contains "{}") | project DeviceName, OSPlatform | project-rename device=DeviceName, os=OSPlatform| take 10000'.format(search_item)
            else:
                search_event = '`Process, ImageLoad Events`\n- Search ProcessCommandLine'
                search_query = 'find in (DeviceProcessEvents, DeviceImageLoadEvents) where Timestamp > ago(30d) and (ProcessCommandLine contains "{0}") | summarize by DeviceName, ProcessCommandLine, InitiatingProcessFolderPath, InitiatingProcessAccountName | project-rename device=DeviceName, commandline=ProcessCommandLine, processpath=InitiatingProcessFolderPath, account=InitiatingProcessAccountName| take 10000'.format(search_item)
            if search_query:
                main_result = mde_search(search_query, search_item, search_event)
            else:
                search_event = 'not match ioc type'
            print(main_result)