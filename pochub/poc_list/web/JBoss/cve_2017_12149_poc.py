#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/12 19:39
# Author     : yunkong
# FileName   : cve_2017_12149_poc.py
# Description:
#
# Exploit Title: JBoss 5.x/6.x 反序列化漏洞（CVE-2017-12149）
# Version: JBoss 5.x/6.x
# CVE: CVE-2017-12149

import requests
import urllib3

urllib3.disable_warnings()  # 忽略https证书告警


def check_cve_2017_12149(target_url):
    vulurl = target_url + "/invoker/readonly"

    headers = {
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
        'Content-Type': "application/json"
    }

    try:
        r = requests.post(vulurl, headers=headers, verify=False)
        e = r.status_code
    except:
        print(f"[-] Target: {target_url} error！！！")
        return False
    if e == 500:
        print(f"[+] Target: {target_url} CVE-2017-12149 may exist！！！")
        return True
    else:
        print(f"[-] Target: {target_url} CVE-2017-12149 may not exist！！！")
        return False


def vuln_scan_start(target_url):
    check_cve_2017_12149(target_url)

# vuln_scan_start("http://192.168.12.130:8080")
