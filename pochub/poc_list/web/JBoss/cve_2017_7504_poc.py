#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/12 21:19
# Author     : yunkong
# FileName   : cve_2017_7504_poc.py
# Description:
#
# Exploit Title: JBoss 4.x JBossMQ JMS 反序列化漏洞（CVE-2017-7504）
# Version: JBoss 4.x
# CVE: CVE-2017-7504
import requests
import urllib3

urllib3.disable_warnings()  # 忽略https证书告警


def check_cve_2017_12149(target_url):
    vulurl = target_url + "/jbossmq-httpil/HTTPServerILServlet"

    headers = {
        'User-Agent': "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.14; rv:63.0) Gecko/20100101 Firefox/63.0",
        'Content-Type': "application/json"
    }

    try:
        r = requests.post(vulurl, headers=headers, verify=False)
        e = r.status_code
    except:
        return False
    if e == 200:
        print(f"[+] Target: {target_url} CVE-2017-7504 may exist！！！")
        return True
    else:
        print(f"[-] Target: {target_url} CVE-2017-7504 may not exist！！！")
        return False


def vuln_scan_start(target_url):
    check_cve_2017_12149(target_url)


vuln_scan_start("http://192.168.12.130:8080")
