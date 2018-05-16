#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests,time
from store_json import store_json
import blacklist_tools

def firehol_level1():
    http = requests.get('http://iplists.firehol.org/files/firehol_level1.netset')
    neir = http.text
    lines = neir.split('\n')
    del lines[-1]
    ip_dict = {}
    for line in lines:
        # print line
        ip_dict[line] = {
            'subtype':'suspect',
            'desc_subtype':'suspect ip;source:iplists.firehol.org/files/firehol_level1.netset',
            'level':'INFO',
            'fp':'unknown',
            'status':'unknown',
            'dport': -1,
            'mapping_ip': line,
            'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
        }
    return ip_dict

def main():
    dict = firehol_level1()
    mylog=blacklist_tools.getlog()
    print len(dict.keys())
    store_json(dict, 'firehol_level1')
    mylog.info("update firehol!")

if __name__=="__main__":
    main()