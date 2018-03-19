#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from store_json import store_json

def firehol_level1():
    http = requests.get('http://iplists.firehol.org/files/firehol_level1.netset')
    neir = http.text
    lines = neir.split('\n')
    del lines[-1]
    ip_dict = {}
    for line in lines:
        # print line
        ip_dict[line] = {
            'type':'fire',
            'source':'iplists.firehol.org/files/firehol_level1.netset',
            'level':'CRITICAL',
            'fp':'unknown',
            'status':'unknown'
        }
    return ip_dict

if __name__=="__main__":
    dict = firehol_level1()
    print len(dict.keys())
    store_json(dict,'firehol_level1')