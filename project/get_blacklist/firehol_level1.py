#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests,time
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
            'level':'INFO',
            'fp':'unknown',
            'status':'unknown',
            'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
        }
    return ip_dict

def main():
    dict = firehol_level1()
    print len(dict.keys())
    store_json(dict, 'firehol_level1')

if __name__=="__main__":
    main()