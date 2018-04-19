#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from store_json import store_json
from lxml import etree


def MiningServerIPList():
    http = requests.get('https://github.com/ZeroDot1/CoinBlockerLists/blob/master/MiningServerIPList.txt')
    neir = http.text
    html = etree.HTML(neir)
    result = html.xpath('//td[starts-with(@id,"LC")]/text()')
    time_source = result[4]
    time_mediate =time_source.split(' ')
    date = time_mediate[5]+'-'+time_mediate[4]+'-'+time_mediate[3]
    del result[:7]
    ip_dict = {}
    for ip in result:
        ip_dict[ip] ={
            'type':'mining pool',
            'source':'bitnodes.earn.com/api/v1/snapshots/latest/',
            'level':'CRITICAL',
            'fp':'unknown',
            'status':'unknown',
            'date':date
        }
    return ip_dict

if __name__=="__main__":
    dict = MiningServerIPList()
    print len(dict.keys())
    store_json(dict,'MiningServerIPList')