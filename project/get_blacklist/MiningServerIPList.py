#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from store_json import store_json
from lxml import etree
import blacklist_tools


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
            'type':'mining_pool',
            'source':'github.com/ZeroDot1/CoinBlockerLists/blob/master/MiningServerIPList',
            'level':'INFO',
            'fp':'unknown',
            'status':'unknown',
            'date':date
        }
    return ip_dict

def main():
    dict = MiningServerIPList()
    mylog=blacklist_tools.getlog()
    print len(dict.keys())
    store_json(dict, 'MiningServerIPList')
    mylog.info("update mining pool!")

if __name__=="__main__":
    main()