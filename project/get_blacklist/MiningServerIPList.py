#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests
from store_json import store_json
from lxml import etree
from project import blacklist_tools


def MiningServerIPList(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('https://github.com/ZeroDot1/CoinBlockerLists/blob/master/MiningServerIPList.txt',verify=False,timeout=120)
        neir = http.text
        html = etree.HTML(neir)
        result = html.xpath('//td[starts-with(@id,"LC")]/text()')
        time_source = result[4]
        time_mediate =time_source.split(' ')
        date = time_mediate[5]+'-'+time_mediate[4]+'-'+time_mediate[3]
        del result[:7]
    except Exception,e:
        mylog.warning("download timeout!!!")
        result=[]
        date=''
    ip_dict = {}
    for ip in result:
        ip_dict[ip] ={
            'subtype':'mining_pool',
            'desc_subtype':'mining pool ip;source:github.com/ZeroDot1/CoinBlockerLists/blob/master/MiningServerIPList',
            'level':'INFO',
            'fp':'unknown',
            'status':'unknown',
            'dport': -1,
            'mapping_ip': ip,
            'date':date
        }
    return ip_dict

def main():
    mylog=blacklist_tools.getlog()
    dict = MiningServerIPList(mylog)
    print len(dict.keys())
    store_json(dict, 'MiningServerIPList')
    mylog.info("update mining pool!")

if __name__=="__main__":
    main()