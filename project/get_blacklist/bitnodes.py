#!/usr/bin/python
# -*- coding: utf-8 -*-

import requests , re, json,time
from store_json import store_json
from project import blacklist_tools


def bitnodes(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    http = requests.get('https://bitnodes.earn.com/api/v1/snapshots/latest/',verify=False)
    neir = http.text
    mylog.info('load json data from html.')
    try:
        neir_json = json.loads(neir)
    except Exception,e:
        mylog.error('load json ERROR')
    result = neir_json['nodes'].keys()
    ip_dict = {}
    mylog.info('restructure data.')
    for ip_port in result:
        iplis = ip_port.split(':')# iplis=[ip,port]
        if(str.isdigit(str(iplis[1]))):
            ip_dict[iplis[0]] ={
                'subtype':'mining_pool',
                'desc_subtype':'mining pool ip;source:bitnodes.earn.com/api/v1/snapshots/latest/',
                'level':'INFO',
                'fp':'unknown',
                'status':'unknown',
                'dport': int(iplis[1]),
                'mapping_ip': iplis[0],
                'date': timestamp_datetime(neir_json['nodes'][ip_port][2])
            }
    return ip_dict

def timestamp_datetime(value):
    format = '%Y-%m-%d'
    # value为传入的值为时间戳(整形)，如：1332888820
    value = time.localtime(value)
    ## 经过localtime转换后变成
    ## time.struct_time(tm_year=2012, tm_mon=3, tm_mday=28, tm_hour=6, tm_min=53, tm_sec=40, tm_wday=2, tm_yday=88, tm_isdst=0)
    # 最后再经过strftime函数转换为正常日期格式。
    dt = time.strftime(format, value)
    return dt

def main():
    mylog = blacklist_tools.getlog()
    mylog.info('download bitnodes...')
    dict = bitnodes(mylog)
    mylog.info('bitnodes size:{}'.format(len(dict.keys())))
    store_json(dict, 'bitnodes')
    mylog.info("update bitnodes!")

if __name__=="__main__":
    main()