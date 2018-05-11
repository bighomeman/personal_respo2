#!/usr/bin/python
# -*- coding: utf-8 -*-

from bs4 import BeautifulSoup
import requests,time
from store_json import store_json
import blacklist_tools

def stopforumspam_toxic_ip_range():
    http = requests.get('http://www.stopforumspam.com/downloads/toxic_ip_range.txt')
    neir = http.text
    lines = neir.split('\n')
    del lines[-1]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        ip_dict[line] = {
            'subtype':'spam',
            'desc_subtype':'spam ip:{};source:http://www.stopforumspam.com/downloads/toxic_ip_range.txt'.format(line),
            'level':'INFO',
            'fp':'unknown',
            'status':'unknown',
            'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
        }
        # print ip_dict
    return ip_dict

def main():
    dict = stopforumspam_toxic_ip_range()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict, 'stopforumspam_toxic_ip_range')
    mylog.info("update spam!")

if __name__=="__main__":
    main()