#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from project import blacklist_tools

# update per 240mins
def bogons_ip():
    http = requests.get('http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt')
    neir = http.text
    lines = neir.split('\n')
    del lines[-1]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line or line == '':
            continue
        else:
            ip_dict[line] = {
                'subtype':'bogons_subnet',
                'desc_subtype':'bogons subnet;source:http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt',
                'level':'INFO',
                'fp':'unknown',
                'status':'unknown',
                'dport':-1,
                'mapping_ip':line,
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    dict = bogons_ip()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict,'bogons')
    mylog.info("update bogons_ip!")
    # print 'update successfully'

if __name__=="__main__":
    main()