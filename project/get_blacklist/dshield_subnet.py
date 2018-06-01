#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from project import blacklist_tools

# update per 15mins
def dshield_subnet():
    http = requests.get('http://feeds.dshield.org/block.txt',verify=False)
    neir = http.text
    lines = neir.split('\n')
    del lines[-1]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line or line == '' or 'Start' in line:
            continue
        else:
            #line is 'Start	End	Netmask	Attacks	Name	Country	email'
            linelis=line.split('\t')
            subnet=linelis[0].strip()+'/24'
            ip_dict[subnet] = {
                'subtype':'dshield_attacking_subnet',
                'desc_subtype':'dshield attacking subnet;source:http://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt',
                'level':'INFO',
                'fp':'unknown',
                'status':'unknown',
                'dport':-1,
                'mapping_ip':subnet,
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    dict = dshield_subnet()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict,'dshield_subnet')
    mylog.info("update dshield !")
    # print 'update successfully'

if __name__=="__main__":
    main()