#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from project import blacklist_tools

# update per 15mins
def ssl_abuse():
    http = requests.get('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',verify=False)
    neir = http.text
    lines = neir.split('\n')
    del lines[-1]
    # print lines
    ip_dict = {}
    for line in lines:
        # print line
        if '#' in line:
            continue
        else:
            lis=line.split(',')# line = 'DstIP,DstPort,Reason' -> lis =[DstIP,DstPort,Reason]
            ip_dict[lis[0]] = {
                'subtype':lis[2].strip().replace(' ','_'),
                'desc_subtype':'{} ip;source:https://sslbl.abuse.ch/blacklist/sslipblacklist.csv'.format(lis[2]),
                'level':'INFO',
                'fp':'unknown',
                'status':'unknown',
                'dport':int(lis[1]),
                'mapping_ip':lis[0],
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    dict = ssl_abuse()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict,'ssl_abuse')
    mylog.info("update ssl_abuse!")
    # print 'update successfully'

if __name__=="__main__":
    main()