#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from project import blacklist_tools

# update per 15mins
def ssl_abuse(mylog):
    requests.adapters.DEFAULT_RETRIES = 5
    try:
        http = requests.get('https://sslbl.abuse.ch/blacklist/sslipblacklist.csv', verify=False,timeout=120)
        neir = http.text
        lines = neir.split('\n')
        del lines[-1]
    except Exception, e:
        mylog.warning("download timeout!!!")
        lines=[]
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
    mylog=blacklist_tools.getlog()
    dict = ssl_abuse(mylog)
    print len(dict)
    store_json(dict,'ssl_abuse')
    mylog.info("update ssl_abuse!")
    # print 'update successfully'

if __name__=="__main__":
    main()