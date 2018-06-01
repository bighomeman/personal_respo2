#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from project import blacklist_tools

# update per 30mins
def ZeuS_ip():
    http = requests.get('https://zeustracker.abuse.ch/blocklist.php?download=badips',verify=False)
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
                'subtype':'ZeuS_trojan',
                'desc_subtype':'ZeuS trojan ip;source:https://sslbl.abuse.ch/blacklist/sslipblacklist.csv',
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
    dict = ZeuS_ip()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict,'ZeuS_ip')
    mylog.info("update ZeuS_ip!")
    # print 'update successfully'

if __name__=="__main__":
    main()