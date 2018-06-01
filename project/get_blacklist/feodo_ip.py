#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

import requests,time
from store_json import store_json
from project import blacklist_tools

# update per 5mins
def feodo_ip():
    http = requests.get('https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',verify=False)
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
            ip_dict[line] = {
                'subtype':'Feodo_C&C',
                'desc_subtype':'Feodo C&C ip;source:https://feodotracker.abuse.ch/blocklist/?download=ipblocklist',
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
    dict = feodo_ip()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict,'feodo_ip')
    mylog.info("update ssl_abuse!")
    # print 'update successfully'

if __name__=="__main__":
    main()