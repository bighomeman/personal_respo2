#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh

#update per 60mins
import requests,time
from store_json import store_json
from project import blacklist_tools


def bambenek_ip():
    http = requests.get('http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt',verify=False)
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
            linelist=line.split(',')# line = ' ip,type,date,source'
            subtype=linelist[1].split('by')[1].strip().replace(' ','_')
            ip_dict[linelist[0]] = {
                'subtype':subtype,
                'desc_subtype':'{} ip;source:http://osint.bambenekconsulting.com/feeds/c2-ipmasterlist.txt'.format(subtype),
                'level':'INFO',
                'fp':'unknown',
                'status':'unknown',
                'dport':-1,
                'mapping_ip':linelist[0],
                'date' : time.strftime('%Y-%m-%d',time.localtime(time.time()))
            }
        # print ip_dict
    return ip_dict

def main():
    dict = bambenek_ip()
    mylog=blacklist_tools.getlog()
    print len(dict)
    store_json(dict,'bambenek_ip')
    mylog.info("update bambenek_ip!")
    # print 'update successfully'

if __name__=="__main__":
    main()