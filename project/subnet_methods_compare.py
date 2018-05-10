#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh
import lpm
import json
from subnet_range import ip_split_num
import socket
import struct
import subnet_range
import time
import blacklist_tools
import os
import datetime

def lpmtest(subnet,subdata):
    ip_subnet = subnet.keys()
    for sn in ip_subnet:
        subnet_split = sn.split('/')
        ip_num = ip_split_num(subnet_split[0])
        netMask = int(subnet_split[1])
        if (netMask == 16):
            newip1 = []
            ip_num[2] = ip_num[2] | 1
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append('*')
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
        elif (netMask == 23):
            newip1 = []
            ip_num[2] = ip_num[2] | 1
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append(str(ip_num[2]))
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
            newip2 = []
            ip_num[2] = ip_num[2] & 0
            newip2.append(str(ip_num[0]))
            newip2.append(str(ip_num[1]))
            newip2.append(str(ip_num[2]))
            newip2.append('*')
            ipstr2 = '.'.join(newip2)
            lpm.insert_rule(ipstr2)
        elif (netMask == 25 or netMask == 24):
            # /25 /24
            newip1 = []
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append(str(ip_num[2]))
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)

    #match
    subnet_result = []
    for ips in subdata:
        ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
        if (lpm.search_ip(ip_es_num)):
            subnet_result.append({ips: 'subnet_lpm_match'})
    return subnet_result

def subnetrangetest(subnet,subdata):
    results=subnet_range.subnet_range_match(subnet,{},subdata)

if __name__ == '__main__':
    tday = datetime.datetime.now().date()
    fpath=os.getcwd()+os.path.sep+'data'+os.path.sep+'lpm_subnet_data'+'-'+str(tday)+'.json'
    subnet=blacklist_tools.load_dict(fpath)
    subdata=['']
    st1=time.time()
    lpmresult=lpmtest(subnet,subdata)
    en1=time.time()
    print 'lpm times:',en1-st1
    print'-----------------------------------'
    st2=time.time()
    rangeresult=subnetrangetest(subnet,subdata)
    en2=time.time()
    print 'range times:',en2-st2
    print '-------------------------------------'
    print 'lpm result:\n'
    for i in lpmresult:
        print i
    print 'range result:\n'
    for ii in rangeresult:
        print ii