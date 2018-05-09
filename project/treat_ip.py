#!/usr/bin/python
# -*- coding: utf-8 -*-
import re,json,sys,os
from blacklist_tools import *
from subnet_range import subnet_range
import socket,struct

def separate_ip(ipdict):
    regex1 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    regex2 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    regex3 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,2}$')
    iplist = ipdict.keys()
    full_match = {}
    segment = {}
    subnet = {}
    for ip_element in iplist:
        if regex1.match(ip_element):
            full_match[ip_element] = ipdict[ip_element]
        elif regex2.match(ip_element):
            segment[ip_element] = ipdict[ip_element]
        elif regex3.match(ip_element):
            subnet[ip_element] = ipdict[ip_element]
    # print len(full_match_dict)
    # print len(segment)
    # print len(subnet)
    # saveAsJSON(date, full_match, path, 'full_match')
    # saveAsJSON(date, segment, path, 'segment')
    # saveAsJSON(date, subnet, path, 'subnet')
    return full_match,segment,subnet

def separate_ip_lpm(ipdict):
    regex_exactly = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$')
    regex_segment_8 = re.compile('^\d{1,3}\.0\.0\.0\-\d{1,3}\.255\.255\.255$')
    regex_segment_16 = re.compile('^\d{1,3}\.\d{1,3}\.0\.0\-\d{1,3}\.\d{1,3}\.255\.255$')
    regex_segment_24 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.0\-\d{1,3}\.\d{1,3}\.\d{1,3}\.255$')
    regex_subnet_8 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/8$')
    regex_subnet_16 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/16$')
    regex_subnet_24 = re.compile('^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/24$')
    iplist = ipdict.keys()
    full_match = {}
    ip_8 = {}
    ip_16 = {}
    ip_24 = {}
    for ip_element in iplist:
        if regex_exactly.match(ip_element):
            full_match[ip_element] = ipdict[ip_element]
        elif regex_segment_8.match(ip_element) or regex_subnet_8.match(ip_element):
            ip_rule_8 = ip_element.split('.')[0]+'.*.*.*'
            ip_8[ip_rule_8] = ipdict[ip_element]
        elif regex_segment_16.match(ip_element) or regex_subnet_16.match(ip_element):
            ip_rule_16 = ip_element.split('.')[0]+'.'+ip_element.split('.')[1]+'.*.*'
            ip_16[ip_rule_16] = ipdict[ip_element]
        elif  regex_segment_24.match(ip_element) or regex_subnet_24.match(ip_element):
            ip_rule_24 = ip_element.split('.')[0]+'.'+ip_element.split('.')[1]+'.'+ip_element.split('.')[2]+'.*'
            ip_24[ip_rule_24] = ipdict[ip_element]
    return full_match,ip_8,ip_16,ip_24


#only fit in XXX.XXX.XXX.XXX-XXX.XXX.XXX.XXX
# return:  ip_int={
#     "AAA.AAA.AAA.AAA-BBB.BBB.BBB.BBB":{
#         "start":"AAA.AAA.AAA.AAA",
#         "end":"BBB.BBB.BBB.BBB"
#           }
#   ......
# }
def int_ip_range(segment,es_ip):
    #segment
    ip_segment = segment.keys()
    ip_int = {}
    for element in ip_segment:
        ip_int[element]={}
        ip_num = []
        ip_segment = element.split('-')
        A = ip_segment[0]
        B = ip_segment[1]
        num_ip_A=socket.ntohl(struct.unpack("I",socket.inet_aton(str(A)))[0])
        num_ip_B=socket.ntohl(struct.unpack("I",socket.inet_aton(str(B)))[0])
        ip_int[element]["start"]=num_ip_A
        ip_int[element]['end']=num_ip_B
        # ip_num.append(num_ip_A)
        # ip_num.append(num_ip_B)
        # ip_int.append(ip_num)
    #match
    segment_match=[]
    for ip_str in es_ip:
        flg=ip_segment_match(ip_int, ip_str)
        if(flg):
            segment_match.append(flg)
    return segment_match

#only for subnet number range
# return:  ip_int={
#     "AAA.AAA.AAA.AAA/XX":{
#         "start":"AAA.AAA.AAA.AAA",
#         "end":"BBB.BBB.BBB.BBB"
#           }
#   ......
# }
def int_ip_subnet_lpm(subnet,es_ip):
    #return lpm : lpm=subnet_range()
    # subnet
    ip_subnet = subnet.keys()
    if len(ip_subnet)>0:
        subnet_msg=subnet[ip_subnet[0]]
    else:
        subnet_msg={}
    subnet_match,snlist = subnet_range(ip_subnet, es_ip)
    return subnet_match,subnet_msg,snlist



	
def ip_segment_match(num_iprange, ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    for ip_range in num_iprange.keys():
        # print ip_range[0], ip_range[1]
        if(long(num_iprange[ip_range]["start"])<=ip_es_num<=long(num_iprange[ip_range]["end"])):
            return {ip_es:ip_range}
        # if ip_range[0] <= ip_es_num <=ip_range[1]:
        #     return ip_es
    return False

def ip_subnet_match(sublpm,es_ip):
    ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(es_ip)))[0])
    return sublpm.search_ip(ip_es_num)

def ip_full_match(full_list,ip_es_list):
    match_result = set(full_list) & set(ip_es_list)
    return list(match_result)

# if __name__=="__main__":
#     subnet = load_dict('.\data\\subnet-2018-03-23.json')
#     ip_int = int_ip_subnet(subnet)
#     # print ip_int
#     # segment = load_dict('.\data\\segment-2018-03-23.json')
#     # ip_int = int_ip_range(segment)
#     ip_es = '192.166.156.253'
#     ip_segment_match(ip_int, ip_es)