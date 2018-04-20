#!/usr/bin/python
# -*- coding: utf-8 -*-
import re,json,sys,os
from blacklist_tools import *
from subnet_range import subnet_range
import parser_config
import socket,struct

def seperate_ip(ipdict):
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



#only fit in XXX.XXX.XXX.XXX-XXX.XXX.XXX.XXX
# return:  ip_int={
#     "AAA.AAA.AAA.AAA-BBB.BBB.BBB.BBB":{
#         "start":"AAA.AAA.AAA.AAA",
#         "end":"BBB.BBB.BBB.BBB"
#           }
#   ......
# }
def int_ip_range(segment):
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
    return ip_int

#only for subnet number range
# return:  ip_int={
#     "AAA.AAA.AAA.AAA/XX":{
#         "start":"AAA.AAA.AAA.AAA",
#         "end":"BBB.BBB.BBB.BBB"
#           }
#   ......
# }
def int_ip_subnet(subnet):
    ip_subnet = subnet.keys()
    ip_int = {}
    for ip_nm in ip_subnet:
        ip_int[ip_nm]={}
        avaliable_ip = subnet_range(ip_nm)
        ip_int_element = []
        try:
            num_ip_A = socket.ntohl(struct.unpack("I",socket.inet_aton(avaliable_ip["start"]))[0])
        except Exception,e:
            print e
        # print avaliable_ip[0],num_ip_A
        try:
            num_ip_B = socket.ntohl(struct.unpack("I",socket.inet_aton(avaliable_ip["end"]))[0])
        except Exception,e:
            print e
        # print avaliable_ip[1],num_ip_B
        ip_int[ip_nm]["start"]=num_ip_A
        ip_int[ip_nm]['end']=num_ip_B
        # ip_int_element.append(num_ip_A)
        # ip_int_element.append(num_ip_B)
        # ip_int.append(ip_int_element)
    return ip_int


	
def ip_segment_match(num_iprange, ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    for ip_range in num_iprange.keys():
        # print ip_range[0], ip_range[1]
        if(long(num_iprange[ip_range]["start"])<=ip_es_num<=long(num_iprange[ip_range]["end"])):
            return {ip_es:ip_range}
        # if ip_range[0] <= ip_es_num <=ip_range[1]:
        #     return ip_es
    return False

def ip_full_match(full_list,ip_es_list):
    match_result = set(full_list) & set(ip_es_list)
    return match_result

if __name__=="__main__":
    subnet = load_dict('.\data\\subnet-2018-03-23.json')
    ip_int = int_ip_subnet(subnet)
    # print ip_int
    # segment = load_dict('.\data\\segment-2018-03-23.json')
    # ip_int = int_ip_range(segment)
    ip_es = '192.166.156.253'
    ip_segment_match(ip_int, ip_es)