#!/usr/bin/python
# -*- coding: utf-8 -*-
import re,json,sys,os
from blacklist_tools import *
from subnet_range import subnet_range
import parser_config
import socket,struct

def seperate_ip(date,ipdict,path):
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
    saveAsJSON(date, full_match, path, 'full_match')
    saveAsJSON(date, segment, path, 'segment')
    saveAsJSON(date, subnet, path, 'subnet')



#only fit in XXX.XXX.XXX.XXX-XXX.XXX.XXX.XXX
def int_ip_range(segment_element):
    ip_int = []
    ip_num = []
    ip_segment = segment_element.split('-')
    A = ip_segment[0]
    B = ip_segment[1]
    num_ip_A=socket.ntohl(struct.unpack("I",socket.inet_aton(str(A)))[0])
    num_ip_B=socket.ntohl(struct.unpack("I",socket.inet_aton(str(B)))[0])
    ip_num.append(num_ip_A)
    ip_num.append(num_ip_B)
    ip_int.append(ip_num)
    return ip_int

#only for subnet number range
def int_ip_subnet(subnet_element):
    ip_int = []
    avaliable_ip = subnet_range(subnet_element)
    ip_int_element = []
    num_ip_A = socket.ntohl(struct.unpack("I",socket.inet_aton(avaliable_ip[0]))[0])
    # print avaliable_ip[0],num_ip_A
    num_ip_B = socket.ntohl(struct.unpack("I",socket.inet_aton(avaliable_ip[1]))[0])
    # print avaliable_ip[1],num_ip_B
    ip_int_element.append(num_ip_A)
    ip_int_element.append(num_ip_B)
    ip_int.append(ip_int_element)
    return ip_int



def ip_segment_match(segment,ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    num_iprange = int_ip_range(segment)
    for ip_es_num in num_iprange:
        # print ip_range[0], ip_range[1]
        if num_iprange[0] <= ip_es_num <= num_iprange[1]:
            return ip_es
    return False

def ip_subnet_match(subnet,ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    num_iprange = int_ip_subnet(subnet)
    for ip_es_num in num_iprange:
        # print ip_range[0], ip_range[1]
        if num_iprange[0] <= ip_es_num <=num_iprange[1]:
            return ip_es
    return False


def ip_full_match(full_list,ip_es_list):
    match_result = set(full_list) & set(ip_es_list)
    match_list = list(match_result)
    return match_list

if __name__=="__main__":
    subnet = load_dict('.\data\\subnet-2018-03-23.json')
    ip_int = int_ip_subnet(subnet)
    # print ip_int
    # segment = load_dict('.\data\\segment-2018-03-23.json')
    # ip_int = int_ip_range(segment)
    ip_es = '192.166.156.253'
