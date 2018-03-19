#!/usr/bin/python
# -*- coding: utf-8 -*-
import re,json,sys,os
from blacklist_tools import *
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
def int_ip_range(segment):
    ip_segment = segment.keys()
    ip_int = []
    for element in ip_segment:
        ip_num = []
        ip_segment = element.split('-')
        A = ip_segment[0]
        B = ip_segment[1]
        num_ip_A=socket.ntohl(struct.unpack("I",socket.inet_aton(str(A)))[0])
        num_ip_B=socket.ntohl(struct.unpack("I",socket.inet_aton(str(B)))[0])
        ip_num.append(num_ip_A)
        ip_num.append(num_ip_B)
        ip_int.append(ip_num)
    return ip_int

#def insert_sort(array):
#    for i in range(len(array)):
#        for j in range(i):
#            if array[i][0] < array[j][0]:
#                array.insert(j, array.pop(i))
#                break
#    return array

	
def ip_segment_match(num_segment, ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    ip_range_num = int_ip_range(num_segment)

    for ip_range in ip_range_num:
        if ip_range[0] <= ip_es_num <=ip_range[0]:
            return ip_es
    return False

def ip_full_match(full_list,ip_es_list):
    match_result = set(full_list) & set(ip_es_list)
    return match_result
