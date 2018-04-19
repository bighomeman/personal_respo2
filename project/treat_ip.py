#!/usr/bin/python
# -*- coding: utf-8 -*-
import re,json,sys,os
from blacklist_tools import *
from subnet_range import subnet_range
import parser_config
import socket,struct

#only fit in XXX.XXX.XXX.XXX-XXX.XXX.XXX.XXX
def int_ip_range(segment_element):
    ip_num = []
    ip_segment = segment_element.split('-')
    A = ip_segment[0]
    B = ip_segment[1]
    num_ip_A=socket.ntohl(struct.unpack("I",socket.inet_aton(str(A)))[0])
    num_ip_B=socket.ntohl(struct.unpack("I",socket.inet_aton(str(B)))[0])
    ip_num.append(num_ip_A)
    ip_num.append(num_ip_B)
    return ip_num

#only for subnet number range
def int_ip_subnet(subnet_element):
    avaliable_ip = subnet_range(subnet_element)
    ip_int_element = []
    num_ip_A = socket.ntohl(struct.unpack("I",socket.inet_aton(avaliable_ip[0]))[0])
    # print avaliable_ip[0],num_ip_A
    num_ip_B = socket.ntohl(struct.unpack("I",socket.inet_aton(avaliable_ip[1]))[0])
    # print avaliable_ip[1],num_ip_B
    ip_int_element.append(num_ip_A)
    ip_int_element.append(num_ip_B)
    return ip_int_element

def ip_segment_match(segment,ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    num_iprange = int_ip_range(segment)
    if num_iprange[0] <= ip_es_num <= num_iprange[1]:
        return ip_es
    return False

def ip_subnet_match(subnet,ip_es):
    ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ip_es)))[0])
    num_iprange = int_ip_subnet(subnet)
    if num_iprange[0] <= ip_es_num <=num_iprange[1]:
        return ip_es
    return False

def ip_full_match(full_list,ip_es_list):
    match_result = set(full_list) & set(ip_es_list)
    match_list = list(match_result)
    return match_list

if __name__=="__main__":
    subnet = load_dict('.\data\\subnet-2018-03-23.json')
    for subnet_element in subnet:
        ip_int = int_ip_subnet(subnet_element)
        print ip_int
    # segment = load_dict('.\data\\segment-2018-03-23.json')
    # ip_int = int_ip_range(segment)