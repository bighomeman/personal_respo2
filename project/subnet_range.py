#!/usr/bin/python
# -*- coding: utf-8 -*-
import blacklist_tools
import json
import parser_config
import datetime
import lpm
import socket,struct
import blacklist_tools
import os

def getsavepath(fpath,name):
    tday = datetime.datetime.now().date()
    file_name = fpath + name + '_' + str(tday) + '.json'
    return file_name

def saveToJSON(dict1,path,name):
    "add the subnet to file"
    mylog=blacklist_tools.getlog()
    file_name = getsavepath(path,name)
    try:
        with open(file_name,'w') as f:
            f.write(json.dumps(dict1))
    except IOError:
        print 'save Error'
        mylog.error('saveToJSON Error!')


def ip_split_num(ip):
    ip_num = ip.split('.')
    for i in range(len(ip_num)):
        ip_num[i] = int(ip_num[i])
    return ip_num

def subnet_to_binary(num):
    nm_binary = num*'1'+(32-num)*'0'
    nm_num = []
    for i in range(4):
        temp =  nm_binary[8*(i):8*(i+1)]
        ip_pot = 0
        for j in range(len(temp)):
            ip_pot = ip_pot + (int(temp[j])*(2**(7-j)))
            if j == 7:
                nm_num.append(int(ip_pot))
    return nm_num

#ip is string for single xxx.xxx.xxx.xxx/XX, subnet is number
def subnet_lpm(subnet,es_ip):
    mylog=blacklist_tools.getlog()
    lpm.init()
    sndict = {}
    fpath = parser_config.get_store_path()[1]
    sn_lte16 = {}
    lpmdict={}
    ip_subnet=subnet.keys()
    for sn in ip_subnet:
        subnet_split = sn.split('/')
        ip_num = ip_split_num(subnet_split[0])
        netMask = int(subnet_split[1])
        if(sn=='192.168.0.0/16'or sn=='172.16.0.0/12' or sn=='10.0.0.0/8'):#略过私网
            continue
            # return 'False'
        elif(netMask<16):#暂时不处理
            sn_lte16[sn]=subnet[sn]
            # return 'False'
        elif(netMask==16):
            lpmdict[sn]=subnet[sn]
            newip1 = []
            ip_num[2] = ip_num[2] | 1
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append('*')
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
        elif(netMask==23):
            lpmdict[sn] = subnet[sn]
            newip1=[]
            ip_num[2]=ip_num[2]|1
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append(str(ip_num[2]))
            newip1.append('*')
            ipstr1='.'.join(newip1)
            lpm.insert_rule(ipstr1)
            newip2=[]
            ip_num[2]=ip_num[2]&254
            newip2.append(str(ip_num[0]))
            newip2.append(str(ip_num[1]))
            newip2.append(str(ip_num[2]))
            newip2.append('*')
            ipstr2='.'.join(newip2)
            lpm.insert_rule(ipstr2)
        elif(netMask==25 or netMask==24):
            #/25当/24处理
            lpmdict[sn] = subnet[sn]
            newip1 = []
            newip1.append(str(ip_num[0]))
            newip1.append(str(ip_num[1]))
            newip1.append(str(ip_num[2]))
            newip1.append('*')
            ipstr1 = '.'.join(newip1)
            lpm.insert_rule(ipstr1)
        else:
            #netMask>16 and not in [16,23,24,25],save them
            sndict[sn]=subnet[sn]

    mylog.info('lpm data size: %d'%len(lpmdict))
    #save
    snpath=getsavepath(fpath,'remain_subnet')
    ltepath=getsavepath(fpath,'lte16_subnet')
    lpmpath=getsavepath(fpath,'lpm_subnet_data')
    if(os.path.exists(snpath)):
        newsndict=blacklist_tools.load_dict(snpath)
        newsndict1=dict(newsndict,**sndict)#merge
        saveToJSON(newsndict1, fpath, "remain_subnet")
    else:
        saveToJSON(sndict, fpath,"remain_subnet")
    if(os.path.exists(ltepath)):
        newlte=blacklist_tools.load_dict(ltepath)
        newlte16=dict(newlte,**sn_lte16)#merge
        saveToJSON(newlte16, fpath, 'lte16_subnet')
    else:
        saveToJSON(sn_lte16,fpath,'lte16_subnet')
    if(os.path.exists(lpmpath)):
        newlpmdict=blacklist_tools.load_dict(lpmpath)
        newlpmdict1=dict(newlpmdict,**lpmdict)#merge
        saveToJSON(newlpmdict1, fpath, 'lpm_subnet_data')
    else:
        saveToJSON(lpmdict,fpath,'lpm_subnet_data')
    #match
    subnet_result=[]
    for ips in es_ip:
        ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
        if(lpm.search_ip(ip_es_num)):
            subnet_result.append({ips:'subnet_lpm_match'})
    return subnet_result, sndict, sn_lte16

# zhou
def subnet_range_match(sndict,sn_lte16,es_ip):
    sndict_list = []
    for ips in es_ip:
        ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ips)))[0])
        for key in sndict:
            subnet_num = subnet_range(key)
            # print subnet_num[0],subnet_num[1]
            subnet_num_min = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[0])))[0])
            subnet_num_max = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[1])))[0])
            if subnet_num_min <= ip_es_num <= subnet_num_max:
                sndict_list.append({ips:key})
        for key in sn_lte16:#key is ip
            subnet_num = subnet_range(key)
            # print subnet_num[0],subnet_num[1]
            subnet_num_min = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[0])))[0])
            subnet_num_max = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[1])))[0])
            if subnet_num_min <= ip_es_num <= subnet_num_max:
                sndict_list.append({ips:key})
    return sndict_list

def subnet_range(subnet):
    subnet_split = subnet.split('/')
    ip_num = ip_split_num(subnet_split[0])
    netMask = int(subnet_split[1])
    nm_num = subnet_to_binary(netMask)
    firstadr = []
    lastadr = []
    ip_range = []
    if netMask == 31:
        firstadr.append(str(ip_num[0] & nm_num[0]))
        firstadr.append(str(ip_num[1] & nm_num[1]))
        firstadr.append(str(ip_num[2] & nm_num[2]))
        firstadr.append(str(ip_num[3] & nm_num[3]))

        lastadr.append(str(ip_num[0] | (~ nm_num[0] & 0xff)))
        lastadr.append(str(ip_num[1] | (~ nm_num[1] & 0xff)))
        lastadr.append(str(ip_num[2] | (~ nm_num[2] & 0xff)))
        lastadr.append(str(ip_num[3] | (~ nm_num[3] & 0xff)))
        begin_addr = '.'.join(firstadr)
        end_addr = '.'.join(lastadr)
        ip_range.append(begin_addr)
        ip_range.append(end_addr)

    elif netMask == 32:
        firstadr.append(str(ip_num[0]))
        firstadr.append(str(ip_num[1]))
        firstadr.append(str(ip_num[2]))
        firstadr.append(str(ip_num[3]))

        lastadr.append(str(ip_num[0]))
        lastadr.append(str(ip_num[1]))
        lastadr.append(str(ip_num[2]))
        lastadr.append(str(ip_num[3]))
        begin_addr = '.'.join(firstadr)
        end_addr = '.'.join(lastadr)
        ip_range.append(begin_addr)
        ip_range.append(end_addr)
    else:
        lastadr.append(str(ip_num[0] | (~ nm_num[0] & 0xff)))
        lastadr.append(str(ip_num[1] | (~ nm_num[1] & 0xff)))
        lastadr.append(str(ip_num[2] | (~ nm_num[2] & 0xff)))
        lastadr.append(str((ip_num[3] | (~ nm_num[3] & 0xff))-1))

        firstadr.append(str(ip_num[0] & nm_num[0]    ))
        firstadr.append(str(ip_num[1] & nm_num[1]    ))
        firstadr.append(str(ip_num[2] & nm_num[2]    ))
        firstadr.append(str((ip_num[3] & nm_num[3])+1))
        begin_addr = '.'.join(firstadr)
        end_addr = '.'.join(lastadr)
        ip_range.append(begin_addr)
        ip_range.append(end_addr)

    return ip_range
