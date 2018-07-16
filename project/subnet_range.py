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
    #socket.inet_ntoa(struct.pack('I',socket.ntohl(int(nm_binary,2)))).split('.')  -> nm_num
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
    sn_gte24={}
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
        elif(netMask>=21 and netMask<=24):
            lpmdict[sn] = subnet[sn]
            idx = pow(2, 24 - netMask) - 1
            # print idx
            ip_base = ip_num[2] & (255 - idx)
            i = 0
            while (i <= idx):
                newip1 = []
                ipstr1 = ''
                ip_num[2] = ip_base + i
                newip1.append(str(ip_num[0]))
                newip1.append(str(ip_num[1]))
                newip1.append(str(ip_num[2]))
                newip1.append('*')
                ipstr1 = '.'.join(newip1)
                # print ipstr1
                lpm.insert_rule(ipstr1)
                i = i + 1
        # elif(netMask==24):
        #     #/25当/24处理
        #     lpmdict[sn] = subnet[sn]
        #     newip1 = []
        #     newip1.append(str(ip_num[0]))
        #     newip1.append(str(ip_num[1]))
        #     newip1.append(str(ip_num[2]))
        #     newip1.append('*')
        #     ipstr1 = '.'.join(newip1)
        #     lpm.insert_rule(ipstr1)
        elif(netMask>24):# range match
            sn_gte24[sn]=subnet[sn]
        else:
            #netMask>16 and netMask<21,save them
            sndict[sn]=subnet[sn]
    mylog.info('lpm data size: %d'%len(lpmdict))
    mylog.info('remaining subnet size:%d'%len(sndict))
    mylog.info('lte16 size:%d'%len(sn_lte16))
    mylog.info('gte24 size:%d' % len(sn_gte24))
    #save
    snpath=getsavepath(fpath,'remaining_subnet')
    ltepath=getsavepath(fpath,'lte16_subnet')
    lpmpath=getsavepath(fpath,'lpm_subnet_data')
    gtepath=getsavepath(fpath,'gte24_subnet')
    if(sndict):
        if(os.path.exists(snpath)):
            newsndict=blacklist_tools.load_dict(snpath)
            newsndict1=dict(newsndict,**sndict)#merge
            saveToJSON(newsndict1, fpath, "remaining_subnet")
        else:
            saveToJSON(sndict, fpath,"remaining_subnet")
    if (sn_lte16):
        if(os.path.exists(ltepath)):
            newlte=blacklist_tools.load_dict(ltepath)
            newlte16=dict(newlte,**sn_lte16)#merge
            saveToJSON(newlte16, fpath, 'lte16_subnet')
        else:
            saveToJSON(sn_lte16,fpath,'lte16_subnet')
    if(lpmdict):
        if(os.path.exists(lpmpath)):
            newlpmdict=blacklist_tools.load_dict(lpmpath)
            newlpmdict1=dict(newlpmdict,**lpmdict)#merge
            saveToJSON(newlpmdict1, fpath, 'lpm_subnet_data')
        else:
            saveToJSON(lpmdict,fpath,'lpm_subnet_data')
    if(sn_gte24):
        if(os.path.exists(gtepath)):
            newlpmdict=blacklist_tools.load_dict(gtepath)
            newlpmdict1=dict(newlpmdict,**sn_gte24)#merge
            saveToJSON(newlpmdict1, fpath, 'gte24_subnet')
        else:
            saveToJSON(sn_gte24,fpath,'gte24_subnet')
    sn_gte24 = dict(sn_gte24, **sndict)  # merge
    #match
    subnet_result=[]
    for ips in es_ip:
        ip_es_num = socket.ntohl(struct.unpack("I", socket.inet_aton(str(ips)))[0])
        if(lpm.search_ip(ip_es_num)):
            subnet_result.append({ips:'subnet_lpm_match'})
    return subnet_result, sndict, sn_lte16,sn_gte24

# zhou
# focus on gte24 data
# Firstly, change gte24 to range type
# Secondly, match by range method
def subnet_range_match(sn_gte24,es_ip):
    sn_gte24_list = []
    #firstly,change
    allrange=subnetTOrange(sn_gte24)
    #secondly, match
    mylog=blacklist_tools.getlog()
    mylog.info('gte24 size:{}'.format(len(sn_gte24)))
    # sorted
    newAllRange=sorted(allrange.iteritems(),key=lambda x:x[1][0])
    rangeLen=len(newAllRange)
    mylog.info('start Binary Search!')
    for ips in es_ip:
        ip_es_num = socket.ntohl(struct.unpack("I",socket.inet_aton(str(ips)))[0])
        # Binary Search
        nlow=0
        nhigh=rangeLen-1
        while(nlow<=nhigh):
            nmid=(nlow+nhigh)/2
            subnet_num=newAllRange[nmid][1]# [start,end]
            if(subnet_num[0]<=ip_es_num<=subnet_num[1]):
                sn_gte24_list.append({ips: newAllRange[nmid][0]})
                break
            elif(subnet_num[0]>ip_es_num):
                nhigh=nmid-1
            elif(subnet_num[1]<ip_es_num):
                nlow=nmid+1
        # for key in allrange.keys():
        #     subnet_num = allrange[key]
        #     # print subnet_num[0],subnet_num[1]
        #     subnet_num_min = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[0])))[0])
        #     subnet_num_max = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[1])))[0])
        #     if subnet_num[0] <= ip_es_num <= subnet_num[1]:
        #         sn_gte24_list.append({ips:key})
        # for key in sn_lte16:#key is ip
        #     subnet_num = subnet_range(key)
        #     # print subnet_num[0],subnet_num[1]
        #     subnet_num_min = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[0])))[0])
        #     subnet_num_max = socket.ntohl(struct.unpack("I",socket.inet_aton(str(subnet_num[1])))[0])
        #     if subnet_num_min <= ip_es_num <= subnet_num_max:
        #         sndict_list.append({ips:key})
    return sn_gte24_list

# change subnet to range
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
        begin_int=socket.ntohl(struct.unpack("I",socket.inet_aton(begin_addr))[0])
        end_int = socket.ntohl(struct.unpack("I", socket.inet_aton(end_addr))[0])
        ip_range.append(begin_int)
        ip_range.append(end_int)

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
        begin_int=socket.ntohl(struct.unpack("I",socket.inet_aton(begin_addr))[0])
        end_int = socket.ntohl(struct.unpack("I", socket.inet_aton(end_addr))[0])
        ip_range.append(begin_int)
        ip_range.append(end_int)
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
        begin_int=socket.ntohl(struct.unpack("I",socket.inet_aton(begin_addr))[0])
        end_int = socket.ntohl(struct.unpack("I", socket.inet_aton(end_addr))[0])
        ip_range.append(begin_int)
        ip_range.append(end_int)

    return ip_range

def subnetTOrange(sn24):
    allRange={}
    for subnets in sn24:# {key:[start,end]}
        allRange[subnets]=subnet_range(subnets)
    return allRange