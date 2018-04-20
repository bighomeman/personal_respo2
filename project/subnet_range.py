#!/usr/bin/python
# -*- coding: utf-8 -*-

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
def subnet_range(subnet):
    subnet_split = subnet.split('/')
    ip_num = ip_split_num(subnet_split[0])
    netMask = int(subnet_split[1])
    nm_num = subnet_to_binary(netMask)
    firstadr = []
    lastadr = []
    ip_range = {}
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
        ip_range["start"] = begin_addr
        ip_range["end"] = end_addr
        # ip_range.append(begin_addr)
        # ip_range.append(end_addr)

    elif netMask == 32:
        firstadr.append(str(ip_num[0]))
        firstadr.append(str(ip_num[1]))
        firstadr.append(str(ip_num[2]))
        firstadr.append(str(ip_num[3]))

        lastadr.append(str(ip_num[0]))
        lastadr.append(str(ip_num[1]))
        lastadr.append(str(ip_num[2]))
        lastadr.append(str(ip_num[3]))
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
        ip_range["start"] = begin_addr
        ip_range["end"] = end_addr

    return ip_range