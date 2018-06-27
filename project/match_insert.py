#!/usr/bin/python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
import json
import datetime,sys
from blacklist_tools import load_dict,load_whitelist
import blacklist_tools
import treat_ip
import parser_config
import os
import lpm
import subnet_range

class ESclient(object):
	def __init__(self,server='192.168.0.122',port='9222'):
		self.__es_client=Elasticsearch([{'host':server,'port':port}])

	def get_es_ip(self,index,gte,lte,aggs_name,time_zone,size=500000):
		search_option={
            "size": 0,
            "query": {
              "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "NOT dip:[192.168.0.0 TO 192.168.255.255] AND NOT dip:[172.16.0.0 TO 172.31.255.255] AND NOT dip[10.0.0.0 TO 10.255.255.255] AND NOT dport:445",
                            "analyze_wildcard": True
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte,
                                "format": "yyyy-MM-dd HH:mm:ss",
                                "time_zone":time_zone
                            }
                        }
                    }
                ],
                "must_not": []
              }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "getDip": {
                    "terms": {
                        "field": aggs_name,
                        "size": size,
                        "order": {
                            "_count": "desc"
                        }
                    }
                }
            }
        }

		search_result=self.__es_client.search(
			index=index,
			body=search_option
			)
		clean_search_result = search_result['aggregations']["getDip"]['buckets']
		ip = []
		for temp in clean_search_result:
			ip.append(temp['key'])
		return ip

	def es_index(self,doc):
		'''
		数据回插es的alert-*索引
		'''
		ret = self.__es_client.index(
			index = 'alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
			doc_type = 'netflow_v9',
			body = doc
			)


def get_all_file(path):
    if(os.path.exists(path)):
        filelist=os.listdir(path)
        return filelist

'''
step1: get dataset from file and separate them into three parts
step2: full match
step3: range match
step4: separate the subnet dataset into two parts(lpm,full)
step5: lpm match and subnet full match
'''
def treatip(dataset,es_ip):
    mylog=blacklist_tools.getlog()
    full,segment,subnet=treat_ip.separate_ip(dataset)#dataset is dict
    # match procedure
    # full match
    full_list = full.keys()
    # return fullmatchlist,type is list
    fullmatchlist=treat_ip.ip_full_match(full_list, es_ip)
    # segment match, segmentlist:[{ip:ipsegment},{},...]
    segmentlist=treat_ip.int_ip_range(segment,es_ip)
    subnet_lpm = {}
    subnet_full = {}
    sndict = {}
    sn_lte16 = {}
    # read conf file to choose the methods
    flg_lpm,flg_full=parser_config.get_method()
    if(1==flg_lpm):
        # subnet match by lpm,subnet_lpm is match results;sndict and sn_lte16 is original subnet data
        mylog.info('start lpm match')
        subnet_lpm,sndict,sn_lte16=subnet_range.subnet_lpm(subnet,es_ip)
        mylog.info('finish lpm match')
    if(1==flg_full):
        #subnet match by zhou, parameters are snlist and es_ip
        mylog.info('sndict size: %d'%len(sndict))
        mylog.info('sn_lte16 size: %d' % len(sn_lte16))
        mylog.info('start range subnet match')
        subnet_full=subnet_range.subnet_range_match(sndict,sn_lte16,es_ip)
        mylog.info('finish range subnet match')
    #whitelist
    wlflg, whitepath = parser_config.get_self_filelist('whitelist')
    if(wlflg==1):
        #get whilelist
        if (os.path.exists(whitepath)):
            filelist = get_all_file(whitepath)
            for fname in filelist:
                fpath = whitepath + fname
                #白名单读取方式不一样, whitedata is dict
                whitedata = blacklist_tools.load_whitelist(fpath)
                #filter procedure
                fullmatchlist, segmentlist, subnet_lpm, subnet_full=treat_ip.whitelist_filter(fullmatchlist,segmentlist,subnet_lpm,subnet_full,whitedata)
        else:
            mylog.info('no self_whitelist_path')

    # return match results
    return fullmatchlist,segmentlist,subnet_lpm,subnet_full


#get four dateset from four match methods , insert separately
# msg is original data
def insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,msg):
    es_insert = ESclient(server=serverNum, port=dport)
    mylog=blacklist_tools.getlog()
    threat_ip={}
    #white list filter ips
    if len(fullmatch) > 0:
        for i in range(len(fullmatch)):
            doc = {}
            doc['level'] = msg[fullmatch[i]]['level']
            doc['type']='mal_ip'
            doc['desc_type']='[MAL_IP] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[fullmatch[i]]['desc_subtype']
            doc['subtype']=msg[fullmatch[i]]['subtype']
            doc['match_type'] = "full_match"
            doc[aggs_name] = fullmatch[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
            threat_ip[fullmatch[i]]=doc
        print 'full_match_insert'
        mylog.info('full_match_insert')

    if len(segmentmatch) > 0:
        for i in range(len(segmentmatch)):
            # segment insert
            ip_es=segmentmatch[i].keys()[0]
            # print ip_es
            ipseg=segmentmatch[i][ip_es]
            # print ipseg
            doc = {}
            doc['level'] = msg[ipseg]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[MAL_IP] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[ipseg]['desc_subtype']
            doc['subtype'] = msg[ipseg]['subtype']
            doc['match_type'] = "segment_match"
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
            threat_ip[ip_es] = doc
        print 'segment_insert'
        mylog.info('segment_insert')

    if len(subnetlpm) > 0:
        for i in range(len(subnetlpm)):
            # segment insert
            ip_es=subnetlpm[i].keys()[0]
            # print ip_es
            ipseg=subnetlpm[i][ip_es]
            # print ipseg
            key1=msg.keys()[0]
            doc = {}
            doc['level'] = msg[key1]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[MAL_IP] Request of suspect IP detection.'
            tmptype=msg[key1]['desc_subtype'].split(';')
            doc['desc_subtype'] = tmptype[0].split(':')[0]+';'+tmptype[1]
            doc['subtype'] = msg[key1]['subtype']
            doc['match_type'] = 'subnet_lpm_match'
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
            threat_ip[ip_es] = doc
        print 'subnet_lpm_insert'
        mylog.info('subnet_lpm_insert')

    if len(subnetfull) > 0:
        for i in range(len(subnetfull)):
            # segment insert
            ip_es=subnetfull[i].keys()[0]
            # print ip_es
            ipseg=subnetfull[i][ip_es]
            # print ipseg
            doc = {}
            doc['level'] = msg[ipseg]['level']
            doc['type'] = 'mal_ip'
            doc['desc_type'] = '[MAL_IP] Request of suspect IP detection.'
            doc['desc_subtype'] = msg[ipseg]['desc_subtype']
            doc['subtype'] = msg[ipseg]['subtype']
            doc['match_type'] = 'subnet_fullmatch'
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
            threat_ip[ip_es] = doc
        print 'subnet_full_insert'
        mylog.info('subnet_full_insert')
    return threat_ip

def checkAndInsert(path,filelist,ip_es_list,index,aggs_name,timestamp,serverNum,dport):
    # check each file
    all_threatIP={}
    for fname in filelist:
        fpath = path + fname
        dataset = load_dict(fpath)
        if (dataset):
            msg = dataset[dataset.keys()[0]]
            # get match result
            fullmatch, segmentmatch, subnetlpm, subnetfull = treatip(dataset,ip_es_list)
            threatIP=insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,dataset)
            # merge
            if(threatIP):
                all_threatIP=dict(all_threatIP,**threatIP)
    return all_threatIP

'''
step1: get the saved file
step2: divide the data into 3 parts(ip_32/ip_seg/ip_subnet),and match each parts
step3: insert the threat info into es
'''
def main(tday,index, gte, lte, aggs_name, timestamp,serverNum,dport,time_zone):
    mylog = blacklist_tools.getlog()
    path=parser_config.get_store_path()[1]+str(tday)+os.path.sep
    cnt=0
    allThreatIP={}
    while(cnt<8):
        if(os.path.exists(path)):
            filelist=get_all_file(path)
            break
        elif cnt==7:
            #default file path
            dflg, defaultpath = parser_config.get_self_filelist('defaultlist')
            if(dflg==1):
                filelist = get_all_file(defaultpath)
            else:
                filelist=[]
            break
        else:
            # check last 7 days file
            lday=tday+datetime.timedelta(-1)
            path = parser_config.get_store_path()[1] + str(lday) + os.path.sep
            cnt=cnt+1
            # mylog.warning('no path!')
            # filelist=[]

    #get es list
    es = ESclient(server =serverNum,port=dport)
    # mylog.info('connected with es')
    ip_es_list = es.get_es_ip(index,gte,lte,aggs_name,time_zone)
    # mylog.info('get es data,data size:%d'%len(ip_es_list))
    if(filelist):
        try:
            #check each file and insert match results
            tmpThreatIP=checkAndInsert(path,filelist,ip_es_list,index,aggs_name,timestamp,serverNum,dport)
            # mylog.info('main_insert Threat_ip size:{}'.format(len(tmpThreatIP)))
            if(tmpThreatIP):
                allThreatIP=dict(allThreatIP,**tmpThreatIP)
        except Exception, e:
            mylog.error('check blacklist:{}'.format(e))
    else:
        mylog.warning('no files!')
    #blacklist match
    blflg,blackpath=parser_config.get_self_filelist('blacklist')
    if(blflg==1):
        if(os.path.exists(blackpath)):
            filelist = get_all_file(blackpath)
            # 黑名单处理与普通文件不一样。
            # check each file
            for fname in filelist:
                fpath = blackpath + fname
                mylog.info('start check local file:{}'.format(fname))
                dataset = blacklist_tools.load_blacklist(fpath)
                if (dataset):
                    # msg = dataset[dataset.keys()[0]]
                    # get match result
                    try:
                        fullmatch, segmentmatch, subnetlpm, subnetfull = treatip(dataset, ip_es_list)
                        tmpIP=insert_result(index, aggs_name, timestamp, serverNum, dport, fullmatch, segmentmatch, subnetlpm,
                                  subnetfull, dataset)
                        if(tmpIP):
                            allThreatIP=dict(allThreatIP,**tmpIP)
                    except Exception,e:
                        mylog.error('check local blacklist:{}'.format(e))
            # checkAndInsert(blackpath,filelist,ip_es_list,index,aggs_name,timestamp,serverNum,dport)

        else:
            mylog.info('no self_blacklist_path')
    return allThreatIP


if __name__ == '__main__':
	main('tcp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])
	main('udp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])