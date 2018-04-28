#!/usr/bin/python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
import json
import datetime,sys
from blacklist_tools import load_dict
import treat_ip
import parser_config
import os
import lpm
import subnet_range

class ESclient(object):
	def __init__(self,server='192.168.0.122',port='9222'):
		self.__es_client=Elasticsearch([{'host':server,'port':port}])

	def get_es_ip(self,index,gte,lte,aggs_name,size=500000):
		search_option={
            "size": 0,
            "query": {
              "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "NOT dip:[192.168.0.0 TO 192.168.255.255]",
                            "analyze_wildcard": True
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte,
                                "format": "yyyy-MM-dd HH:mm:ss",
                                "time_zone":"+08:00"
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
    full,segment,subnet=treat_ip.separate_ip(dataset)
    # match procedure
    # full match
    full_list = full.keys()
    # return fullmatchlist
    fullmatchlist=treat_ip.ip_full_match(full_list, es_ip)
    # segment match, segmentlist:[{},{},...]
    segmentlist=treat_ip.int_ip_range(segment,es_ip)
    subnet_lpm={}
    subnet_full={}
    # read conf file to choose the methods
    flg_lpm,flg_full=parser_config.get_method()
    if(1==flg_lpm):
        # subnet match by lpm
        subnet_lpm,sndict=subnet_range.subnet_lpm(subnet,es_ip)
    if(1==flg_full):
        #subnet match by zhou, parameters are snlist and es_ip
        subnet_full=subnet_range.subnet_range(sndict.es_ip)

    return fullmatchlist,segmentlist,subnet_lpm,subnet_full


#get four dateset from four match methods , insert separately
# msg is the info of file
def insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,msg):
    es_insert = ESclient(server=serverNum, port=dport)
    if len(fullmatch) > 0:
        for i in range(len(fullmatch)):
            doc = {}
            doc['level'] = msg['level']
            doc['source'] = msg['source']
            doc['type']=msg['type']
            doc['match_type'] = "full_match"
            doc[aggs_name] = fullmatch[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'full_match_insert'

    if len(segmentmatch) > 0:
        for i in range(len(segmentmatch)):
            # segment insert
            ip_es=segmentmatch[i].keys()[0]
            ipseg=segmentmatch[i][ip_es]
            doc = {}
            doc['level'] = msg['level']
            doc['source'] = msg['source']
            doc['type'] = msg['type']
            doc['match_type'] = ipseg
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'segment_insert'

    if len(subnetlpm) > 0:
        for i in range(len(subnetlpm)):
            # segment insert
            ip_es=subnetlpm[i].keys()[0]
            ipseg=subnetlpm[i][ip_es]
            doc = {}
            doc['level'] = msg['level']
            doc['source'] = msg['source']
            doc['type'] = msg['type']
            doc['match_type'] = ipseg
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'subnet_lpm_insert'

    if len(subnetfull) > 0:
        print 'subnet_full_insert'


'''
step1: get the saved file
step2: divide the data into 3 parts(ip_32/ip_seg/ip_subnet),and match each parts
step3: insert the threat info into es
'''
def main(tday,index, gte, lte, aggs_name, timestamp,serverNum,dport):
    path=parser_config.get_store_path()[1]+str(tday)+os.path.sep
    filelist=get_all_file(path)
    #get es list
    es = ESclient(server =serverNum,port=dport)
    ip_es_list = es.get_es_ip(index,gte,lte,aggs_name)

    #check each file
    for fname in filelist:
        fpath=path+fname
        dataset=load_dict(fpath)
        if(dataset):
            msg=dataset[dataset.keys()[0]]
            #get match result
            fullmatch,segmentmatch,subnetlpm,subnetfull=treatip(dataset,ip_es_list)
            insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,subnetlpm,subnetfull,msg)



if __name__ == '__main__':
	main('tcp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])
	main('udp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])