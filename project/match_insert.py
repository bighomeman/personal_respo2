#!/usr/bin/python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
import json
import datetime,sys
from blacklist_tools import load_dict
import treat_ip
import parser_config
import os

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

def treatip(dataset,es_ip):
    full,segment,subnet=treat_ip.seperate_ip(dataset)
    # match procedure
    full_list = full.keys()
    fullmatch_result = treat_ip.ip_full_match(full_list, es_ip)
    # print fullmatch_result
    fullmatchlist=list(fullmatch_result)
    segment_match = []
    segmentlist=treat_ip.int_ip_range(segment)
    subnetlist=treat_ip.int_ip_subnet(subnet)
    for ip_str in es_ip:
        if treat_ip.ip_segment_match(segmentlist, ip_str):
            segment_match.append(treat_ip.ip_segment_match(segmentlist, ip_str))
        elif treat_ip.ip_segment_match(subnetlist, ip_str):
            segment_match.append(treat_ip.ip_segment_match(subnetlist, ip_str))
    # print segment_match
    return fullmatchlist,segment_match

def insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch_result,segment_match,dataset):
    es_insert = ESclient(server=serverNum, port=dport)
    if len(fullmatch_result) > 0:
        for i in range(len(fullmatch_result)):
            doc = {}
            doc['level'] = dataset[fullmatch_result[i]]['level']
            doc['source'] = dataset[fullmatch_result[i]]['source']
            doc['type'] = "full_match"
            doc[aggs_name] = dataset[fullmatch_result[i]]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'full_match_insert'

    if len(segment_match) > 0:
        for i in range(len(segment_match)):
            # segment insert
            ip_es=segment_match[i].keys()[0]
            ipseg=segment_match[i][ip_es]
            doc = {}
            doc['level'] = dataset[ipseg]['level']
            doc['source'] = dataset[ipseg]['source']
            doc['type'] = ipseg
            doc[aggs_name] = ip_es
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'segment_insert'


'''
step1: get the saved file
step2: divide the data into 3 parts(ip_32/ip_seg/ip_subnet)
step3: match each parts
step4: insert the threat info into es
'''
def main(tday,index, gte, lte, aggs_name, timestamp,serverNum,dport):
    path=parser_config.get_store_path()[1]+str(tday)+'\\'
    filelist=get_all_file(path)
    #get es list
    es = ESclient(server =serverNum,port=dport)
    ip_es_list = es.get_es_ip(index,gte,lte,aggs_name)

    #check each file
    for fname in filelist:
        fpath=path+fname
        dataset=load_dict(fpath)
        #get match result
        fullmatch,segmentmatch=treatip(dataset,ip_es_list)
        insert_result(index,aggs_name,timestamp,serverNum,dport,fullmatch,segmentmatch,dataset)



if __name__ == '__main__':
	main('tcp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])
	main('udp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])