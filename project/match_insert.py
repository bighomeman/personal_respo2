#!/usr/bin/python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
import json
import datetime,sys
from blacklist_tools import load_dict
import treat_ip

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
                    "query_string":{
                      "query" : "NOT dip:[192.168.0.0 TO 192.168.255.255]"
                    }
				  },
                  {
                    "range": {
                      "@timestamp": {
                        "gte": gte,
                        "lte": lte,
                        "format": "yyyy-MM-dd HH:mm:ss"
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
              aggs_name: {
                "terms": {
                  "field": "dip",
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
		clean_search_result = search_result['aggregations'][aggs_name]['buckets']
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





def main(index, gte, lte, aggs_name, timestamp):
    time=lte.split(" ")
    segment_dict = load_dict(".\data\\segment-"+str(time[0])+".json")
    full_match_dict = load_dict(".\data\\full_match-"+str(time[0])+".json")
    subnet_dict = load_dict(".\data\\subnet-"+str(time[0])+".json")
    es = ESclient(server = '192.168.0.122')
    ip_es_list = es.get_es_ip(index,gte,lte,aggs_name)
    full_list = full_match_dict.keys()

    fullmatch_result = treat_ip.ip_full_match(full_list,ip_es_list)
    segment_match = []
    for ip_str in ip_es_list:
        if treat_ip.ip_segment_match(segment_dict,ip_str):
            segment_match.append(treat_ip.ip_segment_match(segment_dict,ip_str))

    es_insert = ESclient(server = '192.168.0.122', port = '9400')
    if len(fullmatch_result) > 0:
        for i in range(len(fullmatch_result)):
            doc = full_match_dict[fullmatch_result[i]]
            doc[aggs_name] = fullmatch_result[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'full_match_get'

    if len(segment_match) > 0:
        for i in range(len(segment_match)):
            doc = full_match_dict[segment_match[i]]
            doc[aggs_name] = segment_match[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            es_insert.es_index(doc)
        print 'segment_match_get'









if __name__ == '__main__':
	main('tcp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])