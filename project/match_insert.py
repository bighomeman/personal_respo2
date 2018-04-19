#!/usr/bin/python
# -*- coding: utf-8 -*-

from elasticsearch import Elasticsearch
import json
import datetime,sys
from blacklist_tools import load_dict
import treat_ip,parser_config

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
    source_store_path =parser_config.get_store_path()
    segment_dict = load_dict(source_store_path[1] + "segment-"+str(time[0])+".json")
    # print segment_dict
    full_match_dict = load_dict(source_store_path[1] + "full_match-"+str(time[0])+".json")
    # print full_match_dict
    subnet_dict = load_dict(source_store_path[1] + "subnet-"+str(time[0])+".json")
    # print subnet_dict
    es = ESclient(server = '192.168.0.122')
    ip_es_list = es.get_es_ip(index,gte,lte,aggs_name)
    # print ip_es_list
    full_list = full_match_dict.keys()

    fullmatch_result = treat_ip.ip_full_match(full_list,ip_es_list)



    segment_match_ip = []
    segment_match_dict = []
    for ip_str in ip_es_list:
        for segment_element in segment_dict:
            if treat_ip.ip_segment_match(segment_element,ip_str):
                segment_match_ip.append(ip_str)
                segment_match_dict.append(segment_element)


    subnet_match_ip = []
    subnet_match_dict = []
    for ip_str in ip_es_list:

        for subnet_element in subnet_dict:
            if treat_ip.ip_subnet_match(subnet_element,ip_str):
                subnet_match_ip.append(ip_str)
                subnet_match_dict.append(subnet_element)


    es_insert = ESclient(server = '192.168.0.122', port = '9400')
    fullmatch_result = list(fullmatch_result)
    if len(fullmatch_result) > 0:
        print 'fullmatch_result',fullmatch_result,index
        for i in range(len(fullmatch_result)):
            doc = {}
            doc[aggs_name] = fullmatch_result[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            doc['level'] = full_match_dict[fullmatch_result[i]]['level']
            doc['source'] = full_match_dict[fullmatch_result[i]]['source']
            doc['type'] = full_match_dict[fullmatch_result[i]]['type']
            es_insert.es_index(doc)
        print 'full_match_get'

    if len(segment_match_ip) > 0:
        print 'segment_match_ip',segment_match_ip,index, segment_match_dict
        for i in range(len(segment_match_ip)):
            doc = {}
            doc[aggs_name] = segment_match_ip[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            doc['level'] = segment_match_dict[i]['level']
            doc['source'] = segment_match_dict[i]['source']
            doc['type'] = segment_match_dict[i]['type']
            es_insert.es_index(doc)
        print 'segment_match_get'

    if len(subnet_match_ip) > 0:
        print 'subnet_match_ip',subnet_match_ip,index,subnet_match_dict
        for i in range(len(subnet_match_ip)):
            doc = {}
            doc[aggs_name] = subnet_match_ip[i]
            doc['@timestamp'] = timestamp
            doc['index'] = index
            doc['level'] = subnet_match_dict[i]['level']
            doc['source'] = subnet_match_dict[i]['source']
            doc['type'] = subnet_match_dict[i]['type']
            es_insert.es_index(doc)
        print 'segment_match_get'

if __name__ == '__main__':
	main('tcp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])
	main('udp-*',sys.argv[1],sys.argv[2],'dip',sys.argv[3])