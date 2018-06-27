#! /usr/bin/python
# -*- coding: utf-8 -*-
# author: songh

from elasticsearch import Elasticsearch
import time
import datetime
import blacklist_tools

# !/usr/bin/python
# -*- coding: utf-8 -*-

import json

def get_date_flow(es, gte, lte, time_zone, dip):
    search_option = {
        "size": 0,
        "query": {
            "bool": {
                "must": [
                    {
                        "query_string": {
                            "query": "dip:{}".format(dip),
                            'analyze_wildcard': True
                        }
                    },
                    {
                        "range": {
                            "@timestamp": {
                                "gte": gte,
                                "lte": lte,
                                "format": "yyyy-MM-dd HH:mm:ss",
                                "time_zone": time_zone
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
            "sip": {
                "terms": {
                    "field": "sip",
                    "size": 100,
                    "order": {
                        "flow": "desc"
                    }
                },
                "aggs": {
                    "flow": {
                        "sum": {
                            "field": "flow"
                        }
                    },
                    "date": {
                        "date_histogram": {
                            "field": "@timestamp",
                            "interval": "1m",
                            "time_zone": time_zone,
                            "min_doc_count": 1
                        },
                        "aggs": {
                            "flow": {
                                "sum": {
                                    "field": "flow"
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    result = es.search(
        index="tcp-*",
        body=search_option
    )
    return result




def calc_median(datalist):
    datalist.sort()
    half = len(datalist) // 2
    return (datalist[half] + datalist[~half]) / 2.0


def calc_MAD(datalist):
    median = calc_median(datalist)
    return calc_median([abs(data - median) for data in datalist])

# Second_check: 1）根据dip查找某段时间内所有与其通信的sip在每分钟flow计数；
#             2）根据flow计数的序列判断是否有异常
# return: 返回有问题的sip list
def Second_check(es, gte, lte, time_zone, dip,mylog):
    mylog.info('get flow from ES.')
    res = get_date_flow(es=es, gte=gte, lte=lte, time_zone=time_zone, dip=dip)
    ret_siplist = []
    # each sip_item has only one sip but many flows in different time
    for sip_item in res["aggregations"]["sip"]["buckets"]:
        datelist = []
        flowlist = []
        for item in sip_item["date"]["buckets"]:
            datelist.append(item["key"])
            flowlist.append(item["flow"]["value"])
        if len(datelist) < 2:
            continue
        mylog.info('*-*-* len of datelist:{}'.format(len(datelist)))
        date_dev = [datelist[i + 1] - datelist[i] for i in range(len(datelist) - 1)]
        #		print date_dev
        #		print flowlist
        mylog.info('*-*-* result of date_dev:{}'.format(calc_MAD(date_dev)))
        mylog.info('*-*-* result of flowlist:{}'.format(calc_MAD(flowlist)))
        # print calc_MAD(date_dev)
        # print calc_MAD(flowlist)
        if (calc_MAD(date_dev) <= 60000) and (calc_MAD(flowlist) <= 1):
            ret_siplist.append(sip_item["key"])
            mylog.info('*-*-* appending sip:{}.'.format(sip_item["key"]))
    return ret_siplist# sip

class ESclient(object):
    def __init__(self,server='192.168.0.122',port='9222'):
        self.__es_client=Elasticsearch([{'host':server,'port':port}])
    # get alert's dip list
    def get_es_ip(self,index,gte,lte,aggs_name,time_zone,querystr,rangetime,size=500000):
        search_option={
            "size": 0,
            "query": {
              "bool": {
                "must": [
                    {
                        "query_string": querystr
                    },
                    {
                        "range": rangetime
                    }
                ],
                "must_not": []
              }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "get": {
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
        clean_search_result = search_result['aggregations']["get"]['buckets']
        ip = []
        for temp in clean_search_result:
            ip.append(temp['key'])
        return ip

    def es_index(self, doc):
        # 数据回插es的alert-*索引
        ret = self.__es_client.index(
            index='alert-{}'.format(datetime.datetime.now().strftime('%Y-%m-%d')),
            doc_type='netflow_v9',
            body=doc
        )
    # get all alerts' infomation and return dict={dip:{value},dip2:{},...}
    def es_search_alert(self,index,gte,lte,filetype,time_zone,querystr,rangetime,aggs):
        search_option = {
            "size": 0,
            "query": {
                "bool": {
                    "must": [
                        {
                            "query_string": querystr
                        },
                        {
                            "range": rangetime
                        }
                    ],
                    "must_not": []
                }
            },
            "_source": {
                "excludes": []
            },
            "aggs": {
                "get": aggs
                }
        }
        search_result = self.__es_client.search(
            index=index,
            body=search_option
        )
        allrecord={}
        clean_search_result = search_result['hits']["hits"]
        for temp in clean_search_result:
            #temp is dict
            dip=temp["_source"]["dip"]
            allrecord[dip]=temp["_source"]
        return allrecord

    def secondcheck(self,gte2,lte,time_zone,dip,mylog):
        mylog.info('start second check.')
        return Second_check(self.__es_client, gte2, lte, time_zone, dip,mylog)

'''
checkAlert: 检查alert中关于c&c的info告警，获取dip
'''
def checkAlert(index,gte,lte,time_zone,serverNum,dport):
    querystr={
        "query":"type:mal_ip",
        "analyze_wildcard": True
    }
    filetype='dip'
    rangetime={
        "@timestamp": {
            "gte": gte,
            "lte": lte,
            "format": "yyyy-MM-dd HH:mm:ss",
            "time_zone":time_zone
        }
    }
    aggs={
      "date_histogram": {
        "field": "@timestamp",
        "interval": "30m",
        "time_zone": time_zone,
        "min_doc_count": 1
      }
    }
    #get es list
    es = ESclient(server =serverNum,port=dport)
    # mylog.info('connected with es')
    ip_es_list = es.get_es_ip(index,gte,lte,filetype,time_zone,querystr,rangetime)
    allalerts=es.es_search_alert(index,gte,lte,filetype,time_zone,querystr,rangetime,aggs)
    return ip_es_list,es,allalerts


'''
searchAndInsert:1)modified the record (level:warning,add sip)
                2)insert to es
alerts: the alerts infomation
ipdict: dip after second check,and it's reference sip
'''
def searchAndInsert(alerts,ipdict,es,mylog):
    alert_dip=alerts.keys()
    warning_dip=ipdict.keys()
    mylog.info('start second check insert.')
    for tmp in warning_dip:
        if(tmp in alert_dip):# make sure that dip in alerts
            for tsip in ipdict[tmp]:
                doc=alerts[tmp]
                doc['level']="warn"
                doc['sip']=tsip
                es.es_index(doc)
                mylog.info('insert WARNING!!!')
    mylog.info('second check insert finished.')


def main(startTime,all_IP,serverNum,dport):
    mylog=blacklist_tools.getlog()
    # startTime=datetime.datetime.now()
    delta1=datetime.timedelta(minutes=5)
    gte1 = (startTime - delta1).strftime('%Y-%m-%d %H:%M:%S')
    lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
    time_zone = ''
    if (time.daylight == 0):  # 1:dst;
        time_zone = "%+03d:%02d" % (-(time.timezone / 3600), time.timezone % 3600 / 3600.0 * 60)
    else:
        time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
    timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone
    # serverNum='localhost'
    # dport='9200'
    #first step,get the all_IP
    # mylog.info('start check alert info.')
    # diplist,es,allalerts=checkAlert('alert-*',gte1,lte,time_zone,serverNum,dport)
    es = ESclient(server=serverNum, port=dport)
    #second step
    delta2=datetime.timedelta(days=1)
    gte2 = (startTime - delta2).strftime('%Y-%m-%d %H:%M:%S')
    lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
    allwarn={}# {dip:[sip,sip,sip...],ip:[],...},
    try:
        for dip in all_IP.keys():
            allwarn[dip]=es.secondcheck(gte2,lte,time_zone,dip,mylog)
    except Exception,e:
        mylog.error('second_check:{}'.format(e))
    #insert warning alert
    try:
        searchAndInsert(all_IP,allwarn,es,mylog)
    except Exception,e:
        mylog.error('searchAndInsert:{}'.format(e))
