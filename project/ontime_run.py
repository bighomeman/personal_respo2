#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh
import os
import time
import datetime
import match_insert
import parser_config
import update_blacklist

second = datetime.timedelta(seconds=1)
day = datetime.timedelta(days=1)

# def store_run():
#     entertime = time.strftime("%Y-%m-%d %H:%M:%S")
#     startTime = datetime.datetime.strptime(entertime, '%Y-%m-%d %H:%M:%S')
#     #begin= '2017-05-24 23:59:57'
#     #beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
#     #print startTime
#     while True:
#
#         while datetime.datetime.now() < startTime:
#             #print 'beginTime',beginTime
#             print 'startTime',startTime
#             time.sleep(1)
#             #beginTime = beginTime+second
#         try:
#             print("Starting command."),time.ctime()
#             # execute the command
#             storeDate = (startTime).strftime('%Y-%m-%d')
#             command = r'python merge_blacklist.py "%s"' %(storeDate)
#             status = os.system(command)
#             print('done'+"-"*100),time.ctime()
#             print("Command status = %s."%status)
#             startTime = startTime+day
#         except Exception, e:
#             print e

# def run(entertime,delta):
#
#     startTime = datetime.datetime.strptime(entertime, '%Y-%m-%d %H:%M:%S')
#     #begin= '2017-05-24 23:59:57'
#     #beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
#     #print startTime
#     while True:
#
#         while datetime.datetime.now() < startTime:
#             #print 'beginTime',beginTime
#             #print 'startTime',startTime
#             time.sleep(1)
#             #beginTime = beginTime+second
#         try:
#             print("Starting command."),time.ctime()
#             # execute the command
#             gte = (startTime-delta).strftime('%Y-%m-%d %H:%M:%S')
#             lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
#             timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S')+".000+08:00"
#             command = r'python match_insert.py "%s" "%s" "%s"' %(gte,lte,timestamp)
#             status = os.system(command)
#             print('done'+"-"*100),time.ctime()
#             print("Command status = %s."%status)
#             startTime = startTime+delta
#         except Exception, e:
#             print e


def checkES(startTime,indx,aggs_name,serverNum,dport,tday):
    # new check function
    try:
        print("Starting check command."), time.ctime()
        # execute the command
        gte = (startTime - delta).strftime('%Y-%m-%d %H:%M:%S')
        lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S') + ".000+08:00"
        match_insert.main(tday,indx,gte,lte,aggs_name,timestamp,serverNum,dport)
        print("check finish."), time.ctime()
        print"="*40

    except Exception, e:
        print e



def new_run(entertime,delta,serverNum,dport,indx='tcp-*',aggs_name='dip',):
    # new running procedure
    startTime = entertime
    # beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
    # flgnum is the running times per day
    flgnum=0
    # get format: "yy-mm-dd"
    tday=datetime.datetime.now().date()
    runtime=0 # elapsed time of whole process,included check and merge
    while True:
        if(tday!=datetime.datetime.now().date()):
            flgnum=0 # reset flgnum per day
            tday=datetime.datetime.now().date()
        while datetime.datetime.now() < startTime:
            print('time sleep...')
            time.sleep(delta.seconds-runtime)
        try:
            st=time.clock()
            #update source dataset
            update_blacklist.main(tday,flgnum)
            # check interval time is 5mins
            checkES(startTime,indx,aggs_name,serverNum,dport,tday)
            startTime = startTime + delta
            flgnum+=1
            runtime=time.clock()-st# get the time of whole process
        except Exception, e:
            print e


if __name__=="__main__":
    #delta = 5mins
    delta,discard=parser_config.getCheckDeltatime()
    # entertime =
    entertime = time.strftime("%Y-%m-%d %H:%M:%S")
    startTime = datetime.datetime.strptime(entertime, '%Y-%m-%d %H:%M:%S')
    serverNum,dport,indx,aggs_name=parser_config.get_ES_info()
    #serverNum='172.23.2.96',dport = "9200";indx=tcp-*; aggs_name=dip
    new_run(startTime,delta,serverNum,dport,indx,aggs_name)
    # store_run()