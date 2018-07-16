#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh
import os
import time
import datetime
import match_insert
import parser_config
import update_blacklist
import blacklist_tools
import ip_check_C2

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


def checkES(startTime,indx,aggs_name,serverNum,dport,tday,offset):
    # new check function
    mylog=blacklist_tools.getlog()
    try:
        # print("Starting check command."), time.ctime()
        mylog.info("[Starting check command.Time is:{}]".format((startTime).strftime('%Y-%m-%d %H:%M:%S')))
        # execute the command
        gte = (startTime - delta-offset).strftime('%Y-%m-%d %H:%M:%S')
        lte = (startTime-offset).strftime('%Y-%m-%d %H:%M:%S')
        time_zone=''
        if(time.daylight==0):# 1:dst;
            time_zone="%+03d:%02d"%(-(time.timezone/3600),time.timezone%3600/3600.0*60)
        else:
            time_zone = "%+03d:%02d" % (-(time.altzone / 3600), time.altzone % 3600 / 3600.0 * 60)
        timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S.%f') + time_zone
        all_ip=match_insert.main(tday,indx,gte,lte,aggs_name,timestamp,serverNum,dport,time_zone)
        # print("check finish."), time.ctime()
        mylog.info("{0}check finish.{1}".format("="*30,"="*30))
        # print"="*40
        return all_ip

    except Exception, e:
        # print e
        mylog.error(e)
        return {}



def new_run(entertime,delta,serverNum,dport,offset,indx='tcp-*',aggs_name='dip',):
    # new running procedure
    updatetime=datetime.datetime.now()
    startTime = entertime
    # beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
    # flgnum is the running times per day
    flgnum=0
    # get format: "yy-mm-dd"
    tday=datetime.datetime.now().date()
    # runtime=0 # elapsed time of whole process,included check and merge
    mylog=blacklist_tools.getlog()
    updateFlg=parser_config.update_flg() #
    while True:
        if(tday!=datetime.datetime.now().date()):
            flgnum=0 # reset flgnum per day
            tday=datetime.datetime.now().date()
            dirpath = parser_config.get_store_path()[1] + str(tday) + os.path.sep
            os.mkdir(dirpath)
        while datetime.datetime.now() < startTime:
            #print('time sleep...')
            mylog.info("Time sleeping ...")
            time.sleep((startTime-datetime.datetime.now()).total_seconds())
        try:
            # st=time.clock()
            #update source dataset
            if(updateFlg==1):
                if(datetime.datetime.now()>updatetime):
                    update_blacklist.main(tday,flgnum)
                    updatetime=updatetime+delta
            # check interval time is 5mins
            all_IP=checkES(startTime,indx,aggs_name,serverNum,dport,tday,offset)
            #IP second check for C&C
            flg_C2=parser_config.get_ip_secondcheck()
            if(flg_C2==1):
                mylog.info('all_IP size:{}'.format(len(all_IP)))
                ip_check_C2.main(startTime,all_IP,serverNum,dport)
            startTime = startTime + delta
            flgnum+=1
            # runtime=time.clock()-st# get the time of whole process
        except Exception, e:
            # print e
            mylog.error(e)


if __name__=="__main__":
    #delta = 5mins
    delta,discard,offset=parser_config.getCheckDeltatime()
    # entertime =
    entertime = time.strftime("%Y-%m-%d %H:%M:%S")
    startTime = datetime.datetime.strptime(discard, '%Y-%m-%d %H:%M:%S')
    serverNum,dport,indx,aggs_name=parser_config.get_ES_info()
    #serverNum='172.23.2.96',dport = "9200";indx=tcp-*; aggs_name=dip
    #set global dic for storm suppression
    blacklist_tools.global_init()
    blacklist_tools.set_global_value('warn',[])
    new_run(startTime,delta,serverNum,dport,offset,indx,aggs_name)
    # store_run()