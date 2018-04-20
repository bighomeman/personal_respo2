#!/usr/bin/python

import os
import time
import datetime

minutes_5 = datetime.timedelta(minutes=5)
second = datetime.timedelta(seconds=1)
day = datetime.timedelta(days=1)

def run(entertime,delta):

    startTime = datetime.datetime.strptime(entertime, '%Y-%m-%d %H:%M:%S')
    #begin= '2017-05-24 23:59:57'
    #beginTime = datetime.datetime.strptime(begin, '%Y-%m-%d %H:%M:%S')
    #print startTime
    while True:

        while datetime.datetime.now() < startTime:
            #print 'beginTime',beginTime
            #print 'startTime',startTime
            time.sleep(1)
            #beginTime = beginTime+second
        try:
            print("Starting command."),time.ctime()
            # execute the command
            gte = (startTime-delta).strftime('%Y-%m-%d %H:%M:%S')
            lte = (startTime).strftime('%Y-%m-%d %H:%M:%S')
            timestamp = (startTime).strftime('%Y-%m-%dT%H:%M:%S')+".000+08:00"
            command = r'python match_insert.py "%s" "%s" "%s"' %(gte,lte,timestamp)
            status = os.system(command)
            print('done'+"-"*100),time.ctime()
            print("Command status = %s."%status)
            startTime = startTime+delta
        except Exception, e:
            print e

if __name__=="__main__":
    entertime = '2018-03-28 10:00:00'
    delta = minutes_5
    run(entertime,delta)
    # store_run()