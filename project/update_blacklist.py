#! /usr/bin/python
# _*_ Coding:UTF-8 _*_
# author: songh
'''
update each blacklist , each them in different file.
step1 : create a daily dir
step2 : save or update each blacklist
'''
import blacklist_tools
import os
import parser_config
import time

#save data
def update_blacklist_module(flgnum):
    parser_blacklist=parser_config.get_func()
    for filename in parser_blacklist.keys():
        times=int(parser_blacklist[filename])
        # check the update frequency
        if(flgnum%times==0):
            command='python .\get_blacklist\\'+filename+'.py'
            try:
                status=os.system(command)
                print status
            except Exception,e:
                print e

def main(tday,flgnum):
    print("Starting update command."), time.ctime()
    dirpath=".\data\\%s\\"%tday
    if(not os.path.exists(dirpath)):
        os.mkdir(dirpath)
    update_blacklist_module(flgnum)
    print("update finish."), time.ctime()