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
import blacklist_tools

#save data
def update_blacklist_module(flgnum):
    mylog=blacklist_tools.getlog()
    parser_blacklist=parser_config.get_func()
    for filename in parser_blacklist.keys():
        times=int(parser_blacklist[filename])
        # check the update frequency
        if(flgnum%times==0):
            # command='python %s'%fpath
            try:
                df = __import__('get_blacklist.{}'.format(filename), fromlist=True)
                df.main()
                # status=os.system(command)
                # print status
            except Exception,e:
                # print e
                mylog.info(e)

def main(tday,flgnum):
    mylog=blacklist_tools.getlog()
    # print("Starting update command."), time.ctime()
    mylog.info("Starting update command.")
    # dirpath=".\data\\%s\\"%tday
    dirpath=parser_config.get_store_path()[1]+str(tday)+os.path.sep
    if(not os.path.exists(dirpath)):
        os.mkdir(dirpath)
    update_blacklist_module(flgnum)
    # print("update finish."), time.ctime()
    mylog.info("update finish.")