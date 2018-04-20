# -*- coding: utf-8 -*-
import parser_config, os,sys
from blacklist_tools import *
sys.dont_write_bytecode = True
import  treat_ip

# 存储原始数据
def get_blacklist_module():
    parse_blacklist = parser_config.get_func()
    for file_name in parse_blacklist:
         command = 'python .\get_blacklist\\' + file_name +'.py'
         try:
              status = os.system(command)
              print status
         except Exception, e:
                print e

def merge_blacklist(dir,date,name):
    parse_blacklist = parser_config.get_func()
    i = 0
    merge_result = {}
    for file_name in parse_blacklist:
        result = load_dict(file_name + '.json')
        if i == 0:
            merge_result = result
        else:
            merge_result = update_dict(result,merge_result)
        i = i+1
    # print merge_result
    saveAsJSON(date,merge_result,dir,name)

    for file_name in parse_blacklist:
        if os.path.exists(file_name+'.json'):
            os.remove(file_name+'.json')

#建Trie树

def get_resource(date):
    source_store_path =parser_config.get_store_path()
    path = source_store_path[1] + source_store_path[0] + "-" +date + '.json'
    result = load_dict(path)
    return result

def get_source_path(date):
    source_store_path =parser_config.get_store_path()
    path = source_store_path[1]
    return path

if __name__ == '__main__':
    if len(sys.argv)>1:
        source_store_path =parser_config.get_store_path()
        # trie_store_path = parser_config.trie_store_path
        get_blacklist_module()
        merge_blacklist(source_store_path[1],sys.argv[1],source_store_path[0])
        source_dict = get_resource(sys.argv[1])
        path = get_source_path(sys.argv[1])
        treat_ip.seperate_ip(sys.argv[1], source_dict, path)
        # store_trie(trie_store_path[1],sys.argv[1],trie_store_path[0])
    else:
        print '[ERROR] Insufficient number of input parameters'