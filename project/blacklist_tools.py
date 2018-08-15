#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import json
import os
import logging
from logging.handlers import TimedRotatingFileHandler

def judge_level(fp,status):
	'''
	根据fp、status判断level
	'''
	if status == 'online':
		if fp == 'high':
			return 'WARNING'
		else:
			return 'CRITICAL'
	elif status == 'unknown':
		if fp == 'low':
			return 'CRITICAL'
		elif fp == 'high':
			return 'INFO'
		else:
			return 'WARNING'
	else:
		if fp == 'low' or fp == 'unknown':
			return 'WARNING'
		else:
			return 'INFO'


def judge_unknown(str1,str2):
	'''
	两个情报源发现相同的domain时，整合情报，判断fp与status的值
	'''
	if str1 == str2:
		return str1
	elif str1 != 'unknown' and str2 !='unknown':
		return 'unknown'
	elif str1 != 'unknown':
		return str1
	elif str2 != 'unknown':
		return str2

def judge_date(str1,str2):
	'''
	两个情报源发现相同的domain时，记录最近的时间整合情报
	'''
	if str1 == str2:
		return str1
	else:
		date1 = datetime.datetime.strptime(str1,'%Y-%m-%d')
		date2 = datetime.datetime.strptime(str2,'%Y-%m-%d')
		if date1>date2:
			return date1.strftime('%Y-%m-%d')
		else:
			return date2.strftime('%Y-%m-%d')

def update_dict(dict1,dict2):
	'''
	合并两个字典
	'''
	domain_insection = set(dict1.keys()) & set(dict2.keys())
	print domain_insection
	ret_dict = dict(dict1,**dict2)
	if domain_insection:
		for domain in domain_insection:
			ret_type = dict1[domain]['type'] +';'+ dict2[domain]['type']
			ret_source = dict1[domain]['source'] +';'+ dict2[domain]['source']
			ret_status = judge_unknown(dict1[domain]['status'],dict2[domain]['status'])
			ret_fp = judge_unknown(dict1[domain]['fp'],dict2[domain]['fp'])
			ret_date = judge_date(dict1[domain]['date'],dict2[domain]['date'])
			ret_dict[domain] = {
			'type':ret_type,
			'date':ret_date,
			'source':ret_source,
			'status':ret_status,
			'fp':ret_fp
			}
	return ret_dict 

def saveAsJSON(date,dict1,path,name):
	'''
	保存为json
	'''
	file_name = path + name + '-' + str(date) + '.json'
	try:
		with open(file_name,'w') as f:
			f.write(json.dumps(dict1))
	except IOError:
		print 'saveAsJSON Error'

def temp_store(dict,name):
	'''
	保存为json
	'''
	tmp=name[-5:]
	if(tmp=='.json'):
		file_name=name
	else:
		file_name = name+ '.json'
	try:
		with open(file_name,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		print 'temp_store Error'

def load_dict(filedir):
	'''
	加载本地的json文件
	'''
	dict1={}
	try:
		with open(filedir,'r') as f:
			dict1=json.loads(f.read())
	except IOError:
		print 'load_dict Error'
	return dict1

def insert(Trie,element):
	'''
	将element插入Trie
	'''
	if element:
		item=element.pop()
		if item not in Trie:
			Trie[item]={}
		Trie[item]=insert(Trie[item],element)
	return Trie

def create_Trie(blacklist):
	'''
	根据blacklist创建Trie
	'''
	domainTrie={}
	for domain in blacklist:
		domainTrie=insert(domainTrie,domain)
	return domainTrie

def getlog():
	mylog = logging.getLogger()
	if len(mylog.handlers) == 0:  # just only one handler
		level = logging.INFO
		filename = os.getcwd() + os.path.sep + 'data' + os.path.sep +'log'+ os.path.sep+ 'testlog'
		format = '%(asctime)s %(levelname)-8s: %(message)s'
		hdlr = TimedRotatingFileHandler(filename, "midnight", 1, 0)
		hdlr.suffix = "%Y%m%d.log"
		fmt = logging.Formatter(format)
		hdlr.setFormatter(fmt)
		mylog.addHandler(hdlr)
		mylog.setLevel(level)
	return mylog

def load_whitelist(whitepath):
	mylog = getlog()
	datadic = {}
	if (os.path.exists(whitepath)):
		# return  dataset,and type is dict
		with open(whitepath, 'r') as bf:
			allip = bf.read().split(',')
			for ips in allip:
				datadic[ips] = {
					'subtype':'whitelist',
					'desc_subtype': 'local whitelist ip'
				}
	else:
		mylog.info('no whitelist path!')
	return datadic


def load_blacklist(blackpath):
	mylog=getlog()
	datadic={}
	if (os.path.exists(blackpath)):
		#return  dataset,and type is dict
		try:
			with open(blackpath,'r') as bf:
				alllines=bf.read().split('\n')
				del alllines[0]# alllines[0] :ip,subtype,source
				for line in alllines:
					if(line):
						linelis=line.split(',')
						datadic[linelis[0]]={
							'subtype': linelis[1],
							'desc_subtype': '{} ip;source:{}'.format(linelis[1],linelis[2]),
							'level': 'info',
							'mapping_ip': linelis[0],
						}
		except Exception,e:
			mylog.error('load local blacklist:{}'.format(e))
	else:
		mylog.info('no blacklist path!')
	return datadic

#global module
def global_init():
	global _global_dic
	_global_dic={}
def set_global_value(name,value):
	_global_dic[name]=value
def get_global_value(name):
	try:
		return _global_dic[name]
	except Exception,e:
		return None