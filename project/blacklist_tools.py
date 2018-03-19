#!/usr/bin/python
# -*- coding: utf-8 -*-

import datetime
import json

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
		print 'Error'

def temp_store(dict,name):
	'''
	保存为json
	'''
	file_name = name+ '.json'
	try:
		with open(file_name,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		print 'Error'

def load_dict(filedir):
	'''
	加载本地的json文件
	'''
	try:
		with open(filedir,'r') as f:
			dict1=json.loads(f.read())
	except IOError:
		print 'Error'
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
