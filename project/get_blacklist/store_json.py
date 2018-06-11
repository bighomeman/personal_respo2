# -*- coding: utf-8 -*-
import json
import datetime
import sys,os
sys.path.append('..')
from project import parser_config
from project import blacklist_tools

def store_json(dict,name):
	'''
	保存为json
	'''
	mylog=blacklist_tools.getlog()
	tday = datetime.datetime.now().date()
	file_name = name+ '.json'
	savepath=parser_config.get_store_path()[1]+str(tday)+os.path.sep+file_name

	try:
		with open(savepath,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		# print 'store_json Error'
		mylog.warning('change date time!download again!')

if __name__ == '__main__':
	dict={}
	name='1'
	store_json(dict,name)