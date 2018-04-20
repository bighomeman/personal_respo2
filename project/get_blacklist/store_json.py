# -*- coding: utf-8 -*-
import json
import datetime
import project.parser_config


def store_json(dict,name):
	'''
	保存为json
	'''
	tday = datetime.datetime.now().date()
	file_name = name+ '.json'
	savepath=project.parser_config.get_store_path()[1]+str(tday)+'\\'+file_name

	try:
		with open(savepath,'w') as f:
			f.write(json.dumps(dict))
	except IOError:
		print 'Error'

if __name__ == '__main__':
	dict={}
	name='1'
	store_json(dict,name)