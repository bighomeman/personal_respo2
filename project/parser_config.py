import ConfigParser
import re,datetime,time

cp = ConfigParser.ConfigParser()
cp.read("blacklist_match.conf")
section = cp.sections()
# print section
def get_func():
    parse_blacklist_key = cp.options(section[0])
    # print parse_blacklist_key
    #function module
    moudle_func = cp.get("parse_blacklist", parse_blacklist_key[0])
    moudle_list = moudle_func.split(',')
    # print moudle_list
    moudle_name = []
    for temp in moudle_list:
        temp = temp.strip()
        moudle_name.append(temp)
    return moudle_name

def get_store_path():
    #source_data_path
    source_store_path_key = cp.options(section[1])
    # print source_store_path_key
    source_store_path = []
    for temp in source_store_path_key:
        source_store_path.append(cp.get('source_store_path', temp))
    return source_store_path

def get_module_path():
    #source_data_path
    module_path_key = cp.options(section[2])
    # print module_path_key
    module_path = []
    for temp in module_path_key:
        module_path.append(cp.get('blacklist_moudle_path', temp))
    return module_path

#############################################################################################################################


#
# # print frequency

def match_period():
    frequency_key = cp.options(section[3])
    frequency = []
    for temp in frequency_key:
        frequency.append(cp.get('frequency', temp))
    regex1=re.compile(r'\d+')
    regex2=re.compile(r'[a-zA-Z]+')
    period_num = regex1.findall(frequency[1])[0]
    period_scale = regex2.findall(frequency[1])[0]

    if frequency[0] == 'now':
	frequency[0] = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time())) 

    period = []
    period.append(frequency[0])
    if period_scale == 's'or period_scale == 'S':
        period.append(datetime.timedelta(seconds = int(period_num)))
    elif period_scale == 'm'or period_scale == 'M':
        period.append(datetime.timedelta(minutes = int(period_num)))
    elif period_scale == 'd' or period_scale == 'D':
        period.append(datetime.timedelta(days = int(period_num)))
    return period
#############################################################################################################################
