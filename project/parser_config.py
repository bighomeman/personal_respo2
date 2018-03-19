import ConfigParser
import re,datetime

cp = ConfigParser.ConfigParser()
cp.read("blacklist_match.conf")
section = cp.sections()
# print section
def get_func():
    parse_blacklist_key = cp.options(section[0])
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
    source_store_path = []
    for temp in source_store_path_key:
        source_store_path.append(cp.get('source_store_path', temp))
    return source_store_path



# print cp.sections
#cun period
#############################################################################################################################
# frequency_key = cp.options(sections[3])
# frequency = []
# for temp in frequency_key:
#     frequency.append(cp.get('frequency', temp))
#
# # print frequency
# regex1=re.compile(r'\d+')
# regex2=re.compile(r'[a-zA-Z]+')
# period_num = regex1.findall(frequency[1])[0]
# period_scale = regex2.findall(frequency[1])[0]
# def export_period():
#     if period_scale == 's'or period_scale == 'S' :
#         period  = datetime.timedelta(seconds = int(period_num))
#     elif period_scale == 'm'or period_scale == 'M':
#         period = datetime.timedelta(minutes = int(period_num))
#     elif period_scale == 'd' or period_scale == 'D':
#         period = datetime.timedelta(days = int(period_num))
#     return period
#############################################################################################################################