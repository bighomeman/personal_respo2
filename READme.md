# personal_respo2

This is a monitor for checking your host access c&c host by dns request.

The dns-blacklist are collected from open Information web site against malware.

About get_blacklist profile #you can extend data from other's Information web. Writing parsing data py-script into this profile. #Then enhancing the checking scale of monitor.

(1)please keep a funtion 'return dict' like this: the format like:

{ 'tcp or dns ip':

  { 
  
    'type':malware type
  
    'date':add date 'source':information web
    
    'status':online or offline
    
    'false_positive':'unknown' or 'low' or 'high' #misreporting rate for source web
    
    'level':'WARNING'or 'critical' #decide it by youself
    
  },
  
  '...':
  
  {
    .... #other dict date
  },
  
} #you can find example in project/get_blacklist profile

(2) add new file in blacklist_match.conf. sperate by ',' do not add ',' in the end. 

#example : fun1 = ransomwaretracker , malwaredomainlist , zeustracker , malwaredomains keep python file name consisting with configue name.

(3) 'from save_json.py import save_json' function write json file. you can find it at example file's end
