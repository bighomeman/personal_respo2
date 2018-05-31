# personal_respo2
前言
本程序用于获取网络情报，针对imap中记录的目的ip地址进行检查，若目的ip与情报中出现的ip匹配，则发出告警信息，并将告警信息写入ES中。

本程序需在Linux环境下运行，基于python 2.7语法规范编写，主要的相关依赖包如下：
json、logging、datetime、time、elasticsearch、ConfigParser、socket、struct、re、requests、bs4、lxml

本程序GitHub地址为：https://github.com/sh9369/personal_respo2

1. GitHub主页上使用zip打包下载得personal_respo2-master.zip，解压后得personal_respo2文件夹；或使用git clone 命令直接下载。主要的文件目录形式如下：
personal_respo2:
——project：程序主文件目录
————data: 程序数据存放目录
——————log：日志文件目录
——————self_blacklist：本地黑名单文件目录
——————self_defaultlist：本地默认情报源目录
——————self_whitelist：本地白名单文件目录
————get_blacklist：网络情报源处理文件存放目录
——————MiningServerIPList.py：具体处理网络情报的文件
——————  ......
————lpm: lpm算法集成目录
————blacklist_match.conf：程序配置文件
————blacklist_tools：程序公共函数方法文件
————match_insert.py：匹配以及插入ES操作文件
————ontime_run.py：主运行程序
————parser_config.py：配置文件操作函数文件
————subnet_range.py：IP子网段处理函数文件
————treat_ip.py：IP操作处理函数文件
————update_blacklist.py：更新网络情报源函数文件

2.运行前，对blacklist_match.conf文件进行配置参数的修改：
2.1 修改[frequency]下的sharttime，表示开始检查时间；
2.2 修改[ES_info]下对应的server/dport信息；
2.3 若需启动本地黑名单，请在[self_blacklist_path]下令blacklist_flg=1，path对应于本地黑名单的默认目录；
白名单和默认情报源的启动设置与黑名单一致。

3.安装完成对应python版本以及依赖包后，进入/project目录下使用以下命令启动程序：
nohup python ontime_run.py & 
【再次回车】
使用以下命令查看日志文件：
tail -50f ./data/log/testlog
日志文件会记录程序运行中的相关信息，当看到日志文件不断写入内容后表示程序已经运行。

4.增加网络情报源的方法
4.1 在/get_blacklist目录下新建一个处理文件，假设为XXX.py；
4.2 在XXX.py中编写完整的情报下载/清晰/存储过程，务必保证最终存储的数据格式如下：
{
"ip1":
  {    #具体属性域请参考其他处理文件
     “subtype”：“mining_pool”
      “desc_subtype”：“... ... "
       ... .... 
  }
"ip2":
  {
     ... ...
  }
  ... ... 
}
4.3 确定网络情报数据源的更新频率，在blacklist_match.conf文件中[parse_blacklist]下的fun1末尾添加“,XXX:frequency"
