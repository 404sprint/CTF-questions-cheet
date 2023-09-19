# SQL注入

[2019极客大挑战]EASYSQL-----01------万能密码
[SUCTF]EASYSQL-------------01------堆叠注入
[极客大挑战 2019]LoveSQL----01------普通注入
[极客大挑战 2019]BabySQL----02------双写绕过
[极客大挑战 2019]HardSQL----03------报错注入---过滤空格
[CISCN2019 华北赛区 Day2 Web1]Hack World----03---盲注-----三目运算符
[GYCTF2020]Blacklist-------03------堆叠注入
[SWPU2019]Web1-------------05------mysql.innodb_table_stats(无列名)
[极客大挑战 2019]FinalSQL---06------异或盲注
[WUSTCTF2020]颜值成绩查询---06------异或盲注
[CISCN2019 华北赛区 Day1 Web5]CyberPunk-----07----二次注入
[NCTF2019]SQLi-------------08------正则注入
[网鼎杯 2018]Comment-------08-----二次注入、git、BF
[网鼎杯2018]Unfinish------   -----二次注入
October 2019 Twice SQL Injection--二次注入
------类型------


# 文件上传

[极客大挑战 2019]Upload-------02

[ACTF2020 新生赛]Upload-------01-----删js脚本--

https://blog.csdn.net/Obs_cure/article/details/113777386

[SUCTF 2019]CheckIn----------02-------.user.ini--
[MRCTF2020]你传你🐎呢--------03-------.htaccess-
[GXYCTF2019]BabyUpload--------03
[WUSTCTF2020]CV Maker---------07------普通上传
[SWPUCTF 2018]SimplePHP-------08------上传+phar


# 文件包含

Include1-------php://filter-------01
[极客大挑战 2019]Secret File-----302抓包+伪协议----01
[BJDCTF2020]ZJCTF，不过如此------data+filter+非法变量转换特性------04
[BSidesCF 2020]Had a bad day---------目录遍历----------04
[NPUCTF2020]ezinclude--------08-----临时文件包含php segment fault

>fuzz脚本

    ```php
    import requests
    
    for i in range(0,256):
        url=""+chr(i) #根据具体场景改变
        #print url
        r=requests.get(url)
        if '(被替换的内容)' in r.vontent:
            print str(i)+':'+chr(i)# 打印出是哪个字符被过滤了
    ```



# 命令执行

[ACTF2020 新生赛]Exec--------01--------无过滤
[GXYCTF2019]Ping Ping Ping---01--------源码泄露
[RoarCTF 2019]Easy Calc-----02---------PHP特性代码执行
[GXYCTF2019]禁止套娃--------03----------无参rce
[BJDCTF2020]The mystery of ip----04----PHP特性代码执行
[极客大挑战 2019]RCE ME--------06-------取反RCE
[FBCTF2019]RCEService---------06-------绕过preg_match
[红明谷CTF 2021]write_shell----07-------短标签

# php特性

[ACTF2020 新生赛]BackupFile--02-----intval()、弱比较
[极客大挑战 2019]BuyFlag-----02-----科学计数、弱比较
[BJDCTF2020]Easy MD5--------02-----md5数组弱比较
[MRCTF2020]Ez_bypass--------03
[GWCTF 2019]我有一个数据库---04
[BJDCTF2020]Mark loves cat---04
[安洵杯 2019]easy_web--------04
[ASIS 2019]Unicorn shop------04
[WUSTCTF2020]朴实无华--------04-----intval、md5绕过、命令执行
[CISCN 2019 初赛]Love Math---05
[De1CTF 2019]SSRF Me---------06
[SUCTF 2019]Pythonginx-------06-----inda
[MRCTF2020]套娃--------------06--空格转下划线、preg_match绕过、js代码运行、
[HarekazeCTF2019]encode_and_encode---08----json_encode()绕过
[BJDCTF2020]EzPHP---09----PHP特性集合,url解析、换行绕过preg_match、sha强比较、变量覆盖,这道过于繁琐

# 反序列化

[极客大挑战 2019]PHP---------------02---魔法函数绕过
[ZJCTF 2019]NiZhuanSiWei----------02---伪协议+反序列化
[网鼎杯 2020 青龙组]AreUSerialz----03---普通
[网鼎杯 2020 朱雀组]phpweb---------04---命令执行+反序列化
[0CTF 2016]piapiapia--------------04---字符逃逸
[安洵杯 2019]easy_serialize_php---05---减字符逃逸-带php变量覆盖特性
[MRCTF2020]Ezpop------------------05---pop链
[NPUCTF2020]ReadlezPHP------------05

# 模板注入

[护网杯 2018]easy_tornado-------01
[CISCN2019 华东南赛区]Web11-----06
[RootersCTF2019]I_<3_Flask------  -----flask模板
[CISCN2019 华东南赛区]Double Secret---08---jinjia2模板

# CSRF

[极客大挑战 2019]Http



# SSRF



# jwt

[HCTF2018-admin]
https://blog.csdn.net/weixin_44677409/article/details/100733581

[watevrCTF-2019]Cookie Store----07-----cookie认证


# Nodejs

[HFCTF2020]JustEscape----09----vm2沙箱逃逸

# XSS



# XXE



# 其他

[网鼎杯 2020 朱雀组]Nmap
[MRCTF2020]PYWebsite-------05
[BSidesCF 2019]Kookie------06
[GXYCTF2019]StrongestMind-----09---爬虫脚本
[GKCTF 2021]easycms-------09----目录扫描，爆破，任意文件下载

# 框架漏洞

[GYCTF2020]EasyThinking-----09-----tp6.0，session getshell,disabe_functions
