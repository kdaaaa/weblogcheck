# weblogcheck
`web日志` `web日志分析` `安全软件`
#### web应急场景下，没有安全设备，需要手工分析大量weblog；一直苦于没有好用的工具，类如360星图也是15年之后没有更新，缺少新漏洞的特征；故自己动手丰衣足食

工具思路：

         1、简单粗暴，直接进行字符串匹配，无需考虑log格式
         
         2、现内置web_uri漏洞利用规则300+
         
         3、规则组合检测率较高

         
迭代方向：

         1、通用规则补充

         2、机器学习识别日志格式进行处理
         
         3、机器学习对同一IP访问路径进行分析，发现爆破、逻辑漏洞利用等场景
         
         4、对POST、GET等请求方式进行区分分析
         
不足之处：

         1、对于通用uri漏洞利用无法检测，例如漏洞利用路径为：/admin、/login等
         
         2、weblog本身仅保存信息有限，工具仅能辅助查询

使用样例：

![image](https://github.com/kdaaaa/weblogcheck/assets/53358699/b029383a-d0ba-48f5-aaf4-f312d8afe148)

输入结果：
匹配到规则 (行号 `x`):  `“原始日志”`  规则名称: `xxxx`
