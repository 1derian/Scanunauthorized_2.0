# Scanunauthorized2.0 一键批量检测各种未授权访问漏洞

## 新增功能

```
1.在原来的基础上新增kibana的未授权访问检测
2.支持指定未授权的检测
3.支持指定文件检测
4.友好的使用提示
```

## 安装

```
python >= 3.7
pip3 install -r requirements.txt
```

## 使用

```shell
# 查看使用帮助
python3 Scanunauthorized_2.0.py -h

# 指定文件检测 , 默认-f参数的值为host.txt , 默认结果输出到success.txt
python3 Scanunauthorized_2.0.py -f ip.txt -c redis

# 指定未授权的检测
python3 Scanunauthorized_2.0.py -f ip.txt -c jboss

# 使用所有未授权模块检测
python3 Scanunauthorized_2.0.py -f ip.txt -c all
```

## 参考

https://github.com/test502git/Scanunauthorized

## 免责声明🧐

本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。

在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行扫描。

如您在使用本工具的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。
