# coding=utf-8
import argparse
import ftplib, threading, requests, pymongo, pymysql, socket
import textwrap

import psycopg2
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import requests

R = threading.Lock()


def file_write(text):
    global R
    R.acquire()
    f = open('success.txt', 'a', encoding='utf-8').write(text + '\n')
    R.release()


def redis(ip, bar):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 6379))
        s.send(bytes("INFO\r\n", 'UTF-8'))
        result = s.recv(1024).decode()
        if "redis_version" in result:
            print(ip + ":6379 redis未授权")
            file_write(ip + ":6379 redis未授权")
        s.close()
    except Exception as e:
        # print(e)
        pass
    finally:
        pass
        bar.update(1)


def mongodb(ip, bar):
    try:
        conn = pymongo.MongoClient(ip, 27017, socketTimeoutMS=4000)
        dbname = conn.list_database_names()
        print(ip + ":27017 mongodb未授权")
        file_write(ip + ":27017 mongodb未授权")
        conn.close()
    except Exception as e:
        # print(e)
        pass
    finally:
        pass
        bar.update(1)


def memcached(ip, bar):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 11211))
        s.send(bytes('stats\r\n', 'UTF-8'))
        if 'version' in s.recv(1024).decode():
            # print(s.recv(2048).decode())
            print(ip + ":11211 memcached未授权")
            file_write(ip + ":11211 memcached未授权")
        s.close()
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def elasticsearch(ip, bar):
    try:
        url = 'http://' + ip + ':9200/_cat'
        r = requests.get(url, timeout=5)
        if '/_cat/master' in r.content.decode():
            print(ip + ":9200 elasticsearch未授权")
            file_write(ip + ":9200 elasticsearch未授权")
    except Exception as e:
        # print(e)
        pass
    finally:
        pass
        bar.update(1)


def zookeeper(ip, bar):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 2181))
        s.send(bytes('envi', 'UTF-8'))
        data = s.recv(1024).decode()
        s.close()
        if 'Environment' in data:
            print(ip + ":2181 zookeeper未授权")
            file_write(ip + ":2181 zookeeper未授权")
    except Exception as e:
        # print(e)
        pass
    finally:
        pass
        bar.update(1)


def ftp(ip, bar):
    try:
        ftp = ftplib.FTP()
        ftp.connect(ip, 21, timeout=5)  # 连接的ftp sever和端口
        ftp.login('anonymous', 'Aa@12345678')
        print(str(ip) + ":21 FTP未授权")
        file_write(str(ip) + ":21 FTP未授权")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def CouchDB(ip, bar):
    try:
        url = 'http://' + ip + ':5984' + '/_utils/'
        r = requests.get(url, timeout=5)
        if 'couchdb-logo' in r.content.decode():
            print(ip + ":5984 CouchDB未授权")
            file_write(ip + ":5984 CouchDB未授权")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def docker(ip, bar):
    try:
        url = 'http://' + ip + ':2375' + '/version'
        r = requests.get(url, timeout=5)
        if 'ApiVersion' in r.content.decode():
            print(ip + ":2375 docker api未授权")
            file_write(ip + ":2375 docker api未授权")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def Hadoop(ip, bar):
    try:
        url = 'http://' + ip + ':50070' + '/dfshealth.html'
        r = requests.get(url, timeout=5)
        if 'hadoop.css' in r.content.decode():
            print(ip + ":50070 Hadoop未授权")
            file_write(ip + ":50070 Hadoop未授权")
    except Exception as e:
        # print(e)
        pass
    finally:
        pass
        bar.update(1)


def rsync_access(ip, bar):
    try:
        socket.setdefaulttimeout(5)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip, 873))
        s.send(bytes("", 'UTF-8'))
        result = s.recv(1024).decode()
        # print(result)
        if "RSYNCD" in result:
            print(ip + ":873 可能存在rsync未授权,需要手工确认")
            file_write(ip + ":873 可能存在rsync未授权,需要手工确认")
        s.close()
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def mysql_Empty_pwd(ip, bar):
    try:
        conn = pymysql.connect(host=ip, user='root', password='', charset='utf8', autocommit=True)
        print(ip + ":3306 存在mysql空口令漏洞")
        file_write(ip + ":3306 存在mysql空口令漏洞")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def jenkins(ip, bar):
    try:
        url = 'http://' + ip + ':8080' + '/systemInfo'
        r = requests.get(url, timeout=8, verify=False)
        if 'jenkins.war' in r.content.decode() and 'JENKINS_HOME' in r.content.decode():
            print(ip + ":8080 发现jenkins 未授权")
            file_write(ip + ":8080 发现jenkins 未授权")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def jboss(ip, bar):
    try:
        url = 'http://' + ip + ':8080' + '/jmx-console/HtmlAdaptor?action=displayMBeans'
        r = requests.get(url, timeout=8, verify=False)
        if 'JBoss JMX Management Console' in r.content.decode() and r.status_code == 200 and 'jboss' in r.content.decode():
            print(ip + ":8080 发现jboss未授权访问")
            file_write(ip + ":8080 发现jboss未授权访问")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


def postgres(ip, bar):
    try:
        conn = psycopg2.connect(database="postgres", user="postgres", password="", host=ip, port="5432")
        print(ip + ":5432 存在postgres未授权")
        file_write(ip + ":5432 存在postgres未授权")
    except Exception as e:
        # print(e)
        pass
    finally:
        pass
        bar.update(1)


def kibana(ip, bar):
    try:
        url = f"http://{ip}:5601/app/kibana"
        headers = {"Upgrade-Insecure-Requests": "1",
                   "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.5005.63 Safari/537.36",
                   "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
                   "Accept-Encoding": "gzip, deflate", "Accept-Language": "zh-CN,zh;q=0.9,ja;q=0.8",
                   "Connection": "close"}
        res = requests.get(url, headers=headers,timeout=5,verify=False)
        # 存在误报,不准确
        if res.status_code == 200 and res.headers.get("content-security-policy"):
            print(ip + ":5601 存在 kibana 未授权")
            file_write(ip + ":5601 存在 kibana 未授权")
    except Exception as e:
        pass
    finally:
        pass
        bar.update(1)


# 目前支持：redis,Hadoop,docker,CouchDB,ftp,zookeeper,elasticsearch,memcached,mongodb,rsync_access,mysql,target,jenkins,target,jboss的未授权访问，检测速度快

def main(file_path, func):
    func_dic = {
        "redis": redis,
        "Hadoop": Hadoop,
        "docker": docker,
        "CouchDB": CouchDB,
        "ftp": ftp,
        "zookeeper": zookeeper,
        "elasticsearch": elasticsearch,
        "memcached": memcached,
        "rsync_access": rsync_access,
        "mysql_Empty_pwd": mysql_Empty_pwd,
        "jenkins": jenkins,
        "jboss": jboss,
        "postgres": postgres,
        "kibana": kibana,
    }

    ipfile = open(file_path, 'r', encoding='utf-8').read().split('\n')
    bar = tqdm(total=len(ipfile) * 14)
    pool = ThreadPoolExecutor(100)
    for target in ipfile:
        target = target.strip()
        # redis 不同的函数名
        # 先判断func是否存在
        if func not in func_dic:
            print("请输入存在的未授权的poc")
            return
        if func == 'all':
            for k in func_dic:
                func_name = func_dic.get(k)
                pool.submit(func_name, target, bar)
        else:
            func_name = func_dic.get(func)
            pool.submit(func_name, target, bar)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='未授权检测poc', formatter_class=argparse.RawDescriptionHelpFormatter,
                                     epilog=textwrap.dedent('''example:
        python3 Scanunauthorized_2.0.py -f host.txt -c redis
        -c [all,redis,Hadoop,docker,CouchDB,ftp,zookeeper,elasticsearch,
        memcached,mongodb,rsync_access,mysql_Empty_pwd,jenkins,jboss,postgres,kibana]
        '''))

    parser.add_argument("-f", "--file", default='host.txt', dest="file", help="input a file")
    parser.add_argument("-c", "--check", help="input a type")
    args = parser.parse_args()

    main(args.file, args.check)

    # 直接500个线程 , 你是真的猛
    # 需求 更改指定参数 , 检测不同的未授权 , all , 全部未授权检测
    # 新增kibana的检测
