#! /usr/bin/python3
# -*- coding: utf-8 -*-
import xml.etree.ElementTree as ET
import argparse
from argparse import RawTextHelpFormatter
import os
import sys
import tempfile
import subprocess
import time
from multiprocessing import Process

services = {}
NAME_MAP = {"ms-sql-s": "mssql",
            "shell": "rsh",
            "exec": "rexec",
            "login": "rlogin",
            "snmptrap": "snmp"}
input_service = 'all'
input_thread = '10'
input_hosts = '1'
wordlist_path = os.path.join(os.getcwd(), 'wordlist')
class colors:
    white = "\033[1;37m"
    normal = "\033[0;00m"
    red = "\033[1;31m"
    blue = "\033[1;34m"
    green = "\033[1;32m"
    lightblue = "\033[0;34m"
banner = colors.red + r"""
                              #@                           @/              
                           @@@                               @@@           
                        %@@@                                   @@@.        
                      @@@@@                                     @@@@%      
                     @@@@@                                       @@@@@     
                    @@@@@@@                  @                  @@@@@@@    
                    @(@@@@@@@%            @@@@@@@            &@@@@@@@@@    
                    @@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@    
                     @@*@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@ @@     
                       @@@( @@@@@#@@@@@@@@@*@@@,@@@@@@@@@@@@@@@  @@@       
                           @@@@@@ .@@@/@@@@@@@@@@@@@/@@@@ @@@@@@           
                                  @@@   @@@@@@@@@@@   @@@                  
                                 @@@@*  ,@@@@@@@@@(  ,@@@@                 
                                 @@@@@@@@@@@@@@@@@@@@@@@@@                 
                                  @@@.@@@@@@@@@@@@@@@ @@@                  
                                    @@@@@@ @@@@@ @@@@@@                    
                                       @@@@@@@@@@@@@                       
                                       @@   @@@   @@                       
                                       @@ @@@@@@@ @@                       
                                         @@% @  @@                 

""" + '\n' \
         + '\n NmapBrutes.py v1.0' \
         + '\n Created by: MissFeng' + colors.normal

def nmap_xml(xml_file):
    '''解析nmap xml文件'''
    global services
    supported = ['ssh', 'ftp', 'telnet', 'mysql', 'ms-sql-s', ''
                 'vnc', 'imap', 'imaps', 'nntp', 'pop3', 'pop3s',
                 'redis', 'smtp', 'smtps', 'snmp', 'smb', 'exec', 'login', 'shell']
    tree = ET.parse(xml_file)
    root = tree.getroot()
    for host in root.iter('host'):
        ipaddr = host.find('address').attrib['addr']
        for port in host.iter('port'):
            cstate = port.find('state').attrib['state']
            if cstate == "open":
                try:
                    name = port.find('service').attrib['name']
                    tmp_port = port.attrib['portid']
                    iplist = ipaddr.split(',')
                except:
                    continue
                if name in supported:
                    name = NAME_MAP.get(name, name)
                    if name in services:
                        if tmp_port in services[name]:
                            services[name][tmp_port] += iplist
                        else:
                            services[name][tmp_port] = iplist
                    else:
                        services[name] = {tmp_port: iplist}

def parse_args():
    parser = argparse.ArgumentParser(formatter_class=RawTextHelpFormatter, description= \
    "Usage: python3 NmapBrutes.py <OPTIONS> \n")
    menu_group = parser.add_argument_group(colors.lightblue + 'Menu Options' + colors.normal)
    menu_group.add_argument('-f', '--file', help="Nmap扫描结果xml格式文件", required=False, default=None)
    args = parser.parse_args()
    if args.file is None:
        parser.error("argument -f/--file is required")
    return args

def check_xml(filename):
    with open(filename) as f:
        line = f.readlines()
        if '<?xml ' not in line[0]:
            f.close()
            print(f'{filename} 不是有效的xml文件!\n')
            sys.exit(0)
    nmap_xml(filename)
    if not services:
        print(f'{filename}文件里未找到有效端口服务可以进行暴力破解')
        sys.exit(0)

def interactive():
    global input_service, input_thread, input_hosts
    print(colors.white + "\n\n欢迎使用NmapBrutes工具交互界面!\n" + colors.normal)
    print("解析Nmap扫描结果找到:")
    for serv in services:
        for prt in services[serv]:
            iplist = services[serv][prt]
            port = prt
            plist = len(iplist)
            print("Service: " + colors.green + str(serv) + colors.normal + " on port " + colors.red + str(
                port) + colors.normal + " with " + colors.red + str(plist) + colors.normal + " hosts")

    input_service = input('\n' + colors.lightblue + '请根据输出提示输入要暴力破解的服务名(ssh,ftp,telnet)，默认为全部服务: ' + colors.red)
    input_thread = input(colors.lightblue + '请输入同一个服务运行的线程数，默认为10: ' + colors.red)
    input_hosts = input(colors.lightblue + '请输入同时破解的主机数，默认为1: ' + colors.red)
    if input_service == '':
        input_service = 'all'
    if input_thread == '':
        input_thread = '10'
    if input_hosts == '':
        input_hosts = '1'
    print(colors.normal)

def brute(service,port,fname):
    userlist = os.path.join(os.path.join(wordlist_path, service), 'user')
    passlist = os.path.join(os.path.join(wordlist_path, service), 'password')
    cmd = ['hydra', '-M', fname, '-L', userlist, '-P', passlist, '-s', port, '-t', input_thread, '-T', input_hosts, '-F', '-vV', '-I', service]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, bufsize=-1)
    out = "[" + colors.green + "+" + colors.normal + "] "
    output_file = 'results' + '/' + port + '-' + service + '-success.txt'
    for line in iter(p.stdout.readline, b''):
        print(line.decode('utf-8').strip('\n'))
        sys.stdout.flush()
        time.sleep(0.0001)
        if 'host' in line.decode('utf-8'):
            f = open(output_file, 'a')
            f.write(out + line.decode('utf-8'))
            f.close()

if __name__ == '__main__':
    print(banner)
    args = parse_args()
    if os.system("command -v hydra > /dev/null") != 0:
        sys.stderr.write("你的电脑上尚未安装hydra工具，请安装后在使用")
        sys.exit(3)

    if args.file is None:
        sys.exit(0)

    if not os.path.isdir(wordlist_path):
        print(f'当前目录下未找到程序默认密码字典wordlist目录')
        sys.exit(0)

    if os.path.isfile(args.file):
        check_xml(args.file)
    else:
        print(f'{args.file}文件不存在')
        sys.exit(0)

    try:
        tmppath = tempfile.mkdtemp(prefix="nmapbrutes-tmp")
    except Exception as e:
        print(f'创建临时文件错误:{e}')
        sys.exit(0)

    if not os.path.isdir('results'):
        os.mkdir('results')

    interactive()
    to_scan = input_service.split(',')
    for service in services:
        if service in to_scan or to_scan == 'all':
            for port in services[service]:
                fname = tmppath + '/' + service + '-' + port
                iplist = services[service][port]
                f = open(fname, 'w+')
                for ip in iplist:
                    f.write(ip + '\n')
                f.close()
                print(service, port, fname)
                brute_process = Process(target=brute, args=(service, port, fname))
                brute_process.start()