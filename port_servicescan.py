import queue
import threading
import time
import os
import subprocess
import json
import nmap
import xlsxwriter
from tqdm import tqdm

portqueue = queue.Queue(maxsize=0)
queueLock = threading.Lock()
ip_Scanlist = []  # 定义一个被扫的IP列表
ip_Scanlist_namp = [] # 这里list主要放masscan扫不出东西,单独用nmap扫描

class myThread (threading.Thread):
    def __init__(self, threadID,ip_Scan,portqueue):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.q = portqueue
        self.ip = ip_Scan
    def run(self):
        process_data(self.threadID,self.q,self.ip)

def process_data(threadID,q,ip):
    while not exitFlag:
        queueLock.acquire()
        if not portqueue.empty():
            #print('线程ID' + '_' + str(threadID))
            port = q.get()
            port_service_Scan(ip,port)
            queueLock.release()
        else:
            queueLock.release()
        time.sleep(0.5)


# ip地址预处理
def ip_Handle():
    try:
        r = open(r'ip.txt','r+')
        for ip in r.readlines():
            # 预处理C段IP
            if '/24' in ip:
                for i in range(0,255):
                    ip_Scanlist.append(ip.rstrip('0/24\n') + str(i))

            # 预处理间断IP
            elif '-' in ip:
                ip_list = ip.rstrip('\n').split('-')
                num_01 = int(ip_list[0].split('.')[3])
                num_02 = int(ip_list[1].split('.')[3])
                for i in range(num_01,num_02 + 1):
                    ip_Scanlist.append(ip_list[0].split('.')[0] + '.' + ip_list[0].split('.')[1] + '.' + ip_list[0].split('.')[2] + '.' + str(i))

            # 单个IP不做处理
            else:
                ip_Scanlist.append(ip.rstrip('\n'))
        r.close()

    except Exception as e:
        e
        pass
    finally:
        ip_port_Scan(ip_Scanlist)

# 端口多线程扫描
def thread_main(ip_Scan,ports_list):
    global exitFlag
    threads = []
    thread_nums = 10
    threadID = 1
    exitFlag = 0

    # 创建线程对象
    for i in range(0,thread_nums):
        thread = myThread(threadID,ip_Scan,portqueue)
        thread.start()
        threads.append(thread)
        threadID += 1

    # 填充队列
    queueLock.acquire()
    for port in ports_list:
        portqueue.put(port)
    queueLock.release()

    # 等待队列清空
    while not portqueue.empty():
        pass

    # 通知线程是时候退出
    exitFlag = 1

    # 等待所有线程完成
    for t in threads:
        t.join()


# Masscan端口扫描
def ip_port_Scan(ip_Scanlist):
    ports_list = []
    for ip_Scan in tqdm(ip_Scanlist,desc='Processing',ncols=70):
        cmd = 'masscan '+ ip_Scan + ' --ports 3300-4400,80,443 -oJ masscan.json --rate 100'
        result = subprocess.run(cmd,shell=True,text=True,stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        with open('masscan.json', 'r+') as f:
            for line in f:
                if line.startswith('{'):
                    date = json.loads(line[:-2])
                    ports = date['ports'][0]['port']
                    ports_list.append(ports)
        f.close()

        if len(ports_list) > 50:   # 判断是否为防火墙,设置一个端口阈值
            ports_list.clear()
        else:
            thread_main(ip_Scan,ports_list)
        ports_list.clear()


# nmap端口服务扫描
def port_service_Scan(ip,port):
    # print(ip)
    nm = nmap.PortScanner()
    nm.scan(hosts = ip,arguments = '-sV -Pn -sS -p ' + str(port))
    try:
        if nm[ip]['tcp'][port]['state'] == 'open':
            portinfo = nm[ip]['tcp'][port]
            global row
            row = row + 1
            if portinfo['name'] == 'http' and portinfo['tunnel'] == '':
                url = 'http://' + ip + ':' + str(port)
                data = (ip, str(port), 'open', portinfo['name'], portinfo['product'], url)
                worksheet.write_row('A' + str(row), data)
            elif portinfo['name'] == 'http' and 'ssl' in portinfo['tunnel']:
                url = 'https://' + ip + ':' + str(port)
                data = (ip, str(port), 'open', 'https', portinfo['product'], url)
                worksheet.write_row('A' + str(row), data)
            else:
                data = (ip, str(port), 'open', portinfo['name'], portinfo['product'])
                worksheet.write_row('A' + str(row), data)
    except KeyError:
        pass

if __name__ == '__main__':
    row = 1
    workbook = xlsxwriter.Workbook(r'port_servicescan.xlsx')
    worksheet = workbook.add_worksheet('IP')
    data = ('IP','端口','状态','协议','服务','URL')
    worksheet.write_row('A1',data)
    ip_Handle()
    workbook.close()
