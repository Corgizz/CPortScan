需要安装nmap和masscan
Windows环境：需要配置nmap和masscan环境变量

**特别注意：
脚本使用到python-nmap模块,无法识别https,需要修改模块脚本,方法见:
https://www.yuque.com/corgi/yfbm4o/wwlgor

Windows环境下
第一步：确保nmap和masscan安装和环境变量配置
执行nmap和masscan, 出现版本说明则没有问题

第二步：修改python-nmap模块, python-nmap模块不能识别https, 为了确保识别https需要修改
方法见：https://www.yuque.com/corgi/yfbm4o/wwlgor

第三步：ip.txt添加被扫描IP地址,支持三种格式(单个IP,某间断段IP,C端口IP)
192.168.10.0/24 (注：0/24结尾)
192.168.10.1-192.168.10.100
192.168.10.2

安装必要模块
pip3 install -r requirements.txt

使用方法
python3 port_servicescan.py
 ![image](https://github.com/Corgizz/CPortScan/blob/master/img/1.png)
