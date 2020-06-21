import nmap

nm = nmap.PortScanner()
nm.scan(hosts = '121.196.0.49',arguments = '-sV -Pn -sS -p 80')
a = nm['121.196.0.49']['tcp']
print(a)
