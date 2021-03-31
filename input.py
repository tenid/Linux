import matplotlib.pyplot as plt
import numpy as np
exp = []

f= open("log.txt",'r')
while True: #배열에 데이터 2차원 배열에 넣기
    line = f.readline()
    if not line: break
    str = []
    str.append(int(line[0:8].strip()))       #index
    str.append(int(line[8:16].strip()))      #protocol
    str.append(line[16:24].strip())     #transaction_id
    time=line[24:].strip('\n').split('.')    #sec.msec 나누기
    str.append(int(time[0]))     #sec
    str.append(int(time[1]))     #msec
    exp.append(str)
f.close()

dns =[]
icmp = []
http = []
https = []


for i in exp:
    if i[1] == 53: #dns 이면
        for j in exp:
            if i[2]==j[2] and i[0]!=j[0] and i[0]<j[0] : #transaction_id가 같고 index가 다를경우
                msec = j[4]-i[4]
                sec = j[3]-i[3]
                if msec<0:
                    sec = sec -1
                    msec = 10000000+msec #1.000000 => 1.0
                temp = []
                temp.append(sec)
                temp.append(msec/1000000)
                dns.append(temp)

    elif i[1] == 1: #icmp 이면
        for j in exp: #앞의 icmp 패킷과 시간 차이 계산
            if i[1]==j[1] and i[0]+1==j[0] :
                msec = j[4] - i[4]
                sec = j[3] - i[3]
                if msec<0:
                    sec = sec -1
                    msec = 10000000+msec #1.000000 => 1.0
                temp = []
                temp.append(sec)
                temp.append(msec/1000000)
                icmp.append(temp)
dns_len = list(range(1,len(dns)+1))
icmp_len = list(range(1,len(icmp)+1))
http_len = list(range(1,len(http)+1))
https_len = list(range(1,len(https)+1))

dns_exp =[]
icmp_exp = []
http_exp = []
https_exp = []

for i in dns:
    dns_exp.append(i[0]+i[1])
for i in icmp:
    icmp_exp.append(i[0]+i[1])

fig = plt.figure()
#plt.title('Packet Response Time (HTTP,HTTPS,DNS,ICMP)')


plt.subplot(221)
ax1 = fig.add_subplot(2,2,1)
plt.plot(dns_len,dns_exp,'b',label='DNS')
ax1.set_xticks(dns_len)
plt.xlabel('index')
plt.ylabel(' time')
plt.legend(loc='upper right')

plt.subplot(222)
ax2 = fig.add_subplot(2,2,2)
plt.plot(icmp_len,icmp_exp,'r',label='ICMP')
ax2.set_xticks(icmp_len)
plt.xlabel('index')
plt.ylabel(' time')
plt.legend(loc='upper right')

plt.show()









