
from scapy.all import *
conf.sniff_promisc=True ##promiscuous mode

Count=1000
Timeout=60

### reponse a un pkt-SYN ###
def synAns(x):
    #x.show()           #->detaille
    print x.summary()   #->simple
    pIp=IP(src=x[IP].dst, dst=x[IP].src)   #id,ttl??
    ans=pIp/TCP(sport=x[TCP].dport,dport=x[TCP].sport,seq=x[TCP].ack+27, ack=x[TCP].seq+1, flags=0b11) #seq?,dataofs?
    send(ans)


### filtres ###

# 0
def tcp(x):
    return x.haslayer(tcp)

# 1
def tcpSyn(x):     ##Syn-pkt filter
    return x.haslayer(TCP) and (x[TCP].flags>>1 & 1 ) #SYN bit=1

# 2
def tcpAck(x):      ##Ack-pkt filter
    return x.haslayer(TCP) and (x[TCP].flags>>4 & 1 ) #ACK bit=1


if len(sys.argv) >= 3:
    Count=int(sys.argv[2])

if len(sys.argv) >= 4:
    Timeout=int(sys.argv[3])

if len(sys.argv) < 2:
    print "SVP, selectionnez un filtre: 1 (TCP), 2 (Syn), 3 (Ack);\n", "optionnel: count, timeout"

else:
    filtre=sys.argv[1]
    s= "Count: " +repr(Count)+"; Timeout: " +repr(Timeout)
    print s
    
    if filtre == '0':
        print "Filtre TCP"
        sniff(count = Count,lfilter = tcp,prn = synAns, timeout = Timeout)

    if filtre == '1':
        print "Filtre TCP-Syn"
        sniff(count = Count,lfilter = tcpSyn, prn= synAns, timeout = Timeout)

    if filtre == '2':
        print "Filtre TCP-Ack"
        sniff(count = Count,lfilter = tcpAck, prn= synAns, timeout = Timeout)
