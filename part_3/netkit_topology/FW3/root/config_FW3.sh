###### Rules for FW3 ######

## FW3 is only used with FOWARD chain
iptables -P INPUT DROP
iptables -P OUTPUT DROP

## Stateful firewall
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

## Incoming traffic z-nfs 

# 1. HONEYPOT to NFS (portmapper)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p tcp --dport 111 -m conntrack --ctstate NEW -j ACCEPT
# 2. HONEYPOT to NFS (portmapper)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p udp --dport 111 -m conntrack --ctstate NEW -j ACCEPT
# 3. HONEYPOT to NFS (status)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p tcp --dport 2046 -m conntrack --ctstate NEW -j ACCEPT
# 4. HONEYPOT to NFS (status)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p udp --dport 2046 -m conntrack --ctstate NEW -j ACCEPT
# 5. HONEYPOT to NFS (nlockmgr)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p tcp --dport 2047 -m conntrack --ctstate NEW -j ACCEPT
# 6. HONEYPOT to NFS (nlockmgr)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p udp --dport 2047 -m conntrack --ctstate NEW -j ACCEPT
# 7. HONEYPOT to NFS (mountd)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p tcp --dport 2048 -m conntrack --ctstate NEW -j ACCEPT
# 8. HONEYPOT to NFS (mountd)
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p udp --dport 2048 -m conntrack --ctstate NEW -j ACCEPT
# 9. HONEYPOT to NFS
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p tcp --dport 2049 -m conntrack --ctstate NEW -j ACCEPT
# 10. HONEYPOT to NFS
iptables -A FORWARD -s 192.168.3.2 -d 10.10.3.2 -p udp --dport 2049 -m conntrack --ctstate NEW -j ACCEPT
# 11. U3 to RSYNC
iptables -A FORWARD -s 192.168.3.3 -d 10.10.3.3 -p tcp --dport 873 -m conntrack --ctstate NEW -j ACCEPT
# 12. U3 to RSYNC (secured)
iptables -A FORWARD -s 192.168.3.3 -d 10.10.3.3 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# 13. SSH to RSYNC
iptables -A FORWARD -s 10.10.4.6 -d 10.10.3.3 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# 14. input deny
iptables -A FORWARD -d 10.10.3.0/24 -j DROP

## Outgoing traffic z-nfs 

# 15. output deny
iptables -A FORWARD -s 10.10.3.0/24 -j DROP

## Incoming traffic z-u3

# 16. SSH to HONEYPOT
iptables -A FORWARD -s 10.10.4.6 -d 192.168.3.2 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# 17. input deny
iptables -A FORWARD -d 192.168.3.0/24 -j DROP

## Outgoing traffic z-u3

# 18. U3 to SSH
iptables -A FORWARD -s 192.168.3.3 -d 192.168.3.0/24 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# 19. output deny
iptables -A FORWARD -s 192.168.3.0/24 -j DROP

## Incoming traffic z-ssh

# 20.input deny
iptables -A FORWARD -d 10.10.4.0/24 -j DROP

## Outgoing traffic z-ssh

# 21. output deny
iptables -A FORWARD -s 10.10.4.0/24 -j DROP

## Other

# 22. Should not happen. Log to be sure.
iptables -A FORWARD -j LOG
iptables -A FORWARD -j DROP
