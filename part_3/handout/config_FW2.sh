###### Rules for FW3 ######

## FW3 is only used with FOWARD chain
iptables -P INPUT DROP
iptables -P OUTPUT DROP

## Stateful firewall
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

## Incoming traffic z-lweb

# 1. U1 to LWEB (ftp)
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.2.2 -p tcp --dport 21 -m conntrack --ctstate NEW -j ACCEPT
# 2. U1 to LWEB (http)
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.2.2 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
# 3. U2 to LWEB (http)
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.2.2 -p tcp --dport 80 -m conntrack --ctstate NEW -j ACCEPT
# 4. input deny
iptables -A FORWARD -d 10.10.2.0/24 -j LOG --log-prefix "fw2 - block in z-lweb"
iptables -A FORWARD -d 10.10.2.0/24 -j DROP

## Outgoing traffic z-lweb

# 5. output deny
iptables -A FORWARD -s 10.10.2.0/24 -j LOG --log-prefix "fw2 - block out z-lweb"
iptables -A FORWARD -s 10.10.2.0/24 -j DROP

## Incoming traffic z-u1

# 6. SSH to U1
iptables -A FORWARD -s 10.10.1.6 -d 192.168.1.0/24 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# 7. input deny
iptables -A FORWARD -d 192.168.1.0/24 -j LOG --log-prefix "fw2 - block in z-u1"
iptables -A FORWARD -d 192.168.1.0/24 -j DROP

## Outgoing traffic z-u1

# 8. U1 to HTTP
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.4 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT
# 9. U1 to LDNS
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.3 -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
# 10. U1 to LDNS
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.3 -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
# 11. U1 to MAIL (SMTP)
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.5 -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
# 12. U1 to MAIL (IMAP)
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.5 -p tcp --dport 143 -m conntrack --ctstate NEW -j ACCEPT
# 13. U1 to MAIL (IMAPS)
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.5 -p tcp --dport 993 -m conntrack --ctstate NEW -j ACCEPT
# 14. U1 to ssh
iptables -A FORWARD -s 192.168.1.0/24 -d 10.10.1.6 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT
# 15. DCHP_R1 to DHCP
iptables -A FORWARD -s 192.168.1.2 -d 10.10.1.2 -p udp --dport 67 -m conntrack --ctstate NEW -j ACCEPT
# 16. output deny
iptables -A FORWARD -s 192.168.1.0/24 -j LOG --log-prefix "fw2 - block out z-u1"
iptables -A FORWARD -s 192.168.1.0/24 -j DROP

## Incoming traffic z-u2

# 17. SSH to U2
iptables -A FORWARD -s 10.10.1.6 -d 192.168.2.0/24 -p tcp --dport 22 -m conntrack --ctstate NEW -j ACCEPT  
# 18. input deny
iptables -A FORWARD -d 192.168.2.0/24 -j LOG --log-prefix "fw2 - block in z-u2"
iptables -A FORWARD -d 192.168.2.0/24 -j DROP

## Outgoing traffic z-u2

# 19. U2 to HTTP
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.1.4 -p tcp --dport 3128 -m conntrack --ctstate NEW -j ACCEPT
# 20. U2 to LDNS
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.1.3 -p tcp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
# 21. U2 to LDNS
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.1.3 -p udp --dport 53 -m conntrack --ctstate NEW -j ACCEPT
# 22. U2 to MAIL (SMTP)
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.1.5 -p tcp --dport 25 -m conntrack --ctstate NEW -j ACCEPT
# 23. U2 to MAIL (IMAP)
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.1.5 -p tcp --dport 143 -m conntrack --ctstate NEW -j ACCEPT
# 24. U2 to MAIL (IMAPS)
iptables -A FORWARD -s 192.168.2.0/24 -d 10.10.1.5 -p tcp --dport 993 -m conntrack --ctstate NEW -j ACCEPT
# 25. DHCP_R2 to DHCP
iptables -A FORWARD -s 192.168.2.2 -d 10.10.1.2 -p udp --dport 67 -m conntrack --ctstate NEW -j ACCEPT
# 26. output deny
iptables -A FORWARD -s 192.168.2.0/24 -j LOG --log-prefix "fw2 - block out z-u2"
iptables -A FORWARD -s 192.168.2.0/24 -j DROP

## Incoming traffic z-all-sandwich

# 27. input deny
iptables -A FORWARD -d 10.10.1.0/24 -j LOG --log-prefix "fw2 - block in z-sandwich"
iptables -A FORWARD -d 10.10.1.0/24 -j DROP

## Outgoing traffic z-all-sandwich

# 28. output deny
iptables -A FORWARD -s 10.10.1.0/24 -j LOG --log-prefix "fw2 - block out z-sandwich"
iptables -A FORWARD -s 10.10.1.0/24 -j DROP

## Other

# 29. Should not happen. Log to be sure.
iptables -A FORWARD -j LOG --log-prefix "fw3 - deny any other forward"
iptables -A FORWARD -j DROP