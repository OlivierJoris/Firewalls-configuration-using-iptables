###### Rules for FW1 ######

# First, let us configure the nat table.
# SSH
iptables -t nat -A PREROUTING -p tcp -d 172.32.4.100 --dport 22 -j DNAT --to-destination 172.31.6.6:22
# SMTP
iptables -t nat -A PREROUTING -p tcp -d 172.32.4.100 --dport 25 -j DNAT --to-destination 172.31.6.5:25
# IMAPS
iptables -t nat -A PREROUTING -p tcp -d 172.32.4.100 --dport 993 -j DNAT --to-destination 172.31.6.5:993
# Allowing webteam to reach ssh in PWEB through SSH relay
iptables -t nat -A POSTROUTING -p tcp -s 172.31.6.6 -d 172.32.5.2 --dport 22 -j SNAT --to-source 172.32.4.100:22222
# Allowing access to web pages of PWEB to internal network.
iptables -t nat -A POSTROUTING -p tcp -s 172.31.5.4 -d 172.32.5.2 --dport 80 -j SNAT --to-source 172.32.4.100:8080
iptables -t nat -A POSTROUTING -p tcp -s 172.31.5.4 -d 172.32.5.2 --dport 443 -j SNAT --to-source 172.32.4.100:4430
# dynamic POSTROUTING
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# FW1 is only used with FOWARD chain
iptables -P INPUT DROP
iptables -P OUTPUT DROP

# Since we want a stateful firewall, we need to allow packets related to accepted connection.
# Thus, we need:
iptables -A FORWARD -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

# Now, let us accept the desired traffic.

# 1) Internet -> IMAPS
iptables -A FORWARD -p tcp -d 172.31.6.5 --dport 993 -m conntrack --ctstate NEW -j ACCEPT

# 2) Internet -> SMTP
iptables -A FORWARD -p tcp -d 172.31.6.5 --dport 25 -m conntrack --ctstate NEW -j ACCEPT

# 3) Internet -> SSH
iptables -A FORWARD -p tcp -d 172.31.6.6 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# 4) Deny in z-mail-ssh
iptables -A FORWARD -d 172.31.6.0/24 -j LOG --log-prefix "fw1 - block in z-mail-ssh"
iptables -A FORWARD -d 172.31.6.0/24 -j DROP

# 5) SSH -> Internet
iptables -A FORWARD -p tcp -s 172.31.6.6 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# 6) MAIL (SMTP) -> Internet
iptables -A FORWARD -p tcp -s 172.31.6.5 --dport 25 -m conntrack --ctstate NEW -j ACCEPT

# 7) Deny out z-mail-ssh
iptables -A FORWARD -s 172.31.6.0/24 -j LOG --log-prefix "fw1 - block out z-mail-ssh"
iptables -A FORWARD -s 172.31.6.0/24 -j DROP

#8) Deny in z-http
iptables -A FORWARD -d 172.31.5.0/24 -j LOG --log-prefix "fw1 - block in z-http"
iptables -A FORWARD -d 172.31.5.0/24 -j DROP

# 9) LDNS -> Internet over TCP
iptables -A FORWARD -p tcp -s 172.31.5.3 --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# 10) LDNS -> Internet over UDP
iptables -A FORWARD -p udp -s 172.31.5.3 --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# 11) HTTP -> Internet
iptables -A FORWARD -p tcp -s 172.31.5.4 --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# 12) HTTPS -> Internet
iptables -A FORWARD -p tcp -s 172.31.5.4 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# 13) Deny out z-http
iptables -A FORWARD -s 172.31.5.0/24 -j LOG --log-prefix "fw1 - block out z-http"
iptables -A FORWARD -s 172.31.5.0/24 -j DROP

# 14) Internet -> PWEB over HTTP
iptables -A FORWARD -p tcp -d 172.32.5.2 --dport 80 -m conntrack --ctstate NEW -j ACCEPT

# 15) Internet -> PWEB over HTTPS
iptables -A FORWARD -p tcp -d 172.32.5.2 --dport 443 -m conntrack --ctstate NEW -j ACCEPT

# 16) SSH -> PWEB
iptables -A FORWARD -p tcp -s 172.31.6.6 -d 172.32.5.2 --dport 22 -m conntrack --ctstate NEW -j ACCEPT

# 17) Internet -> PDNS over TCP
iptables -A FORWARD -p tcp -d 172.32.5.3 --dport 53 -m conntrack --ctstate NEW -j ACCEPT

#18) Internet -> PDNS over UDP
iptables -A FORWARD -p udp -d 172.32.5.3 --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# 19) Deny in z-public
iptables -A FORWARD -d 172.32.5.0/24 -j LOG --log-prefix "fw1 - block in z-public"
iptables -A FORWARD -d 172.32.5.0/24 -j DROP

# 20) PDNS to Internet over tcp
iptables -A FORWARD -p tcp -s 172.32.5.3 --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# 21) PDNS to Internet over udp
iptables -A FORWARD -p udp -s 172.32.5.3 --dport 53 -m conntrack --ctstate NEW -j ACCEPT

# 22) Deny out z-public
iptables -A FORWARD -s 172.32.5.0/24 -j LOG --log-prefix "fw1 - block out z-public"
iptables -A FORWARD -s 172.32.5.0/24 -j DROP

# 23) Log & deny everything by default
iptables -A FORWARD -j LOG --log-prefix "fw1 - deny any other forward"
iptables -A FORWARD -j DROP
