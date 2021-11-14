###### Rules for FW1 ######

# First, let us accept everything by default.
# We will add the default log and drop at the end.
iptables -P INPUT ACCEPT
iptables -P OUTPUT ACCEPT
iptables -P FORWARD ACCEPT

# Now, let us accept the desired traffic.

# 1) Internet -> IMAPS
iptables -A FORWARD -p tcp -d 172.31.6.5 --dport 993 -j ACCEPT

# 2) Internet -> SMTP
iptables -A FORWARD -p tcp -d 172.31.6.5 --dport 25 -j ACCEPT

# 3) Internet -> SSH
iptables -A FORWARD -p tcp -d 172.31.6.6 --dport 22 -j ACCEPT

# 4) Deny in z-mail-ssh
iptables -A FORWARD -d 172.31.6.0/24 -j LOG --log-prefix "fw1 - block in z-mail-ssh"
iptables -A FORWARD -d 172.31.6.0/24 -j DROP

# 5) SSH -> Internet
iptables -A FORWARD -p tcp -s 172.31.6.6 --dport 22 -j ACCEPT

# 6) MAIL (SMTP) -> Internet
iptables -A FORWARD -p tcp -s 172.31.6.5 --dport 25 -j ACCEPT

# 7) Deny out z-mail-ssh
iptables -A FORWARD -s 172.31.6.0/24 -j LOG --log-prefix "fw1 - block out z-mail-ssh"
iptables -A FORWARD -s 172.31.6.0/24 -j DROP

#8) Deny in z-http
iptables -A FORWARD -d 172.31.5.0/24 -j LOG --log-prefix "fw1 - block in z-http"
iptables -A FORWARD -d 172.31.5.0/24 -j DROP

# 9) LDNS -> Internet over TCP
iptables -A FORWARD -p tcp -s 172.31.5.3 --dport 53 -j ACCEPT

# 10) LDNS -> Internet over UDP
iptables -A FORWARD -p udp -s 172.31.5.3 --dport 53 -j ACCEPT

# 11) HTTP -> Internet
iptables -A FORWARD -p tcp -s 172.31.5.4 --dport 80 -j ACCEPT

# 12) HTTPS -> Internet
iptables -A FORWARD -p tcp -s 172.31.5.4 --dport 443 -j ACCEPT

# 13) Deny out z-http
iptables -A FORWARD -s 172.31.5.0/24 -j LOG --log-prefix "fw1 - block out z-http"
iptables -A FORWARD -s 172.31.5.0/24 -j DROP

# 14) Internet -> PWEB over HTTP
iptables -A FORWARD -p tcp -d 172.32.5.2 --dport 80 -j ACCEPT

# 15) Internet -> PWEB over HTTPS
iptables -A FORWARD -p tcp -d 172.32.5.2 --dport 443 -j ACCEPT

# 16) SSH -> PWEB
iptables -A FORWARD -p tcp -s 172.31.6.6 -d 172.32.5.2 --dport 22 -j ACCEPT

# 17) Internet -> PDNS over TCP
iptables -A FORWARD -p tcp -d 172.32.5.3 --dport 53 -j ACCEPT

#18) Internet -> PDNS over UDP
iptables -A FORWARD -p udp -d 172.32.5.3 --dport 53 -j ACCEPT

# 19) Deny in z-public
iptables -A FORWARD -d 172.32.5.0/24 -j LOG --log-prefix "fw1 - block in z-public"

# 20) PDNS to Internet over tcp
iptables -A FORWARD -p tcp -s 172.32.5.3 --dport 53 -j ACCEPT

# 21) PDNS to Internet over udp
iptables -A FORWARD -p udp -s 172.32.5.3 --dport 53 -j ACCEPT

# 22) Deny in z-http
iptables -A FORWARD -s 172.32.5.0/24 -j LOG --log-prefix "fw1 - block in z-http"
iptables -A FORWARD -s 172.32.5.0/24 -j DROP

# 23) Log & deny everything by default
iptables -A INPUT -j LOG --log-prefix "fw1 - deny any other input"
iptables -A INPUT -j DROP
iptables -A OUTPUT -j LOG --log-prefix "fw1 - deny any other output"
iptables -A OUTPUT -j DROP
iptables -A FORWARD -j LOG --log-prefix "fw1 - deny any other forward"
iptables -A FORWARD -j DROP
