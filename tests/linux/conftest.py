"""Realistic command output fixtures for Linux collector tests."""

from __future__ import annotations

import pytest


# ---------------------------------------------------------------------------
# ps output
# ---------------------------------------------------------------------------

GNU_PS_OUTPUT = """\
root         1  0.0  0.1 168284 13400 ?        Ss   Jan01   0:12 /sbin/init
root         2  0.0  0.0      0     0 ?        S    Jan01   0:00 [kthreadd]
root       123  0.5  1.2 234567 98765 ?        Ssl  Jan01   5:43 /usr/bin/python3 /app/main.py
www-data   456  1.2  0.8 123456 65432 ?        S    Jan01   3:21 nginx: worker process
nobody     789  0.0  0.0  12345  1234 ?        S    Jan01   0:01 /usr/sbin/dnsmasq --keep-in-foreground
"""

BUSYBOX_PS_OUTPUT = """\
  PID USER     STAT COMMAND
    1 root     S    /sbin/init
   42 root     S    /usr/sbin/sshd
  100 nobody   S    /usr/bin/dropbear
  200 www      R    /usr/bin/httpd -f
"""

# ---------------------------------------------------------------------------
# systemctl output
# ---------------------------------------------------------------------------

SYSTEMCTL_LIST_UNITS = """\
  sshd.service     loaded active   running OpenBSD Secure Shell server
  nginx.service    loaded active   running A high performance web server
  cron.service     loaded active   running Regular background program processing daemon
  bluetooth.service loaded inactive dead    Bluetooth service
"""

SYSTEMCTL_LIST_UNIT_FILES = """\
sshd.service                           enabled
nginx.service                          enabled
cron.service                           enabled
bluetooth.service                      disabled
avahi-daemon.service                   static
"""

# ---------------------------------------------------------------------------
# ss / netstat output
# ---------------------------------------------------------------------------

SS_OUTPUT = """\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128           0.0.0.0:22         0.0.0.0:*     users:(("sshd",pid=123,fd=3))
tcp   LISTEN 0      511           0.0.0.0:80         0.0.0.0:*     users:(("nginx",pid=456,fd=6))
tcp   LISTEN 0      128              [::]:22            [::]:*     users:(("sshd",pid=123,fd=4))
udp   LISTEN 0      0             0.0.0.0:68         0.0.0.0:*     users:(("dhclient",pid=789,fd=7))
"""

SS_OUTPUT_IPV6_TRIPLE_COLON = """\
Netid State  Recv-Q Send-Q  Local Address:Port  Peer Address:Port Process
tcp   LISTEN 0      128           :::8080            :::*     users:(("node",pid=999,fd=3))
"""

# ---------------------------------------------------------------------------
# Hardening check outputs
# ---------------------------------------------------------------------------

SSHD_ROOT_LOGIN_NO = "PermitRootLogin no"
SSHD_ROOT_LOGIN_YES = "PermitRootLogin yes"
SSHD_PASSWORD_AUTH_NO = "PasswordAuthentication no"
SSHD_PASSWORD_AUTH_YES = "PasswordAuthentication yes"

IPTABLES_WITH_RULES = """\
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
ACCEPT     all  --  0.0.0.0/0            0.0.0.0/0
DROP       tcp  --  0.0.0.0/0            0.0.0.0/0            tcp dpt:23
"""

IPTABLES_EMPTY = """\
Chain INPUT (policy ACCEPT)
target     prot opt source               destination
"""

SUID_FILES_FEW = """\
/usr/bin/passwd
/usr/bin/sudo
/usr/bin/su
"""

SUID_FILES_MANY = "\n".join(f"/usr/bin/suid{i}" for i in range(20))

# ---------------------------------------------------------------------------
# Hardware device listings
# ---------------------------------------------------------------------------

SERIAL_DEVICES = """\
/dev/ttyS0
/dev/ttyS1
/dev/ttyUSB0
"""

SPI_DEVICES = """\
/dev/spidev0.0
/dev/spidev0.1
"""

I2C_DEVICES = """\
/dev/i2c-0
/dev/i2c-1
"""

GPIO_DEVICES = """\
/dev/gpiochip0
/dev/gpiochip1
"""

LSUSB_OUTPUT = """\
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub
Bus 001 Device 002: ID 0403:6001 Future Technology Devices International, Ltd FT232 Serial
"""


# ---------------------------------------------------------------------------
# systemctl show output (for service-process mapping)
# ---------------------------------------------------------------------------

SYSTEMCTL_SHOW_OUTPUT = """\
Id=sshd.service
MainPID=123

Id=nginx.service
MainPID=456

Id=cron.service
MainPID=500

Id=bluetooth.service
MainPID=0
"""

SYSTEMCTL_SHOW_EMPTY = """\
Id=sshd.service
MainPID=0
"""


@pytest.fixture
def gnu_ps_output() -> str:
    return GNU_PS_OUTPUT


@pytest.fixture
def busybox_ps_output() -> str:
    return BUSYBOX_PS_OUTPUT


@pytest.fixture
def systemctl_units_output() -> str:
    return SYSTEMCTL_LIST_UNITS


@pytest.fixture
def systemctl_unit_files_output() -> str:
    return SYSTEMCTL_LIST_UNIT_FILES


@pytest.fixture
def ss_output() -> str:
    return SS_OUTPUT
