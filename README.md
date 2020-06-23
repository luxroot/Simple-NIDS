# HW4_20203331_MyeongGeun-Shin
IS 511 - HW4 Network security by MyeongGeun Shin (20203331)

Due: June 24, 2:30 PM

---

Run `install.sh` with `sudo` command. It will install python3, netaddr, scapy if not exists.

So, at first time please run

```sh
chmod u+x install.sh main.py && sudo ./install.sh
```



Then you're ready to go! You can run this program with following.

```sh
sudo python3 main.py rule_file.txt
```

Or, 

```sh
sudo ./main.py rule_file.txt
```

(`sudo` is required to capture low-number ports packets)