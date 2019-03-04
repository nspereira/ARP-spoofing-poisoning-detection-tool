# ARP spoofing detector

ARP Spoofing Detector is a sniffer capable of detecting ARP cache Spoofing/Poisoning. Once an ARP spoof attack is detected, a warning message will be displayed asking you if you wish to add a rule to iptables so you can block any input from that attacker, the attackers mac address will also be added to a blacklist text file. The script also sends a system notification that will be sent to the user and corresponding information will be logged in the log file.

![shell](https://i.imgur.com/OIukZHG.png)

![notification](https://i.imgur.com/oaYNbjC.png)

<h2>Features</h2>

- Add attacker MAC address to iptables
- Add attacker MAC address to a blacklist text file
- Log all ARP attacks detected in the log file
- Send system notification once attack occurs


<h2>HOW TO RUN</h2>

simply run:

`sudo python2.7 arpspoof_detector.py`

