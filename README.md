# ARP-spoofing-poisoning-detection-tool

ARP Spoofing Detector is a sniffer capable of detecting ARP cache Spoofing/Poisoning. Once an ARP spoof attack is detected, a warning message will be displayed asking you if you wish to add a rule to iptables so you can block any input from that attacker, the attackers mac address will also be added to a blacklist text file. The script also sends a system notification that will be sent to the user and corresponding information will be logged in the log file.


<h2>Features</h2>


<h2>HOW TO RUN</h2>

First make sure you have Root access to the machine you intend to run this script and simply run:

`sudo python2.7 arpspoof_detector.py`

