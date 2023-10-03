<h1>Wazuh SIEM</h1>



<h2>Description</h2>
Welcome to the Wazuh SIEM Environment project! This repository provides comprehensive documentation and resources to help you set up a open source SIEM(Security Information and Event Manager). A SIEM is a key tool for blue teamers, it allows for a centralized dashboard for collecting, analyzing, aggerating, and indexing security related data. Aiding in detecting intrustions, attacks, and vulnerabilities.
<br />

<h2>What You''ll Find in This Repository</h2>
Installation Guide: Step-by-step instructions to configure a Wazuh SIEM on your system, including system requirements and configuration details. In this guide I will be using Linode to host my Wazuh server. Other options are using AWS or a OVA file linked below:
https://documentation.wazuh.com/current/development/packaging/generate-ova.html


<h2>Wazuh Walk Through</h2>

1. In the Linode market place select the "Wazuh" App. Enter your email for the SSL cert. Create a Sudo user that can SSH into the Wazuh cloud. Upon deployment wait 5 minutes for Wazuh to configure.
2. SSH into Wazuh
   When your machine is running open up a terminal and ssh into the machine.
   "ssh root@xxx.xxx.xxx.xxx"
3. Once you log into the Wazuh box you can run the following command to check for .deploymet-secerts.txt
   "ls -al"
4. We need to view insde the text file so run the following command:
   "cat .deployment-secert.txt" 
5. Find and copy the indexer_password for the web user interface
6. Now we need to open the Wazuh dashboard. On linode find the Reverse DNS address for your user interface. Copy that into a web browser. Use username "admin" and the password found on step 5 to login.
7. Now we need to add agents for our SIEM to monitor. On the wazuh dashboard navigate to Agents then Deploy new agent.
8. To deploying an agent choose the proper Operating System, Version, Architecture, FQDN (this will be the address on your dashboard), name your agent, and give it a group to operate in. 




<br/>

<h2>Languages and Utilities Used</h2>

- <b>PowerShell</b> 
- <b>Orcale Virtual Box</b>
- <b>Python</b>
- <b>sysmon</b>

