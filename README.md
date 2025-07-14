# Network_threat_analysis
**What Are Network Threats?**

Network threats are malicious activities or suspicious behaviors that compromise the security, reliability, or performance of a computer network. These threats can come from external attackers, malware, or even misconfigured systems within the network.

So understanding and detecting these threats is critical to protecting modern IT infrastructures.

**Common Types of Network Threats (Explained Simply)**

   | Threat Type   | What It Means                       | When It Happens                                              | Why It’s Dangerous                               |
| ------------- | ----------------------------------- | ------------------------------------------------------------ | ------------------------------------------------ |
| **Intrusion** | Unauthorized or suspicious behavior | Accessing critical ports, one-way traffic, spoofed timing    | Can evade firewall but compromise data integrity |
| **Malware**   | Code with malicious intent          | Often seen with repeated access to ports, high packet counts | Can steal, corrupt or encrypt files              |
| **Spike**     | Sudden rise in traffic              | DoS, brute force, scanning attempts                          | Crashes the system or overwhelms it              |
| **Rare Port** | Port used very infrequently         | Custom backdoors, C\&C servers                               | Bypasses standard monitoring tools               |


Dataset Link : https://www.kaggle.com/datasets/tunguz/internet-firewall-data-set

Our data set has the following attributes 

Our dataset is a cleaned and pre-processed version of a firewall log containing the following fields:

<img width="750" height="691" alt="image" src="https://github.com/user-attachments/assets/339aceaa-1300-426b-b67d-2b9874cdec25" />

We addressed this problem by developing scores for each Threat type since each threat is depending on multiple things : 
For Intrusion : 
 | Rule Condition                            | Score | Reason                     |
| ----------------------------------------- | ----- | -------------------------- |
| `Action == deny/drop`                     | +2    | Firewall flagged it        |
| `Destination Port in [3389, 22, 23, 445]` | +2    | Common attack ports        |
| `pkts_received == 0`                      | +1    | Possibly failed attack     |
| `Elapsed Time == 0 & Bytes > 0`           | +3    | Bot-like behavior          |
| `Bytes Received == 0 & Bytes Sent > 0`    | +2    | Data exfil suspicion       |
| `Packets <= 1`                            | +1    | Suspicious minimal traffic |


For malware : 

| Pattern                                          | Why It’s Suspicious         |
| ------------------------------------------------ | --------------------------- |
| **Allow + Very short Elapsed Time + High Bytes** | Sudden data upload/download |
| **Unusual port** + **High packets**              | Hidden communication        |
| **Same Source Port & Dest Port (loopback)**      | Port hijack, VPN tunneling  |


For Spike detection : 
 we created new time stamps column since we didn't originally have in the column and then calculated for bytes for particular port in each time block and then evaluated deviation's if it was deviating much we flagged it as 1 if not 0

<img width="385" height="232" alt="image" src="https://github.com/user-attachments/assets/f0800ff6-ab1e-491c-b2de-f0a35e72e2cc" />

for example we can see for source port 0 in block 2 the bytes recieved is much greater than rest of them so we will flag this as traffic_spike usually in network analysis

For uncommon IP's : 
 We calculated source ports counts and the one which are less than 5 were flagged as uncommon IP's


so after all this we have now created rules for intrusion,malware,spike and uncommon IP's now we created a new column known as threat_flag it will show whether it is threat or not

After training normally on various algorithms of classification i found out that is_threat = 0 is falling in minority so i used oversampling techniques i.e **SMOTE** for this and model improved its perfomance among them best model coming out was RF .

DashBoard for visulaizing different netwoek threats for 1hr,12hr,24hr : https://networkthreatanalysis-5zauduqwqexr6zizdnkqym.streamlit.app/




