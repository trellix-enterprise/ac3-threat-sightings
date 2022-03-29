"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[548],{4137:function(e,t,n){n.d(t,{Zo:function(){return m},kt:function(){return p}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var s=r.createContext({}),u=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},m=function(e){var t=u(e.components);return r.createElement(s.Provider,{value:t},e.children)},c={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,i=e.originalType,s=e.parentName,m=l(e,["components","mdxType","originalType","parentName"]),d=u(n),p=a,g=d["".concat(s,".").concat(p)]||d[p]||c[p]||i;return n?r.createElement(g,o(o({ref:t},m),{},{components:n})):r.createElement(g,o({ref:t},m))}));function p(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=n.length,o=new Array(i);o[0]=d;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:a,o[1]=l;for(var u=2;u<i;u++)o[u]=n[u];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},636:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return l},contentTitle:function(){return s},metadata:function(){return u},toc:function(){return m},default:function(){return d}});var r=n(7462),a=n(3366),i=(n(7294),n(4137)),o=["components"],l={},s=void 0,u={unversionedId:"Techniques/T1016 - System Network Configuration Discovery",id:"Techniques/T1016 - System Network Configuration Discovery",isDocsHomePage:!1,title:"T1016 - System Network Configuration Discovery",description:"Found 3 references across 2 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1016 - System Network Configuration Discovery.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1016 - System Network Configuration Discovery",permalink:"/ac3-threat-sightings/docs/Techniques/T1016 - System Network Configuration Discovery",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1006 - Direct Volume Access",permalink:"/ac3-threat-sightings/docs/Techniques/T1006 - Direct Volume Access"},next:{title:"T1018 - Remote System Discovery",permalink:"/ac3-threat-sightings/docs/Techniques/T1018 - Remote System Discovery"}},m=[{value:"From the AC3 Threat Sighting for <em>Conti Ransomware</em>",id:"from-the-ac3-threat-sighting-for-conti-ransomware",children:[]},{value:"From the AC3 Threat Sighting for <em>Diavol Ransomware</em>",id:"from-the-ac3-threat-sighting-for-diavol-ransomware",children:[]}],c={toc:m};function d(e){var t=e.components,n=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,r.Z)({},c,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 3 references across 2 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-conti-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Conti Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"Conti used ",(0,i.kt)("em",{parentName:"td"},"AdFind via Cobalt Strike")," for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},"Sequence of ",(0,i.kt)("em",{parentName:"td"},"AdFind.exe")," commands."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"(objectcategory=person)\\" > ad_users.txt'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"objectcategory=computer\\" > ad_computers.txt'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"(objectcategory=organizationalUnit)\\" > ad_ous.txt'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -sc trustdmp > trustdump.txt"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f (objectCategory=subnet) > subnets.txt"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"(objectcategory=group)\\" > ad_group.txt'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -gcb -sc trustdmp > trustdump.txt"))))),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-diavol-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Diavol Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"Cobalt Strike")," to execute a well-known ",(0,i.kt)("em",{parentName:"td"},"AdFind")," recon script for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"CMD")," launched sequence of masqueraded ",(0,i.kt)("em",{parentName:"td"},"AdFind.exe")," commands."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"(objectcategory=person)\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"objectcategory=computer\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"(objectcategory=organizationalUnit)\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"qq.exe -sc trustdmp"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"qq.exe -subnets -f (objectCategory=subnet)"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"(objectcategory=group)\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"qq.exe -gcb -sc trustdmp"))),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used multiple system utilities for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},"Performed additional Discovery activity"),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'net group "Domain Admins" /domain'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"whoami"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"ipconfig /all"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"systeminfo"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"tasklist"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'net group \\"Enterprise admins\\" /domain'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net localgroup administrators"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"whoami /all"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net use"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"query user"))))))}d.isMDXComponent=!0}}]);