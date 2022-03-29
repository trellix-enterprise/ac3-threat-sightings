"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[8360],{4137:function(e,t,r){r.d(t,{Zo:function(){return m},kt:function(){return d}});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var c=n.createContext({}),l=function(e){var t=n.useContext(c),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},m=function(e){var t=l(e.components);return n.createElement(c.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},p=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,c=e.parentName,m=s(e,["components","mdxType","originalType","parentName"]),p=l(r),d=a,h=p["".concat(c,".").concat(d)]||p[d]||u[d]||i;return r?n.createElement(h,o(o({ref:t},m),{},{components:r})):n.createElement(h,o({ref:t},m))}));function d(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,o=new Array(i);o[0]=p;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s.mdxType="string"==typeof e?e:a,o[1]=s;for(var l=2;l<i;l++)o[l]=r[l];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}p.displayName="MDXCreateElement"},8585:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return s},contentTitle:function(){return c},metadata:function(){return l},toc:function(){return m},default:function(){return p}});var n=r(7462),a=r(3366),i=(r(7294),r(4137)),o=["components"],s={},c=void 0,l={unversionedId:"Techniques/T1021.002 - Remote Services- SMB-Windows Admin Shares",id:"Techniques/T1021.002 - Remote Services- SMB-Windows Admin Shares",isDocsHomePage:!1,title:"T1021.002 - Remote Services- SMB-Windows Admin Shares",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1021.002 - Remote Services- SMB-Windows Admin Shares.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1021.002 - Remote Services- SMB-Windows Admin Shares",permalink:"/ac3-threat-sightings/docs/Techniques/T1021.002 - Remote Services- SMB-Windows Admin Shares",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1021.001 - Remote Services- SMB-Windows Admin Shares",permalink:"/ac3-threat-sightings/docs/Techniques/T1021.001 - Remote Services- SMB-Windows Admin Shares"},next:{title:"T1027 - Obfuscated Files or Information",permalink:"/ac3-threat-sightings/docs/Techniques/T1027 - Obfuscated Files or Information"}},m=[{value:"From the AC3 Threat Sighting for <em>BlackCat Ransomware</em>",id:"from-the-ac3-threat-sighting-for-blackcat-ransomware",children:[]}],u={toc:m};function p(e){var t=e.components,r=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,n.Z)({},u,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-blackcat-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"BlackCat Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_BlackCat_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_BlackCat_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Lateral Movement"),(0,i.kt)("td",{parentName:"tr",align:null},"BlackCat malware has used ",(0,i.kt)("em",{parentName:"td"},"net.exe")," to mount remote drives for Lateral Movement."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"net use")," command executed to mount (unmmaped) remote drive."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net use \\\\\\\\REMOTEDIR /user:Administrator password /persistent:no"))))))}p.isMDXComponent=!0}}]);