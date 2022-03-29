"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[9214],{4137:function(e,t,r){r.d(t,{Zo:function(){return m},kt:function(){return d}});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function l(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var s=n.createContext({}),c=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},m=function(e){var t=c(e.components);return n.createElement(s.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},p=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,s=e.parentName,m=l(e,["components","mdxType","originalType","parentName"]),p=c(r),d=a,h=p["".concat(s,".").concat(d)]||p[d]||u[d]||i;return r?n.createElement(h,o(o({ref:t},m),{},{components:r})):n.createElement(h,o({ref:t},m))}));function d(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,o=new Array(i);o[0]=p;var l={};for(var s in t)hasOwnProperty.call(t,s)&&(l[s]=t[s]);l.originalType=e,l.mdxType="string"==typeof e?e:a,o[1]=l;for(var c=2;c<i;c++)o[c]=r[c];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}p.displayName="MDXCreateElement"},1922:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return l},contentTitle:function(){return s},metadata:function(){return c},toc:function(){return m},default:function(){return p}});var n=r(7462),a=r(3366),i=(r(7294),r(4137)),o=["components"],l={},s=void 0,c={unversionedId:"Techniques/T1078 - Valid Accounts",id:"Techniques/T1078 - Valid Accounts",isDocsHomePage:!1,title:"T1078 - Valid Accounts",description:"Found 3 references across 2 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1078 - Valid Accounts.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1078 - Valid Accounts",permalink:"/ac3-threat-sightings/docs/Techniques/T1078 - Valid Accounts",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1071.004 - Application Layer Protocol- Web Protocols",permalink:"/ac3-threat-sightings/docs/Techniques/T1071.004 - Application Layer Protocol- Web Protocols"},next:{title:"T1082 - System Information Discovery",permalink:"/ac3-threat-sightings/docs/Techniques/T1082 - System Information Discovery"}},m=[{value:"From the AC3 Threat Sighting for <em>BlackCat Ransomware</em>",id:"from-the-ac3-threat-sighting-for-blackcat-ransomware",children:[]},{value:"From the AC3 Threat Sighting for <em>Darkside Ransomware</em>",id:"from-the-ac3-threat-sighting-for-darkside-ransomware",children:[]}],u={toc:m};function p(e){var t=e.components,r=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,n.Z)({},u,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 3 references across 2 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-blackcat-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"BlackCat Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_BlackCat_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_BlackCat_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Lateral Movement"),(0,i.kt)("td",{parentName:"tr",align:null},"BlackCat malware has used ",(0,i.kt)("em",{parentName:"td"},"net.exe")," to mount remote drives for Lateral Movement."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"net use")," command executed to mount (unmmaped) remote drive."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net use \\\\\\\\REMOTEDIR /user:Administrator password /persistent:no"))))),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-darkside-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Darkside Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Darkside_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Darkside_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Initial Access"),(0,i.kt)("td",{parentName:"tr",align:null},"DarkSide used ",(0,i.kt)("em",{parentName:"td"},"Valid Credentials")," over ",(0,i.kt)("em",{parentName:"td"},"RDP")," for Initial Access."),(0,i.kt)("td",{parentName:"tr",align:null},"No details available about User Login."),(0,i.kt)("td",{parentName:"tr",align:null})),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Lateral Movement"),(0,i.kt)("td",{parentName:"tr",align:null},"DarkSide used ",(0,i.kt)("em",{parentName:"td"},"Valid Credentials")," over ",(0,i.kt)("em",{parentName:"td"},"RDP")," for Lateral Movement."),(0,i.kt)("td",{parentName:"tr",align:null},"No details available about User Login."),(0,i.kt)("td",{parentName:"tr",align:null})))))}p.isMDXComponent=!0}}]);