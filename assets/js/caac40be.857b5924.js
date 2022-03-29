"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[475],{4137:function(e,t,n){n.d(t,{Zo:function(){return u},kt:function(){return d}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var s=r.createContext({}),l=function(e){var t=r.useContext(s),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},u=function(e){var t=l(e.components);return r.createElement(s.Provider,{value:t},e.children)},m={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},p=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,i=e.originalType,s=e.parentName,u=c(e,["components","mdxType","originalType","parentName"]),p=l(n),d=a,h=p["".concat(s,".").concat(d)]||p[d]||m[d]||i;return n?r.createElement(h,o(o({ref:t},u),{},{components:n})):r.createElement(h,o({ref:t},u))}));function d(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=n.length,o=new Array(i);o[0]=p;var c={};for(var s in t)hasOwnProperty.call(t,s)&&(c[s]=t[s]);c.originalType=e,c.mdxType="string"==typeof e?e:a,o[1]=c;for(var l=2;l<i;l++)o[l]=n[l];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}p.displayName="MDXCreateElement"},9094:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return c},contentTitle:function(){return s},metadata:function(){return l},toc:function(){return u},default:function(){return p}});var r=n(7462),a=n(3366),i=(n(7294),n(4137)),o=["components"],c={},s=void 0,l={unversionedId:"Techniques/T1049 - System Network Connections Discovery",id:"Techniques/T1049 - System Network Connections Discovery",isDocsHomePage:!1,title:"T1049 - System Network Connections Discovery",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1049 - System Network Connections Discovery.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1049 - System Network Connections Discovery",permalink:"/ac3-threat-sightings/docs/Techniques/T1049 - System Network Connections Discovery",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1048 - Exfiltration Over Alternative Protocol",permalink:"/ac3-threat-sightings/docs/Techniques/T1048 - Exfiltration Over Alternative Protocol"},next:{title:"T1053.005 - Scheduled Task-Job- Scheduled Task",permalink:"/ac3-threat-sightings/docs/Techniques/T1053.005 - Scheduled Task-Job- Scheduled Task"}},u=[{value:"From the AC3 Threat Sighting for <em>Hafnium</em>",id:"from-the-ac3-threat-sighting-for-hafnium",children:[]}],m={toc:u};function p(e){var t=e.components,n=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,r.Z)({},m,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-hafnium"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Hafnium")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Hafnium.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Hafnium.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"nltest, net and other basic commands via China Chopper Web Shell")," for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"CMD")," spawns discovery commands (",(0,i.kt)("em",{parentName:"td"},"query.exe"),", ",(0,i.kt)("em",{parentName:"td"},"hostname.exe"),", ",(0,i.kt)("em",{parentName:"td"},"ping.exe"),", ",(0,i.kt)("em",{parentName:"td"},"tasklist.exe"),", ",(0,i.kt)("em",{parentName:"td"},"whoami.exe"),")."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"query user"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"hostname"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"ping #{dst} -n 1"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"tasklist\\|findstr dll"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"whoami"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"tasklist"))))))}p.isMDXComponent=!0}}]);