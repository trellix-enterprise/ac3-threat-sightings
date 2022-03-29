"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[1461],{4137:function(e,t,r){r.d(t,{Zo:function(){return u},kt:function(){return d}});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function o(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function i(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?o(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):o(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function s(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},o=Object.keys(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(n=0;n<o.length;n++)r=o[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var l=n.createContext({}),c=function(e){var t=n.useContext(l),r=t;return e&&(r="function"==typeof e?e(t):i(i({},t),e)),r},u=function(e){var t=c(e.components);return n.createElement(l.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,u=s(e,["components","mdxType","originalType","parentName"]),m=c(r),d=a,h=m["".concat(l,".").concat(d)]||m[d]||p[d]||o;return r?n.createElement(h,i(i({ref:t},u),{},{components:r})):n.createElement(h,i({ref:t},u))}));function d(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=r.length,i=new Array(o);i[0]=m;var s={};for(var l in t)hasOwnProperty.call(t,l)&&(s[l]=t[l]);s.originalType=e,s.mdxType="string"==typeof e?e:a,i[1]=s;for(var c=2;c<o;c++)i[c]=r[c];return n.createElement.apply(null,i)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},3945:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return s},contentTitle:function(){return l},metadata:function(){return c},toc:function(){return u},default:function(){return m}});var n=r(7462),a=r(3366),o=(r(7294),r(4137)),i=["components"],s={},l=void 0,c={unversionedId:"Techniques/T1069.001 - Permission Groups Discovery- Local Groups",id:"Techniques/T1069.001 - Permission Groups Discovery- Local Groups",isDocsHomePage:!1,title:"T1069.001 - Permission Groups Discovery- Local Groups",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1069.001 - Permission Groups Discovery- Local Groups.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1069.001 - Permission Groups Discovery- Local Groups",permalink:"/ac3-threat-sightings/docs/Techniques/T1069.001 - Permission Groups Discovery- Local Groups",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1069 - Permission Groups Discovery",permalink:"/ac3-threat-sightings/docs/Techniques/T1069 - Permission Groups Discovery"},next:{title:"T1069.002 - Permission Groups Discovery- Domain Groups",permalink:"/ac3-threat-sightings/docs/Techniques/T1069.002 - Permission Groups Discovery- Domain Groups"}},u=[{value:"From the AC3 Threat Sighting for <em>Diavol Ransomware</em>",id:"from-the-ac3-threat-sighting-for-diavol-ransomware",children:[]}],p={toc:u};function m(e){var t=e.components,r=(0,a.Z)(e,i);return(0,o.kt)("wrapper",(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,o.kt)("h2",{id:"from-the-ac3-threat-sighting-for-diavol-ransomware"},"From the AC3 Threat Sighting for ",(0,o.kt)("em",{parentName:"h2"},"Diavol Ransomware")),(0,o.kt)("p",null,"Full details at: ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml")),(0,o.kt)("table",null,(0,o.kt)("thead",{parentName:"table"},(0,o.kt)("tr",{parentName:"thead"},(0,o.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,o.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,o.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,o.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,o.kt)("tbody",{parentName:"table"},(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,o.kt)("td",{parentName:"tr",align:null},"BazarLoader used a well known set of ",(0,o.kt)("em",{parentName:"td"},"net.exe")," and ",(0,o.kt)("em",{parentName:"td"},"nltest.exe")," commands for Discovery."),(0,o.kt)("td",{parentName:"tr",align:null},"Sequence of ",(0,o.kt)("em",{parentName:"td"},"net.exe")," and ",(0,o.kt)("em",{parentName:"td"},"nltest.exe")," commands."),(0,o.kt)("td",{parentName:"tr",align:null},(0,o.kt)("em",{parentName:"td"},"Process Created"),": ",(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"net group /domain admins"),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'net group \\"Domain Computers\\" /domain'),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"net localgroup administrator"),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"net view /all"),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"nltest /domain_trusts /alltrusts"))))))}m.isMDXComponent=!0}}]);