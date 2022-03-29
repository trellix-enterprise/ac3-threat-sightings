"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[2638],{4137:function(e,t,n){n.d(t,{Zo:function(){return c},kt:function(){return d}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function i(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function o(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?i(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):i(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},i=Object.keys(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(r=0;r<i.length;r++)n=i[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var m=r.createContext({}),s=function(e){var t=r.useContext(m),n=t;return e&&(n="function"==typeof e?e(t):o(o({},t),e)),n},c=function(e){var t=s(e.components);return r.createElement(m.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},p=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,i=e.originalType,m=e.parentName,c=l(e,["components","mdxType","originalType","parentName"]),p=s(n),d=a,h=p["".concat(m,".").concat(d)]||p[d]||u[d]||i;return n?r.createElement(h,o(o({ref:t},c),{},{components:n})):r.createElement(h,o({ref:t},c))}));function d(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=n.length,o=new Array(i);o[0]=p;var l={};for(var m in t)hasOwnProperty.call(t,m)&&(l[m]=t[m]);l.originalType=e,l.mdxType="string"==typeof e?e:a,o[1]=l;for(var s=2;s<i;s++)o[s]=n[s];return r.createElement.apply(null,o)}return r.createElement.apply(null,n)}p.displayName="MDXCreateElement"},6503:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return l},contentTitle:function(){return m},metadata:function(){return s},toc:function(){return c},default:function(){return p}});var r=n(7462),a=n(3366),i=(n(7294),n(4137)),o=["components"],l={},m=void 0,s={unversionedId:"Techniques/T1482 - Domain Trust Discovery",id:"Techniques/T1482 - Domain Trust Discovery",isDocsHomePage:!1,title:"T1482 - Domain Trust Discovery",description:"Found 3 references across 2 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1482 - Domain Trust Discovery.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1482 - Domain Trust Discovery",permalink:"/ac3-threat-sightings/docs/Techniques/T1482 - Domain Trust Discovery",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1219 - Remote Access Software",permalink:"/ac3-threat-sightings/docs/Techniques/T1219 - Remote Access Software"},next:{title:"T1486 - Data Encrypted for Impact",permalink:"/ac3-threat-sightings/docs/Techniques/T1486 - Data Encrypted for Impact"}},c=[{value:"From the AC3 Threat Sighting for <em>Diavol Ransomware</em>",id:"from-the-ac3-threat-sighting-for-diavol-ransomware",children:[]},{value:"From the AC3 Threat Sighting for <em>Hafnium</em>",id:"from-the-ac3-threat-sighting-for-hafnium",children:[]}],u={toc:c};function p(e){var t=e.components,n=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,r.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 3 references across 2 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-diavol-ransomware"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Diavol Ransomware")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"BazarLoader used a well known set of ",(0,i.kt)("em",{parentName:"td"},"net.exe")," and ",(0,i.kt)("em",{parentName:"td"},"nltest.exe")," commands for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},"Sequence of ",(0,i.kt)("em",{parentName:"td"},"net.exe")," and ",(0,i.kt)("em",{parentName:"td"},"nltest.exe")," commands."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net group /domain admins"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'net group \\"Domain Computers\\" /domain'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net localgroup administrator"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"net view /all"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"nltest /domain_trusts /alltrusts"))),(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"Cobalt Strike")," to execute a well-known ",(0,i.kt)("em",{parentName:"td"},"AdFind")," recon script for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"CMD")," launched sequence of masqueraded ",(0,i.kt)("em",{parentName:"td"},"AdFind.exe")," commands."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"(objectcategory=person)\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"objectcategory=computer\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"(objectcategory=organizationalUnit)\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"qq.exe -sc trustdmp"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"qq.exe -subnets -f (objectCategory=subnet)"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'qq.exe -f \\"(objectcategory=group)\\"'),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"qq.exe -gcb -sc trustdmp"))))),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-hafnium"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"Hafnium")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Hafnium.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Hafnium.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,i.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,i.kt)("em",{parentName:"td"},"nltest, net and other basic commands via China Chopper Web Shell")," for Discovery."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"CMD")," spawns ",(0,i.kt)("em",{parentName:"td"},"nltest.exe")," and ",(0,i.kt)("em",{parentName:"td"},"net.exe")," commands."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Process Created"),": ",(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"nltest /dclist:#{DOMAIN}"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},"whoami"),(0,i.kt)("br",null),"- ",(0,i.kt)("inlineCode",{parentName:"td"},'net group \\"Domain computers\\" /do'))))))}p.isMDXComponent=!0}}]);