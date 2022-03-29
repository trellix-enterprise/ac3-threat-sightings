"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[1171],{4137:function(e,t,n){n.d(t,{Zo:function(){return p},kt:function(){return f}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function l(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var c=r.createContext({}),s=function(e){var t=r.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=s(e.components);return r.createElement(c.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},m=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,c=e.parentName,p=l(e,["components","mdxType","originalType","parentName"]),m=s(n),f=a,h=m["".concat(c,".").concat(f)]||m[f]||u[f]||o;return n?r.createElement(h,i(i({ref:t},p),{},{components:n})):r.createElement(h,i({ref:t},p))}));function f(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=m;var l={};for(var c in t)hasOwnProperty.call(t,c)&&(l[c]=t[c]);l.originalType=e,l.mdxType="string"==typeof e?e:a,i[1]=l;for(var s=2;s<o;s++)i[s]=n[s];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}m.displayName="MDXCreateElement"},2951:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return l},contentTitle:function(){return c},metadata:function(){return s},toc:function(){return p},default:function(){return m}});var r=n(7462),a=n(3366),o=(n(7294),n(4137)),i=["components"],l={},c=void 0,s={unversionedId:"Weapons/psh-New-NetFirewallRule",id:"Weapons/psh-New-NetFirewallRule",isDocsHomePage:!1,title:"psh-New-NetFirewallRule",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/04-Weapons/psh-New-NetFirewallRule.md",sourceDirName:"04-Weapons",slug:"/Weapons/psh-New-NetFirewallRule",permalink:"/ac3-threat-sightings/docs/Weapons/psh-New-NetFirewallRule",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"psexec",permalink:"/ac3-threat-sightings/docs/Weapons/psexec"},next:{title:"psh-Restart-Service",permalink:"/ac3-threat-sightings/docs/Weapons/psh-Restart-Service"}},p=[{value:"From the AC3 Threat Sighting for <em>Conti Ransomware</em>",id:"from-the-ac3-threat-sighting-for-conti-ransomware",children:[]}],u={toc:p};function m(e){var t=e.components,n=(0,a.Z)(e,i);return(0,o.kt)("wrapper",(0,r.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,o.kt)("h2",{id:"from-the-ac3-threat-sighting-for-conti-ransomware"},"From the AC3 Threat Sighting for ",(0,o.kt)("em",{parentName:"h2"},"Conti Ransomware")),(0,o.kt)("p",null,"Full details at: ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml")),(0,o.kt)("table",null,(0,o.kt)("thead",{parentName:"table"},(0,o.kt)("tr",{parentName:"thead"},(0,o.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,o.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,o.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,o.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,o.kt)("tbody",{parentName:"table"},(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"Defense Evasion"),(0,o.kt)("td",{parentName:"tr",align:null},"Conti used ",(0,o.kt)("em",{parentName:"td"},"PowerShell")," commandlets to allow incomming RDP connections on an uncommon port for Defense Evasion."),(0,o.kt)("td",{parentName:"tr",align:null},(0,o.kt)("em",{parentName:"td"},"New-NetFirewallRule")," commandlet adding new firewall rules for TCP and UDP connections."),(0,o.kt)("td",{parentName:"tr",align:null},(0,o.kt)("em",{parentName:"td"},"Process Created"),": ",(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'New-NetFirewallRule -DisplayName "New RDP Port 1350" -Direction Inbound -LocalPort 1350 -Protocol TCP -Action allow'),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'New-NetFirewallRule -DisplayName "New RDP Port 1350" -Direction Inbound -LocalPort 1350 -Protocol UDP -Action allow'))))))}m.isMDXComponent=!0}}]);