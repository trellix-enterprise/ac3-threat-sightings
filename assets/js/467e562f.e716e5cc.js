"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[5676],{4137:function(e,t,n){n.d(t,{Zo:function(){return p},kt:function(){return m}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function c(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var l=r.createContext({}),s=function(e){var t=r.useContext(l),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=s(e.components);return r.createElement(l.Provider,{value:t},e.children)},u={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},d=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,l=e.parentName,p=c(e,["components","mdxType","originalType","parentName"]),d=s(n),m=a,f=d["".concat(l,".").concat(m)]||d[m]||u[m]||o;return n?r.createElement(f,i(i({ref:t},p),{},{components:n})):r.createElement(f,i({ref:t},p))}));function m(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=d;var c={};for(var l in t)hasOwnProperty.call(t,l)&&(c[l]=t[l]);c.originalType=e,c.mdxType="string"==typeof e?e:a,i[1]=c;for(var s=2;s<o;s++)i[s]=n[s];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}d.displayName="MDXCreateElement"},8774:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return c},contentTitle:function(){return l},metadata:function(){return s},toc:function(){return p},default:function(){return d}});var r=n(7462),a=n(3366),o=(n(7294),n(4137)),i=["components"],c={},l=void 0,s={unversionedId:"Weapons/advanced_ip_scanner",id:"Weapons/advanced_ip_scanner",isDocsHomePage:!1,title:"advanced_ip_scanner",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/04-Weapons/advanced_ip_scanner.md",sourceDirName:"04-Weapons",slug:"/Weapons/advanced_ip_scanner",permalink:"/ac3-threat-sightings/docs/Weapons/advanced_ip_scanner",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"adhoc-malware",permalink:"/ac3-threat-sightings/docs/Weapons/adhoc-malware"},next:{title:"advancedrun",permalink:"/ac3-threat-sightings/docs/Weapons/advancedrun"}},p=[{value:"From the AC3 Threat Sighting for <em>Diavol Ransomware</em>",id:"from-the-ac3-threat-sighting-for-diavol-ransomware",children:[]}],u={toc:p};function d(e){var t=e.components,n=(0,a.Z)(e,i);return(0,o.kt)("wrapper",(0,r.Z)({},u,n,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,o.kt)("h2",{id:"from-the-ac3-threat-sighting-for-diavol-ransomware"},"From the AC3 Threat Sighting for ",(0,o.kt)("em",{parentName:"h2"},"Diavol Ransomware")),(0,o.kt)("p",null,"Full details at: ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Diavol_Ransomware.yml")),(0,o.kt)("table",null,(0,o.kt)("thead",{parentName:"table"},(0,o.kt)("tr",{parentName:"thead"},(0,o.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,o.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,o.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,o.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,o.kt)("tbody",{parentName:"table"},(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,o.kt)("td",{parentName:"tr",align:null},"Threat Actor used ",(0,o.kt)("em",{parentName:"td"},"RDP")," to download and execute portable version of ",(0,o.kt)("em",{parentName:"td"},"Advanced_IP_Scanner")," for Discovery."),(0,o.kt)("td",{parentName:"tr",align:null},"Executed Advanced_IP_Scanner manually over RDP"),(0,o.kt)("td",{parentName:"tr",align:null},(0,o.kt)("em",{parentName:"td"},"Process Created"),": ",(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"n/d"))))))}d.isMDXComponent=!0}}]);