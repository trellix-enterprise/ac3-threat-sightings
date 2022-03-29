"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[1781],{4137:function(e,t,r){r.d(t,{Zo:function(){return u},kt:function(){return h}});var n=r(7294);function a(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function i(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?i(Object(r),!0).forEach((function(t){a(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):i(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function c(e,t){if(null==e)return{};var r,n,a=function(e,t){if(null==e)return{};var r,n,a={},i=Object.keys(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||(a[r]=e[r]);return a}(e,t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(e);for(n=0;n<i.length;n++)r=i[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(a[r]=e[r])}return a}var s=n.createContext({}),l=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},u=function(e){var t=l(e.components);return n.createElement(s.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,a=e.mdxType,i=e.originalType,s=e.parentName,u=c(e,["components","mdxType","originalType","parentName"]),m=l(r),h=a,f=m["".concat(s,".").concat(h)]||m[h]||p[h]||i;return r?n.createElement(f,o(o({ref:t},u),{},{components:r})):n.createElement(f,o({ref:t},u))}));function h(e,t){var r=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var i=r.length,o=new Array(i);o[0]=m;var c={};for(var s in t)hasOwnProperty.call(t,s)&&(c[s]=t[s]);c.originalType=e,c.mdxType="string"==typeof e?e:a,o[1]=c;for(var l=2;l<i;l++)o[l]=r[l];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},8715:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return c},contentTitle:function(){return s},metadata:function(){return l},toc:function(){return u},default:function(){return m}});var n=r(7462),a=r(3366),i=(r(7294),r(4137)),o=["components"],c={},s=void 0,l={unversionedId:"Techniques/T1529 - System Shutdown-Reboot",id:"Techniques/T1529 - System Shutdown-Reboot",isDocsHomePage:!1,title:"T1529 - System Shutdown-Reboot",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1529 - System Shutdown-Reboot.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1529 - System Shutdown-Reboot",permalink:"/ac3-threat-sightings/docs/Techniques/T1529 - System Shutdown-Reboot",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1505.003 - Server Software Component- Web Shell",permalink:"/ac3-threat-sightings/docs/Techniques/T1505.003 - Server Software Component- Web Shell"},next:{title:"T1531 - Account Access Removal",permalink:"/ac3-threat-sightings/docs/Techniques/T1531 - Account Access Removal"}},u=[{value:"From the AC3 Threat Sighting for <em>HermeticWiper</em>",id:"from-the-ac3-threat-sighting-for-hermeticwiper",children:[]}],p={toc:u};function m(e){var t=e.components,r=(0,a.Z)(e,o);return(0,i.kt)("wrapper",(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,i.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,i.kt)("h2",{id:"from-the-ac3-threat-sighting-for-hermeticwiper"},"From the AC3 Threat Sighting for ",(0,i.kt)("em",{parentName:"h2"},"HermeticWiper")),(0,i.kt)("p",null,"Full details at: ",(0,i.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_HermeticWiper.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_HermeticWiper.yml")),(0,i.kt)("table",null,(0,i.kt)("thead",{parentName:"table"},(0,i.kt)("tr",{parentName:"thead"},(0,i.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,i.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,i.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,i.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,i.kt)("tbody",{parentName:"table"},(0,i.kt)("tr",{parentName:"tbody"},(0,i.kt)("td",{parentName:"tr",align:null},"Impact"),(0,i.kt)("td",{parentName:"tr",align:null},"HermeticWiper used ",(0,i.kt)("em",{parentName:"td"},"InitiateSystemShutdownEx")," Native API to shutdown the system for Impact."),(0,i.kt)("td",{parentName:"tr",align:null},(0,i.kt)("em",{parentName:"td"},"Native APIs")," to increase privilege"),(0,i.kt)("td",{parentName:"tr",align:null})))))}m.isMDXComponent=!0}}]);