"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[7707],{4137:function(e,t,r){r.d(t,{Zo:function(){return u},kt:function(){return h}});var n=r(7294);function i(e,t,r){return t in e?Object.defineProperty(e,t,{value:r,enumerable:!0,configurable:!0,writable:!0}):e[t]=r,e}function a(e,t){var r=Object.keys(e);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(e);t&&(n=n.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),r.push.apply(r,n)}return r}function o(e){for(var t=1;t<arguments.length;t++){var r=null!=arguments[t]?arguments[t]:{};t%2?a(Object(r),!0).forEach((function(t){i(e,t,r[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(r)):a(Object(r)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(r,t))}))}return e}function c(e,t){if(null==e)return{};var r,n,i=function(e,t){if(null==e)return{};var r,n,i={},a=Object.keys(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||(i[r]=e[r]);return i}(e,t);if(Object.getOwnPropertySymbols){var a=Object.getOwnPropertySymbols(e);for(n=0;n<a.length;n++)r=a[n],t.indexOf(r)>=0||Object.prototype.propertyIsEnumerable.call(e,r)&&(i[r]=e[r])}return i}var s=n.createContext({}),l=function(e){var t=n.useContext(s),r=t;return e&&(r="function"==typeof e?e(t):o(o({},t),e)),r},u=function(e){var t=l(e.components);return n.createElement(s.Provider,{value:t},e.children)},p={inlineCode:"code",wrapper:function(e){var t=e.children;return n.createElement(n.Fragment,{},t)}},m=n.forwardRef((function(e,t){var r=e.components,i=e.mdxType,a=e.originalType,s=e.parentName,u=c(e,["components","mdxType","originalType","parentName"]),m=l(r),h=i,f=m["".concat(s,".").concat(h)]||m[h]||p[h]||a;return r?n.createElement(f,o(o({ref:t},u),{},{components:r})):n.createElement(f,o({ref:t},u))}));function h(e,t){var r=arguments,i=t&&t.mdxType;if("string"==typeof e||i){var a=r.length,o=new Array(a);o[0]=m;var c={};for(var s in t)hasOwnProperty.call(t,s)&&(c[s]=t[s]);c.originalType=e,c.mdxType="string"==typeof e?e:i,o[1]=c;for(var l=2;l<a;l++)o[l]=r[l];return n.createElement.apply(null,o)}return n.createElement.apply(null,r)}m.displayName="MDXCreateElement"},3142:function(e,t,r){r.r(t),r.d(t,{frontMatter:function(){return c},contentTitle:function(){return s},metadata:function(){return l},toc:function(){return u},default:function(){return m}});var n=r(7462),i=r(3366),a=(r(7294),r(4137)),o=["components"],c={},s=void 0,l={unversionedId:"Techniques/T1561.001 - Disk Content Wipe",id:"Techniques/T1561.001 - Disk Content Wipe",isDocsHomePage:!1,title:"T1561.001 - Disk Content Wipe",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/05-Techniques/T1561.001 - Disk Content Wipe.md",sourceDirName:"05-Techniques",slug:"/Techniques/T1561.001 - Disk Content Wipe",permalink:"/ac3-threat-sightings/docs/Techniques/T1561.001 - Disk Content Wipe",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"T1561 - Disk Wipe",permalink:"/ac3-threat-sightings/docs/Techniques/T1561 - Disk Wipe"},next:{title:"T1561.002 - Disk Structure Wipe",permalink:"/ac3-threat-sightings/docs/Techniques/T1561.002 - Disk Structure Wipe"}},u=[{value:"From the AC3 Threat Sighting for <em>HermeticWiper</em>",id:"from-the-ac3-threat-sighting-for-hermeticwiper",children:[]}],p={toc:u};function m(e){var t=e.components,r=(0,i.Z)(e,o);return(0,a.kt)("wrapper",(0,n.Z)({},p,r,{components:t,mdxType:"MDXLayout"}),(0,a.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,a.kt)("h2",{id:"from-the-ac3-threat-sighting-for-hermeticwiper"},"From the AC3 Threat Sighting for ",(0,a.kt)("em",{parentName:"h2"},"HermeticWiper")),(0,a.kt)("p",null,"Full details at: ",(0,a.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_HermeticWiper.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_HermeticWiper.yml")),(0,a.kt)("table",null,(0,a.kt)("thead",{parentName:"table"},(0,a.kt)("tr",{parentName:"thead"},(0,a.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,a.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,a.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,a.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,a.kt)("tbody",{parentName:"table"},(0,a.kt)("tr",{parentName:"tbody"},(0,a.kt)("td",{parentName:"tr",align:null},"Impact"),(0,a.kt)("td",{parentName:"tr",align:null},"HermeticWiper used ",(0,a.kt)("em",{parentName:"td"},"EaseUS Partition Master")," drivers for direct access to storage devices to overwrite files for Impact."),(0,a.kt)("td",{parentName:"tr",align:null},"Malware overwrites files under specific folders with random data."),(0,a.kt)("td",{parentName:"tr",align:null})))))}m.isMDXComponent=!0}}]);