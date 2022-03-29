"use strict";(self.webpackChunkac3_threat_sightings=self.webpackChunkac3_threat_sightings||[]).push([[7139],{4137:function(e,t,n){n.d(t,{Zo:function(){return p},kt:function(){return m}});var r=n(7294);function a(e,t,n){return t in e?Object.defineProperty(e,t,{value:n,enumerable:!0,configurable:!0,writable:!0}):e[t]=n,e}function o(e,t){var n=Object.keys(e);if(Object.getOwnPropertySymbols){var r=Object.getOwnPropertySymbols(e);t&&(r=r.filter((function(t){return Object.getOwnPropertyDescriptor(e,t).enumerable}))),n.push.apply(n,r)}return n}function i(e){for(var t=1;t<arguments.length;t++){var n=null!=arguments[t]?arguments[t]:{};t%2?o(Object(n),!0).forEach((function(t){a(e,t,n[t])})):Object.getOwnPropertyDescriptors?Object.defineProperties(e,Object.getOwnPropertyDescriptors(n)):o(Object(n)).forEach((function(t){Object.defineProperty(e,t,Object.getOwnPropertyDescriptor(n,t))}))}return e}function s(e,t){if(null==e)return{};var n,r,a=function(e,t){if(null==e)return{};var n,r,a={},o=Object.keys(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||(a[n]=e[n]);return a}(e,t);if(Object.getOwnPropertySymbols){var o=Object.getOwnPropertySymbols(e);for(r=0;r<o.length;r++)n=o[r],t.indexOf(n)>=0||Object.prototype.propertyIsEnumerable.call(e,n)&&(a[n]=e[n])}return a}var c=r.createContext({}),u=function(e){var t=r.useContext(c),n=t;return e&&(n="function"==typeof e?e(t):i(i({},t),e)),n},p=function(e){var t=u(e.components);return r.createElement(c.Provider,{value:t},e.children)},d={inlineCode:"code",wrapper:function(e){var t=e.children;return r.createElement(r.Fragment,{},t)}},l=r.forwardRef((function(e,t){var n=e.components,a=e.mdxType,o=e.originalType,c=e.parentName,p=s(e,["components","mdxType","originalType","parentName"]),l=u(n),m=a,f=l["".concat(c,".").concat(m)]||l[m]||d[m]||o;return n?r.createElement(f,i(i({ref:t},p),{},{components:n})):r.createElement(f,i({ref:t},p))}));function m(e,t){var n=arguments,a=t&&t.mdxType;if("string"==typeof e||a){var o=n.length,i=new Array(o);i[0]=l;var s={};for(var c in t)hasOwnProperty.call(t,c)&&(s[c]=t[c]);s.originalType=e,s.mdxType="string"==typeof e?e:a,i[1]=s;for(var u=2;u<o;u++)i[u]=n[u];return r.createElement.apply(null,i)}return r.createElement.apply(null,n)}l.displayName="MDXCreateElement"},5671:function(e,t,n){n.r(t),n.d(t,{frontMatter:function(){return s},contentTitle:function(){return c},metadata:function(){return u},toc:function(){return p},default:function(){return l}});var r=n(7462),a=n(3366),o=(n(7294),n(4137)),i=["components"],s={},c=void 0,u={unversionedId:"Weapons/adfind",id:"Weapons/adfind",isDocsHomePage:!1,title:"adfind",description:"Found 1 references across 1 AC3 Threat Sightings. Enjoy!",source:"@site/docs/04-Weapons/adfind.md",sourceDirName:"04-Weapons",slug:"/Weapons/adfind",permalink:"/ac3-threat-sightings/docs/Weapons/adfind",tags:[],version:"current",frontMatter:{},sidebar:"tutorialSidebar",previous:{title:"RDP",permalink:"/ac3-threat-sightings/docs/Weapons/RDP"},next:{title:"adhoc-malware",permalink:"/ac3-threat-sightings/docs/Weapons/adhoc-malware"}},p=[{value:"From the AC3 Threat Sighting for <em>Conti Ransomware</em>",id:"from-the-ac3-threat-sighting-for-conti-ransomware",children:[]}],d={toc:p};function l(e){var t=e.components,n=(0,a.Z)(e,i);return(0,o.kt)("wrapper",(0,r.Z)({},d,n,{components:t,mdxType:"MDXLayout"}),(0,o.kt)("p",null,"Found 1 references across 1 AC3 Threat Sightings. Enjoy!"),(0,o.kt)("h2",{id:"from-the-ac3-threat-sighting-for-conti-ransomware"},"From the AC3 Threat Sighting for ",(0,o.kt)("em",{parentName:"h2"},"Conti Ransomware")),(0,o.kt)("p",null,"Full details at: ",(0,o.kt)("a",{parentName:"p",href:"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml"},"https://github.com/mcafee-enterprise/ac3-threat-sightings/blob/main/sightings/Sightings_Conti_Ransomware.yml")),(0,o.kt)("table",null,(0,o.kt)("thead",{parentName:"table"},(0,o.kt)("tr",{parentName:"thead"},(0,o.kt)("th",{parentName:"tr",align:null},"Tactic"),(0,o.kt)("th",{parentName:"tr",align:null},"Procedure"),(0,o.kt)("th",{parentName:"tr",align:null},"Behaviors"),(0,o.kt)("th",{parentName:"tr",align:null},"Observables"))),(0,o.kt)("tbody",{parentName:"table"},(0,o.kt)("tr",{parentName:"tbody"},(0,o.kt)("td",{parentName:"tr",align:null},"Discovery"),(0,o.kt)("td",{parentName:"tr",align:null},"Conti used ",(0,o.kt)("em",{parentName:"td"},"AdFind via Cobalt Strike")," for Discovery."),(0,o.kt)("td",{parentName:"tr",align:null},"Sequence of ",(0,o.kt)("em",{parentName:"td"},"AdFind.exe")," commands."),(0,o.kt)("td",{parentName:"tr",align:null},(0,o.kt)("em",{parentName:"td"},"Process Created"),": ",(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"(objectcategory=person)\\" > ad_users.txt'),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"objectcategory=computer\\" > ad_computers.txt'),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"(objectcategory=organizationalUnit)\\" > ad_ous.txt'),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -sc trustdmp > trustdump.txt"),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f (objectCategory=subnet) > subnets.txt"),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},'adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -f \\"(objectcategory=group)\\" > ad_group.txt'),(0,o.kt)("br",null),"- ",(0,o.kt)("inlineCode",{parentName:"td"},"adfind.exe -h #{ip} -b dc=#{domain} -u #{user} -up #{password} -gcb -sc trustdmp > trustdump.txt"))))))}l.isMDXComponent=!0}}]);