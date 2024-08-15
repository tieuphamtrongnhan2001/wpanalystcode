"use strict";(self.webpackChunktainacan=self.webpackChunktainacan||[]).push([[2302],{86294:(t,e,a)=>{a.d(e,{A:()=>d});var i=a(6934),r=a(40834),n=(a(52730),a(57182),a(43334),a(73889)),l=a(35189);function A(t){return A="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},A(t)}function s(t,e){var a=Object.keys(t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);e&&(i=i.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),a.push.apply(a,i)}return a}function o(t){for(var e=1;e<arguments.length;e++){var a=null!=arguments[e]?arguments[e]:{};e%2?s(Object(a),!0).forEach((function(e){g(t,e,a[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(a)):s(Object(a)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(a,e))}))}return t}function g(t,e,a){return(e=function(t){var e=function(t,e){if("object"!=A(t)||!t)return t;var a=t[Symbol.toPrimitive];if(void 0!==a){var i=a.call(t,e||"default");if("object"!=A(i))return i;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===e?String:Number)(t)}(t,"string");return"symbol"==A(e)?e:e+""}(e))in t?Object.defineProperty(t,e,{value:a,enumerable:!0,configurable:!0,writable:!0}):t[e]=a,t}const d={name:"FiltersTagsList",props:{isInsideModal:Boolean},data:function(){return{swiper:{}}},computed:o(o({},(0,r.L8)("search",{totalItems:"getTotalItems"})),{},{filterTags:function(){var t=this,e=this.getFilterTags(),a=[];return e.forEach((function(e){if(Array.isArray(e.label))for(var i=0;i<e.label.length;i++)a.push({singleLabel:e.label[i],value:e.value[i],filterId:e.filterId,label:"postin"!=e.argType?e.label:e.label+" "+(1==e.label?t.$i18n.get("item"):t.$i18n.get("items")),taxonomy:e.taxonomy,metadatumName:t.getMetadatumName(e),metadatumId:e.metadatumId,argType:e.argType,secondaryMetadatumId:e.secondaryMetadatumId});else a.push({value:e.value,filterId:e.filterId,label:"postin"!=e.argType?e.label:e.label+" "+(1==e.label?t.$i18n.get("item"):t.$i18n.get("items")),taxonomy:e.taxonomy,metadatumName:t.getMetadatumName(e),metadatumId:e.metadatumId,argType:e.argType,secondaryMetadatumId:e.secondaryMetadatumId})})),a}}),watch:{filterTags:{handler:function(){"function"==typeof this.swiper.update&&this.swiper.update()},deep:!0}},mounted:function(){var t=this;(0,i.dY)((function(){t.swiper=new n.A("#tainacanFilterTagsSwiper"+(t.isInsideModal?"InsideModal":""),{mousewheel:!0,observer:!0,resizeObserver:!0,preventInteractionOnTransition:!0,allowClick:!0,allowTouchMove:!0,slideToClickedSlide:!0,slidesPerView:"auto",navigation:{nextEl:"#tainacan-filter-tags-next",prevEl:"#tainacan-filter-tags-prev"},modules:[l.FJ,l.Vx]})}))},beforeUnmount:function(){"function"==typeof this.swiper.destroy&&this.swiper.destroy()},methods:o(o({},(0,r.L8)("search",["getFilterTags"])),{},{removeMetaQuery:function(t){var e=t.filterId,a=t.value,i=t.singleLabel,r=t.label,n=t.taxonomy,l=t.metadatumId,A=t.metadatumName,s=t.argType,o=t.secondaryMetadatumId;this.$eventBusSearch.resetPageOnStore(),this.$eventBusSearch.removeMetaFromFilterTag({filterId:e,singleLabel:i,label:r,value:a,taxonomy:n,metadatumId:l,metadatumName:A,argType:s,secondaryMetadatumId:o})},clearAllFilters:function(){this.$eventBusSearch.resetPageOnStore(),this.$eventBusSearch.clearAllFilters()},getMetadatumName:function(t){return"postin"==t.argType?this.$i18n.get("label_items_selection"):"collection"==t.argType?this.$i18n.get("collection"):t.metadatumName}})}},6069:(t,e,a)=>{a.d(e,{X:()=>b});var i=a(6934),r=function(t){return(0,i.Qi)("data-v-0573b2a0"),t=t(),(0,i.jt)(),t},n={key:0,class:"filter-tags-info"},l=["innerHTML"],A=["innerHTML"],s=["id"],o={class:"swiper-wrapper"},g={class:""},d={class:"filter-tag-metadatum-name"},p=["innerHTML"],u=["onClick"],c=r((function(){return(0,i.Lk)("button",{id:"tainacan-filter-tags-prev",class:"swiper-button-prev"},[(0,i.Lk)("svg",{width:"24",height:"24",viewBox:"0 0 24 24"},[(0,i.Lk)("path",{d:"M15.41 7.41L14 6l-6 6 6 6 1.41-1.41L10.83 12z"}),(0,i.Lk)("path",{d:"M0 0h24v24H0z",fill:"none"})])],-1)})),f=r((function(){return(0,i.Lk)("button",{id:"tainacan-filter-tags-next",class:"swiper-button-next"},[(0,i.Lk)("svg",{width:"24",height:"24",viewBox:"0 0 24 24"},[(0,i.Lk)("path",{d:"M10 6L8.59 7.41 13.17 12l-4.58 4.59L10 18l6-6z"}),(0,i.Lk)("path",{d:"M0 0h24v24H0z",fill:"none"})])],-1)}));function b(t,e,a,r,b,m){return(0,i.uX)(),(0,i.Wv)(i.eB,{name:"filter-item"},{default:(0,i.k6)((function(){return[(0,i.bo)((0,i.Lk)("div",null,[null!=m.filterTags&&m.filterTags.length>0?((0,i.uX)(),(0,i.CE)("p",n,[(0,i.Lk)("span",{style:{"margin-right":"1em"},innerHTML:null===t.totalItems?t.$i18n.get("label_loading_items"):1==t.totalItems?t.$i18n.getWithVariables("info_item_%s_found",[t.totalItems]):t.$i18n.getWithVariables("info_items_%s_found",[t.totalItems])},null,8,l),(0,i.Lk)("span",null,[(0,i.Lk)("span",{innerHTML:1==m.filterTags.length?t.$i18n.getWithVariables("info_%s_applied_filter",[m.filterTags.length]):t.$i18n.getWithVariables("info_%s_applied_filters",[m.filterTags.length])},null,8,A),(0,i.eW)("   "),(0,i.Lk)("a",{id:"button-clear-all",onClick:e[0]||(e[0]=function(t){return m.clearAllFilters()})},(0,i.v_)(t.$i18n.get("label_clear_filters")),1)])])):(0,i.Q3)("",!0),(0,i.Lk)("div",{id:"tainacanFilterTagsSwiper"+(a.isInsideModal?"InsideModal":""),class:"swiper"},[(0,i.Lk)("ul",o,[((0,i.uX)(!0),(0,i.CE)(i.FK,null,(0,i.pI)(m.filterTags,(function(t,e){return(0,i.uX)(),(0,i.CE)("li",{key:e,class:(0,i.C4)(["swiper-slide filter-tag",{"is-readonly":!t.filterId&&"postin"!=t.argType}])},[(0,i.Lk)("span",g,[(0,i.Lk)("div",d,(0,i.v_)(t.metadatumName),1),(0,i.Lk)("div",{class:"filter-tag-metadatum-value",innerHTML:null!=t.singleLabel?t.singleLabel:t.label},null,8,p)]),t.filterId||"postin"==t.argType?((0,i.uX)(),(0,i.CE)("a",{key:0,role:"button",tabindex:"0",class:"tag is-delete",onClick:function(e){return m.removeMetaQuery(t)}},null,8,u)):(0,i.Q3)("",!0)],2)})),128))]),c,f],8,s)],512),[[i.aG,null!=m.filterTags&&m.filterTags.length>0]])]})),_:1})}},53978:(t,e,a)=>{a.d(e,{A:()=>A});var i=a(31601),r=a.n(i),n=a(76314),l=a.n(n)()(r());l.push([t.id,".filter-tags-list[data-v-0573b2a0]{width:100%;padding:1em var(--tainacan-one-column) 1em var(--tainacan-one-column);font-size:0.75em;display:flex;justify-content:flex-start;align-items:baseline;color:var(--tainacan-label-color)}.filter-tags-list .filter-tags-info[data-v-0573b2a0]{margin:0 1.25em 4px 0;white-space:nowrap;display:flex;flex-direction:column}.filter-tags-list .filter-tag[data-v-0573b2a0]{border-radius:4px;padding:3px 8px 2px 8px;position:relative;background-color:var(--tainacan-input-background-color);border:solid 1px var(--tainacan-input-border-color);margin-bottom:0 !important;margin-right:4px !important;max-width:calc(100% - 21px);animation-name:appear;animation-duration:0.3s}.filter-tags-list .filter-tag .filter-tag-metadatum-name[data-v-0573b2a0]{font-size:0.9375em;white-space:nowrap;padding-right:20px}.filter-tags-list .filter-tag .filter-tag-metadatum-value[data-v-0573b2a0]{font-size:1.0625em;font-weight:500;white-space:nowrap}.filter-tags-list .filter-tag .tag.is-delete[data-v-0573b2a0]{position:absolute;right:2px;top:2px;border-radius:50px;background-color:transparent}.filter-tags-list .filter-tag .tag.is-delete[data-v-0573b2a0]:hover,.filter-tags-list .filter-tag .tag.is-delete[data-v-0573b2a0]:focus{border:none;background-color:var(--tainacan-item-hover-background-color);color:var(--tainacan-secondary)}.filter-tags-list .filter-tag.is-readonly[data-v-0573b2a0]{border-style:dashed}.filter-tags-list .swiper[data-v-0573b2a0]{width:100%;position:relative;margin:0;--swiper-navigation-size: 2em;--swiper-navigation-color: var(--tainacan-secondary)}.filter-tags-list .swiper ul.swiper-wrapper[data-v-0573b2a0]{padding-inline-start:0}.filter-tags-list .swiper .swiper-slide[data-v-0573b2a0]{width:auto}.filter-tags-list .swiper .swiper-button-next[data-v-0573b2a0],.filter-tags-list .swiper .swiper-button-prev[data-v-0573b2a0]{padding:34px 26px;border:none;background-color:transparent;position:absolute;top:0;bottom:0}.filter-tags-list .swiper .swiper-button-prev[data-v-0573b2a0]::after,.filter-tags-list .swiper .swiper-rtl .swiper-button-next[data-v-0573b2a0]::after{content:'previous'}.filter-tags-list .swiper .swiper-button-next[data-v-0573b2a0],.filter-tags-list .swiper .swiper-rtl .swiper-button-prev[data-v-0573b2a0]{right:0;background-image:linear-gradient(90deg, rgba(255,255,255,0) 0%, var(--tainacan-background-color) 40%)}.filter-tags-list .swiper .swiper-button-prev[data-v-0573b2a0],.filter-tags-list .swiper .swiper-rtl .swiper-button-next[data-v-0573b2a0]{left:0;background-image:linear-gradient(90deg, var(--tainacan-background-color) 0%, rgba(255,255,255,0) 60%)}.filter-tags-list .swiper .swiper-button-next.swiper-button-disabled[data-v-0573b2a0],.filter-tags-list .swiper .swiper-button-prev.swiper-button-disabled[data-v-0573b2a0]{display:none;visibility:hidden}.filter-tags-list .swiper .swiper-button-next[data-v-0573b2a0]::after,.filter-tags-list .swiper .swiper-button-prev[data-v-0573b2a0]::after{font-family:\"TainacanIcons\";opacity:0.7;transition:opacity ease 0.2s}.filter-tags-list #button-clear-all[data-v-0573b2a0]{margin-left:auto;font-size:1em !important;white-space:nowrap}@media only screen and (max-width: 768px){.filter-tags-list[data-v-0573b2a0]{padding-top:1em;flex-wrap:wrap}.filter-tags-list .filter-tags-info[data-v-0573b2a0]{margin:0 0 4px 0;flex-direction:row;justify-content:space-between}.filter-tags-list .swiper[data-v-0573b2a0]{margin-top:1em}.filter-tags-list .swiper .swiper-button-next[data-v-0573b2a0],.filter-tags-list .swiper .swiper-rtl .swiper-button-prev[data-v-0573b2a0]{padding-right:8px}.filter-tags-list .swiper .swiper-button-prev[data-v-0573b2a0],.filter-tags-list .swiper .swiper-rtl .swiper-button-next[data-v-0573b2a0]{padding-left:8px}}\n",""]);const A=l},50645:(t,e,a)=>{var i=a(85072),r=a.n(i),n=a(97825),l=a.n(n),A=a(77659),s=a.n(A),o=a(55056),g=a.n(o),d=a(10540),p=a.n(d),u=a(63494),c=a.n(u),f=a(53978),b={};b.styleTagTransform=c(),b.setAttributes=g(),b.insert=s().bind(null,"head"),b.domAPI=l(),b.insertStyleElement=p();r()(f.A,b),f.A&&f.A.locals&&f.A.locals},540:(t,e,a)=>{a.r(e),a.d(e,{default:()=>n});var i=a(93676),r=a(79871);a(23118);const n=(0,a(66262).A)(r.A,[["render",i.X],["__scopeId","data-v-0573b2a0"]])},79871:(t,e,a)=>{a.d(e,{A:()=>i.A});var i=a(86294)},93676:(t,e,a)=>{a.d(e,{X:()=>i.X});var i=a(6069)},23118:(t,e,a)=>{a(50645)},56085:t=>{t.exports="data:application/font-woff;charset=utf-8;base64, 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"}}]);