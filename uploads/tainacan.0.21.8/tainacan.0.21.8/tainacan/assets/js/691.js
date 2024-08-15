"use strict";(self.webpackChunktainacan=self.webpackChunktainacan||[]).push([[691],{72986:(t,a,e)=>{function i(t){return i="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},i(t)}function n(t,a){var e=Object.keys(t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);a&&(i=i.filter((function(a){return Object.getOwnPropertyDescriptor(t,a).enumerable}))),e.push.apply(e,i)}return e}function o(t,a,e){return(a=function(t){var a=function(t,a){if("object"!=i(t)||!t)return t;var e=t[Symbol.toPrimitive];if(void 0!==e){var n=e.call(t,a||"default");if("object"!=i(n))return n;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===a?String:Number)(t)}(t,"string");return"symbol"==i(a)?a:a+""}(a))in t?Object.defineProperty(t,a,{value:e,enumerable:!0,configurable:!0,writable:!0}):t[a]=e,t}e.d(a,{A:()=>r});const r={name:"TainacanCollectionSubheader",data:function(){return{activeRoute:"ItemsList",pageTitle:"",activeRouteName:""}},computed:function(t){for(var a=1;a<arguments.length;a++){var e=null!=arguments[a]?arguments[a]:{};a%2?n(Object(e),!0).forEach((function(a){o(t,a,e[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(e)):n(Object(e)).forEach((function(a){Object.defineProperty(t,a,Object.getOwnPropertyDescriptor(e,a))}))}return t}({},(0,e(40834).L8)("collection",{collection:"getCollection"})),watch:{$route:{handler:function(t,a){t.path!=a.path&&(this.activeRoute=t.name,this.pageTitle=this.$route.meta.title)},deep:!0}},created:function(){this.activeRoute=this.$route.name,this.pageTitle=this.$route.meta.title}}},88857:(t,a,e)=>{e.d(a,{A:()=>s});var i=e(69120),n=e(40834);function o(t){return o="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},o(t)}function r(t,a){var e=Object.keys(t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);a&&(i=i.filter((function(a){return Object.getOwnPropertyDescriptor(t,a).enumerable}))),e.push.apply(e,i)}return e}function c(t,a,e){return(a=function(t){var a=function(t,a){if("object"!=o(t)||!t)return t;var e=t[Symbol.toPrimitive];if(void 0!==e){var i=e.call(t,a||"default");if("object"!=o(i))return i;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===a?String:Number)(t)}(t,"string");return"symbol"==o(a)?a:a+""}(a))in t?Object.defineProperty(t,a,{value:e,enumerable:!0,configurable:!0,writable:!0}):t[a]=e,t}const s={name:"CollectionPage",components:{TainacanCollectionSubheader:i.A},data:function(){return{collectionId:[String,Number],isLoadingCollectionBasics:Boolean}},watch:{$route:{handler:function(t,a){var e=this;this.isRepositoryLevel||null==a||null==a.path||t.path==a.path||this.collectionId==this.$route.params.collectionId||(this.isLoadingCollectionBasics=!0,this.collectionId=Number(this.$route.params.collectionId),this.fetchCollectionBasics({collectionId:this.collectionId,isContextEdit:!0}).then((function(){e.isLoadingCollectionBasics=!1})).catch((function(t){e.$console.error(t),e.isLoadingCollectionBasics=!1})))},deep:!0}},created:function(){var t=this;this.collectionId=Number(this.$route.params.collectionId),this.$eventBusSearch.setCollectionId(this.collectionId),this.fetchCollectionBasics({collectionId:this.collectionId,isContextEdit:!0}).then((function(){t.isLoadingCollectionBasics=!1})).catch((function(a){t.$console.error(a),t.isLoadingCollectionBasics=!1}))},methods:function(t){for(var a=1;a<arguments.length;a++){var e=null!=arguments[a]?arguments[a]:{};a%2?r(Object(e),!0).forEach((function(a){c(t,a,e[a])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(e)):r(Object(e)).forEach((function(a){Object.defineProperty(t,a,Object.getOwnPropertyDescriptor(e,a))}))}return t}({},(0,n.i0)("collection",["fetchCollectionBasics"]))}},60906:(t,a,e)=>{e.d(a,{X:()=>O});var i=e(6934),n=function(t){return(0,i.Qi)("data-v-36be3c01"),t=t(),(0,i.jt)(),t},o={id:"tainacan-subheader",class:"secondary-page"},r={class:"back-button is-hidden-mobile"},c=["aria-label","onClick"],s=[n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-previous"})],-1)}))],l={class:"level"},m={class:"level-left"},u={class:"back-button is-hidden-tablet level-item"},d=["aria-label","onClick"],b=[n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-previous"})],-1)}))],p={class:"menu-list level-right"},f=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-items"})],-1)})),h={class:"menu-text"},v=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-settings"})],-1)})),g={class:"menu-text"},y=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-metadata"})],-1)})),k={class:"menu-text"},x=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-filters"})],-1)})),w={class:"menu-text"},C=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-activities"})],-1)})),P={class:"menu-text"},_=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-capability"})],-1)})),$={class:"menu-text"};function O(t,a,e,n,O,L){var I=(0,i.g2)("router-link");return(0,i.uX)(),(0,i.CE)("div",o,[(0,i.Lk)("div",r,["ItemPage"==O.activeRoute||"ItemEditionForm"==O.activeRoute||"ItemCreatePage"==O.activeRoute?((0,i.uX)(),(0,i.Wv)(I,{key:0,to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionItemsPath(t.collection.id,""):"",query:"CollectionItemsPage"==O.activeRoute?t.$route.query:""},custom:""},{default:(0,i.k6)((function(a){var e=a.navigate;return[(0,i.Lk)("button",{role:"link","aria-label":t.$i18n.get("back"),type:"button",class:"button is-turquoise4",onClick:function(t){return e()}},s,8,c)]})),_:1},8,["to"])):(0,i.Q3)("",!0)]),(0,i.Lk)("div",l,[(0,i.Lk)("div",m,[(0,i.Lk)("div",u,["ItemPage"==O.activeRoute||"ItemEditionForm"==O.activeRoute||"ItemCreatePage"==O.activeRoute?((0,i.uX)(),(0,i.Wv)(I,{key:0,to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionItemsPath(t.collection.id,""):"",query:"CollectionItemsPage"==O.activeRoute?t.$route.query:""},custom:""},{default:(0,i.k6)((function(a){var e=a.navigate;return[(0,i.Lk)("button",{role:"link","aria-label":t.$i18n.get("back"),type:"button",class:"button is-turquoise4",onClick:function(t){return e()}},b,8,d)]})),_:1},8,["to"])):(0,i.Q3)("",!0)])]),(0,i.Lk)("ul",p,[(0,i.Lk)("li",{class:(0,i.C4)(["ItemPage"==O.activeRoute||"CollectionItemsPage"==O.activeRoute||"ItemEditionForm"==O.activeRoute||"ItemCreatePage"==O.activeRoute?"is-active":"","level-item"])},[(0,i.bF)(I,{to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionItemsPath(t.collection.id,""):"",query:"CollectionItemsPage"==O.activeRoute?t.$route.query:""},"aria-label":t.$i18n.get("label_collection_items")},{default:(0,i.k6)((function(){return[f,(0,i.Lk)("span",h,(0,i.v_)(t.$i18n.get("items")),1)]})),_:1},8,["to","aria-label"])],2),t.collection&&t.collection.current_user_can_edit?((0,i.uX)(),(0,i.CE)("li",{key:0,class:(0,i.C4)(["CollectionEditionForm"==O.activeRoute?"is-active":"","level-item"])},[(0,i.bF)(I,{to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionEditPath(t.collection.id):""},"aria-label":t.$i18n.get("label_settings")},{default:(0,i.k6)((function(){return[v,(0,i.Lk)("span",g,(0,i.v_)(t.$i18n.get("label_settings")),1)]})),_:1},8,["to","aria-label"])],2)):(0,i.Q3)("",!0),t.collection&&t.collection.current_user_can_edit_metadata?((0,i.uX)(),(0,i.CE)("li",{key:1,class:(0,i.C4)(["CollectionMetadataPage"==O.activeRoute?"is-active":"","level-item"])},[(0,i.bF)(I,{to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionMetadataPath(t.collection.id):""},"aria-label":t.$i18n.get("label_collection_metadata")},{default:(0,i.k6)((function(){return[y,(0,i.Lk)("span",k,(0,i.v_)(t.$i18n.getFrom("metadata","name")),1)]})),_:1},8,["to","aria-label"])],2)):(0,i.Q3)("",!0),t.collection&&t.collection.current_user_can_edit_filters?((0,i.uX)(),(0,i.CE)("li",{key:2,class:(0,i.C4)(["CollectionFiltersPage"==O.activeRoute?"is-active":"","level-item"])},[(0,i.bF)(I,{to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionFiltersPath(t.collection.id):""},"aria-label":t.$i18n.get("label_collection_filters")},{default:(0,i.k6)((function(){return[x,(0,i.Lk)("span",w,(0,i.v_)(t.$i18n.getFrom("filters","name")),1)]})),_:1},8,["to","aria-label"])],2)):(0,i.Q3)("",!0),t.$userCaps.hasCapability("tnc_rep_read_logs")?((0,i.uX)(),(0,i.CE)("li",{key:3,class:(0,i.C4)(["CollectionActivitiesPage"==O.activeRoute?"is-active":"","level-item"])},[(0,i.bF)(I,{to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionActivitiesPath(t.collection.id):""},"aria-label":t.$i18n.get("label_collection_activities")},{default:(0,i.k6)((function(){return[C,(0,i.Lk)("span",P,(0,i.v_)(t.$i18n.get("activities")),1)]})),_:1},8,["to","aria-label"])],2)):(0,i.Q3)("",!0),t.collection&&t.collection.current_user_can_edit_users?((0,i.uX)(),(0,i.CE)("li",{key:4,class:(0,i.C4)(["CollectionCapabilitiesPage"==O.activeRoute?"is-active":"","level-item is-hidden-mobile"])},[(0,i.bF)(I,{to:{path:t.collection&&t.collection.id?t.$routerHelper.getCollectionCapabilitiesPath(t.collection.id):""},"aria-label":t.$i18n.get("label_collection_capabilities")},{default:(0,i.k6)((function(){return[_,(0,i.Lk)("span",$,(0,i.v_)(t.$i18n.get("capabilities")),1)]})),_:1},8,["to","aria-label"])],2)):(0,i.Q3)("",!0)])])])}},59435:(t,a,e)=>{e.d(a,{X:()=>n});var i=e(6934);function n(t,a,e,n,o,r){var c=(0,i.g2)("tainacan-collection-subheader"),s=(0,i.g2)("router-view");return(0,i.uX)(),(0,i.CE)("div",{class:(0,i.C4)(["columns is-fullheight",{"tainacan-admin-collection-item-edition-mode":t.$adminOptions.itemEditionMode,"tainacan-admin-collection-mobile-app-mode":t.$adminOptions.mobileAppMode}])},[(0,i.Lk)("section",{class:"column is-secondary-content",style:(0,i.Tr)(t.$adminOptions.hideRepositorySubheader?"margin-top: 0; height: 100%;":"")},[t.$adminOptions.hideCollectionSubheader?(0,i.Q3)("",!0):((0,i.uX)(),(0,i.Wv)(c,{key:0})),(0,i.bF)(s,{id:"collection-page-container","collection-id":o.collectionId,class:(0,i.C4)(["page-container",{"page-container-small":!t.$adminOptions.hideRepositorySubheader&&!t.$adminOptions.hideCollectionSubheader,"is-loading-collection-basics":o.isLoadingCollectionBasics}])},null,8,["collection-id","class"])],4)],2)}},39589:(t,a,e)=>{e.d(a,{A:()=>c});var i=e(31601),n=e.n(i),o=e(76314),r=e.n(o)()(n());r.push([t.id,".sr-only[data-v-36be3c01]{position:absolute;width:1px;height:1px;padding:0;margin:-1px;overflow:hidden;clip:rect(0, 0, 0, 0);border:0}.icon[data-v-36be3c01]{height:1.5em;width:1.5em}.icon.is-small[data-v-36be3c01]{height:1em;width:1em}.icon.is-medium[data-v-36be3c01]{height:2em;width:2em}.icon.is-large[data-v-36be3c01]{height:3em;width:3em}@keyframes slide-menu-in-36be3c01{from{-ms-transform:translate(-100%, 0);-webkit-transform:translate(-100%, 0);transform:translate(-100%, 0)}to{-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}}@keyframes slide-menu-out-36be3c01{from{-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}to{-ms-transform:translate(-100%, 0);-webkit-transform:translate(-100%, 0);transform:translate(-100%, 0)}}@keyframes appear-36be3c01{from{opacity:0.0;visibility:hidden}to{opacity:1.0;visibility:visible}}@keyframes disappear-36be3c01{from{opacity:0.3;visibility:visible}to{opacity:0.0;visibility:hidden}}.slide-menu-enter-active[data-v-36be3c01]{animation-name:slide-menu-in-36be3c01;animation-duration:0.3s;animation-timing-function:ease-out}.slide-menu-enter-active .modal-background[data-v-36be3c01]{animation-name:appear-36be3c01;animation-duration:0.6s;animation-timing-function:ease-out}.slide-menu-leave-active[data-v-36be3c01]{animation-name:slide-menu-out-36be3c01;animation-duration:0.3s;animation-timing-function:ease-in}.slide-menu-leave-active .modal-background[data-v-36be3c01]{opacity:0.0;animation-name:disappear-36be3c01;animation-duration:0.2s;animation-timing-function:ease-in}@keyframes appear-from-top-tooltip-36be3c01{from{top:24px;opacity:0}to{top:48px;opacity:1}}@keyframes appear-from-top-36be3c01{from{top:-48px}to{top:0px}}@keyframes appear-from-bottom-36be3c01{from{bottom:-48px}to{bottom:-12px}}@keyframes expand-36be3c01{from{max-height:0}to{max-height:222px}}@keyframes item-appear-36be3c01{from{opacity:0;visibility:hidden;transform:translate(0, 12px)}to{opacity:1;visibility:visible;transform:translate(0, 0px)}}.item-appear-enter-active[data-v-36be3c01]{animation-name:item-appear-36be3c01;animation-duration:0.2s;animation-timing-function:ease-out}.item-appear-leave-active[data-v-36be3c01]{animation-name:item-appear-36be3c01;animation-duration:0.2s;animation-timing-function:ease-in;animation-direction:reverse}@keyframes filter-item-in-36be3c01{from{opacity:0;height:0px;max-height:0px;min-height:0px;-ms-transform:translate(0%, -30%);-webkit-transform:translate(0%, -30%);transform:translate(0%, -30%)}to{height:35px;max-height:35px;min-height:35px;opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}}@keyframes filter-item-out-36be3c01{from{height:35px;max-height:35px;min-height:35px;opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}to{height:0px;max-height:0px;min-height:0px;opacity:0;-ms-transform:translate(0%, -30%);-webkit-transform:translate(0%, -30%);transform:translate(0%, -30%)}}.filter-item-enter-active[data-v-36be3c01]{overflow:hidden;animation-name:filter-item-in-36be3c01;animation-duration:0.1s;animation-timing-function:ease}.filter-item-leave-active[data-v-36be3c01]{overflow:hidden;animation-name:filter-item-out-36be3c01;animation-duration:0.1s;animation-timing-function:ease}@keyframes form-collapse-in-36be3c01{from{opacity:0;height:0px;max-height:0px;min-height:0px}to{height:300px;max-height:300px;min-height:300px;opacity:1}}@keyframes form-collapse-out-36be3c01{from{height:300px;max-height:300px;min-height:300px}to{height:0px;max-height:0px;min-height:0px}}.form-collapse-enter-active[data-v-36be3c01]{overflow:hidden;animation-name:form-collapse-in-36be3c01;animation-duration:0.2s;animation-timing-function:ease}.form-collapse-leave-active[data-v-36be3c01]{overflow:hidden;animation-name:form-collapse-out-36be3c01;animation-duration:0.15s;animation-timing-function:ease}@keyframes form-capabilities-in-36be3c01{from{opacity:0;height:0px;max-height:0px;min-height:0px}to{height:120px;max-height:120px;min-height:120px;opacity:1}}@keyframes form-capabilities-out-36be3c01{from{height:120px;max-height:120px;min-height:120px}to{height:0px;max-height:0px;min-height:0px}}.form-capabilities-enter-active[data-v-36be3c01]{overflow:hidden;animation-name:form-capabilities-in-36be3c01;animation-duration:0.2s;animation-timing-function:ease}.form-capabilities-leave-active[data-v-36be3c01]{overflow:hidden;animation-name:form-capabilities-out-36be3c01;animation-duration:0.15s;animation-timing-function:ease}@keyframes filters-menu-in-36be3c01{from{opacity:0;width:0px;max-width:0px;min-width:0px;-ms-transform:translate(-30%, 0%);-webkit-transform:translate(-30%, 0%);transform:translate(-30%, 0%)}to{height:180px;max-width:180px;min-width:180px;opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}}@keyframes filters-menu-out-36be3c01{from{width:180px;max-width:180px;min-width:180px;opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}to{width:0px;max-width:0px;min-width:0px;opacity:0;-ms-transform:translate(-30%, 0%);-webkit-transform:translate(-30%, 0%);transform:translate(-30%, 0%)}}.filters-menu-enter-active[data-v-36be3c01]{animation-name:filters-menu-in-36be3c01;animation-duration:0.2s;animation-timing-function:ease}.filters-menu-leave-active[data-v-36be3c01]{animation-name:filters-menu-out-36be3c01;animation-duration:0.2s;animation-timing-function:ease}@keyframes panel-from-top-in-36be3c01{from{opacity:0.8;-ms-transform:translate(0%, -75%);-webkit-transform:translate(0%, -75%);transform:translate(0%, -75%)}to{opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}}@keyframes panel-from-top-out-36be3c01{from{opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}to{opacity:0.8;-ms-transform:translate(0%, -80%);-webkit-transform:translate(0%, -80%);transform:translate(0%, -80%)}}.panel-from-top-enter-active[data-v-36be3c01]{animation-name:panel-from-top-in-36be3c01;animation-duration:0.3s;animation-timing-function:ease-in}.panel-from-top-leave-active[data-v-36be3c01]{animation-name:panel-from-top-out-36be3c01;animation-duration:0.2s;animation-timing-function:ease-out}@keyframes slide-left-in-36be3c01{from{opacity:0;-ms-transform:translate(-5%, 0%) scale(0.95);-webkit-transform:translate(-5%, 0%) scale(0.95);transform:translate(-5%, 0%) scale(0.95)}to{opacity:1;-ms-transform:translate(0, 0) scale(1);-webkit-transform:translate(0, 0) scale(1);transform:translate(0, 0) scale(1)}}@keyframes slide-left-out-36be3c01{from{opacity:1;-ms-transform:translate(0, 0) scale(1);-webkit-transform:translate(0, 0) scale(1);transform:translate(0, 0) scale(1)}to{opacity:0;-ms-transform:translate(10%, 0%) scale(0.95);-webkit-transform:translate(10%, 0%) scale(0.95);transform:translate(10%, 0%) scale(0.95)}}.slide-left-enter-active[data-v-36be3c01]{animation-name:slide-left-in-36be3c01;animation-duration:0.4s;animation-timing-function:ease}.slide-left-leave-active[data-v-36be3c01]{animation-name:slide-left-out-36be3c01;animation-duration:0.4s;animation-timing-function:ease}@keyframes slide-right-in-36be3c01{from{opacity:0;-ms-transform:translate(10%, 0%) scale(0.95);-webkit-transform:translate(10%, 0%) scale(0.95);transform:translate(10%, 0%) scale(0.95)}to{opacity:1;-ms-transform:translate(0, 0) scale(1);-webkit-transform:translate(0, 0) scale(1);transform:translate(0, 0) scale(1)}}@keyframes slide-right-out-36be3c01{from{opacity:1;-ms-transform:translate(0, 0) scale(1);-webkit-transform:translate(0, 0) scale(1);transform:translate(0, 0) scale(1)}to{opacity:0;-ms-transform:translate(-5%, 0%) scale(0.95);-webkit-transform:translate(-5%, 0%) scale(0.95);transform:translate(-5%, 0%) scale(0.95)}}.slide-right-enter-active[data-v-36be3c01]{animation-name:slide-right-in-36be3c01;animation-duration:0.3s;animation-timing-function:ease}.slide-right-leave-active[data-v-36be3c01]{animation-name:slide-right-out-36be3c01;animation-duration:0.3s;animation-timing-function:ease}@keyframes page-left-in-36be3c01{from{opacity:0;-ms-transform:translate(-5%, 0%);-webkit-transform:translate(-5%, 0%);transform:translate(-5%, 0%)}to{opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}}@keyframes page-left-out-36be3c01{from{opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}to{opacity:0;-ms-transform:translate(10%, 0%);-webkit-transform:translate(10%, 0%);transform:translate(10%, 0%)}}.page-left-enter-active[data-v-36be3c01]{animation-name:page-left-in-36be3c01;animation-duration:0.4s;animation-timing-function:ease}.page-left-leave-active[data-v-36be3c01]{animation-name:page-left-out-36be3c01;animation-duration:0.4s;animation-timing-function:ease}@keyframes page-right-in-36be3c01{from{opacity:0;-ms-transform:translate(10%, 0%);-webkit-transform:translate(10%, 0%);transform:translate(10%, 0%)}to{opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}}@keyframes page-right-out-36be3c01{from{opacity:1;-ms-transform:translate(0, 0);-webkit-transform:translate(0, 0);transform:translate(0, 0)}to{opacity:0;-ms-transform:translate(-5%, 0%);-webkit-transform:translate(-5%, 0%);transform:translate(-5%, 0%)}}.page-right-enter-active[data-v-36be3c01]{animation-name:page-right-in-36be3c01;animation-duration:0.3s;animation-timing-function:ease}.page-right-leave-active[data-v-36be3c01]{animation-name:page-right-out-36be3c01;animation-duration:0.3s;animation-timing-function:ease}@-webkit-keyframes skeleton-animation-36be3c01{0%{opacity:1.0}50%{opacity:0.2}100%{opacity:1.0}}@-moz-keyframes skeleton-animation-36be3c01{0%{opacity:1.0}50%{opacity:0.2}100%{opacity:1.0}}@-o-keyframes skeleton-animation-36be3c01{0%{opacity:1.0}50%{opacity:0.2}100%{opacity:1.0}}@keyframes skeleton-animation-36be3c01{0%{opacity:1.0}50%{opacity:0.2}100%{opacity:1.0}}.skeleton[data-v-36be3c01]{border-radius:2px;background:var(--tainacan-skeleton-color);-webkit-animation:skeleton-animation-36be3c01 1.8s ease infinite;-moz-animation:skeleton-animation-36be3c01 1.8s ease infinite;-o-animation:skeleton-animation-36be3c01 1.8s ease infinite;animation:skeleton-animation-36be3c01 1.8s ease infinite}@keyframes metadatum-highlight-36be3c01{from{background-color:var(--tainacan-primary1)}to{background-color:var(--tainacan-white)}}#tainacan-subheader[data-v-36be3c01]{background-color:var(--tainacan-turquoise5);height:2.35em;max-height:2.35em;width:100%;padding-top:18px;padding-bottom:18px;padding-right:var(--tainacan-one-column);padding-left:0;margin:0px;vertical-align:middle;left:0;right:0;z-index:9;display:flex;align-items:center;transition:padding 0.3s, height 0.3s}#tainacan-subheader h1[data-v-36be3c01]{font-size:1.125em;font-weight:500;color:var(--tainacan-white);line-height:22px;margin-bottom:12px;max-width:450px;text-overflow:ellipsis;white-space:nowrap;overflow:hidden}#tainacan-subheader .back-button[data-v-36be3c01]{padding:0;margin:0;width:var(--tainacan-one-column);min-width:var(--tainacan-one-column);color:var(--tainacan-white);display:flex}#tainacan-subheader .back-button button[data-v-36be3c01],#tainacan-subheader .back-button button[data-v-36be3c01]:hover,#tainacan-subheader .back-button button[data-v-36be3c01]:focus,#tainacan-subheader .back-button button[data-v-36be3c01]:active{width:100%;color:var(--tainacan-white);background-color:transparent !important;border:none;height:2.35em !important}#tainacan-subheader .back-button button .icon[data-v-36be3c01],#tainacan-subheader .back-button button:hover .icon[data-v-36be3c01],#tainacan-subheader .back-button button:focus .icon[data-v-36be3c01],#tainacan-subheader .back-button button:active .icon[data-v-36be3c01]{margin-top:-2px;font-size:1.5em}#tainacan-subheader li[data-v-36be3c01]{margin-right:0px;height:2.35em;transition:background-color 0.2s ease}#tainacan-subheader li.is-active[data-v-36be3c01]{background-color:var(--tainacan-turquoise4)}#tainacan-subheader li.is-active a[data-v-36be3c01]{background-color:var(--tainacan-turquoise4);transition:color 0.2s ease;color:var(--tainacan-white) !important;text-decoration:none}#tainacan-subheader li.is-active svg[data-v-36be3c01]{fill:var(--tainacan-white) !important}#tainacan-subheader li[data-v-36be3c01]:hover:not(.is-active){background-color:var(--tainacan-turquoise4)}#tainacan-subheader li:hover:not(.is-active) a[data-v-36be3c01]{background-color:transparent;text-decoration:none}#tainacan-subheader li a[data-v-36be3c01]{color:var(--tainacan-white) !important;text-align:center;white-space:nowrap;padding:6px 11px;min-width:50px;line-height:22px;border-radius:0px;position:relative;align-items:center;display:block}#tainacan-subheader li a[data-v-36be3c01]:focus{box-shadow:none}#tainacan-subheader li .icon[data-v-36be3c01]{margin:0;padding:0}#tainacan-subheader li .icon svg[data-v-36be3c01]{position:relative;top:2px;margin-bottom:2px;height:16px;fill:var(--tainacan-white)}#tainacan-subheader li .icon .tainacan-icon-capability[data-v-36be3c01]::before{font-size:1.75em !important}#tainacan-subheader li .menu-text[data-v-36be3c01]{margin-left:2px;font-size:0.875em;display:inline-flex}@media screen and (max-width: 769px){#tainacan-subheader[data-v-36be3c01]{width:100% !important;max-width:100% !important;padding:0;top:206px;margin-bottom:0px !important}#tainacan-subheader .level[data-v-36be3c01]{width:100%;display:flex}#tainacan-subheader .level-left[data-v-36be3c01]{margin-left:0px !important;display:flex;padding:0 1em}#tainacan-subheader .level-left .level-item[data-v-36be3c01]{display:inline-flex}#tainacan-subheader .level-right[data-v-36be3c01]{margin-top:0px;flex-flow:wrap;display:flex;align-items:baseline;justify-content:space-between}#tainacan-subheader .level-right .level-item[data-v-36be3c01]{margin-bottom:0}#tainacan-subheader .level-right .level-item a[data-v-36be3c01]{padding:0.45em 0.7em !important;text-align:center}#tainacan-subheader .level-right .level-item .menu-text[data-v-36be3c01]{display:none}}\n",""]);const c=r},98466:(t,a,e)=>{e.d(a,{A:()=>c});var i=e(31601),n=e.n(i),o=e(76314),r=e.n(o)()(n());r.push([t.id,"#collection-page-container.is-loading-collection-basics .section{display:none}\n",""]);const c=r},62394:(t,a,e)=>{var i=e(85072),n=e.n(i),o=e(97825),r=e.n(o),c=e(77659),s=e.n(c),l=e(55056),m=e.n(l),u=e(10540),d=e.n(u),b=e(63494),p=e.n(b),f=e(39589),h={};h.styleTagTransform=p(),h.setAttributes=m(),h.insert=s().bind(null,"head"),h.domAPI=r(),h.insertStyleElement=d();n()(f.A,h),f.A&&f.A.locals&&f.A.locals},35789:(t,a,e)=>{var i=e(85072),n=e.n(i),o=e(97825),r=e.n(o),c=e(77659),s=e.n(c),l=e(55056),m=e.n(l),u=e(10540),d=e.n(u),b=e(63494),p=e.n(b),f=e(98466),h={};h.styleTagTransform=p(),h.setAttributes=m(),h.insert=s().bind(null,"head"),h.domAPI=r(),h.insertStyleElement=d();n()(f.A,h),f.A&&f.A.locals&&f.A.locals},69120:(t,a,e)=>{e.d(a,{A:()=>o});var i=e(76859),n=e(9711);e(63169);const o=(0,e(66262).A)(n.A,[["render",i.X],["__scopeId","data-v-36be3c01"]])},80691:(t,a,e)=>{e.r(a),e.d(a,{default:()=>o});var i=e(84078),n=e(56708);e(93614);const o=(0,e(66262).A)(n.A,[["render",i.X]])},9711:(t,a,e)=>{e.d(a,{A:()=>i.A});var i=e(72986)},56708:(t,a,e)=>{e.d(a,{A:()=>i.A});var i=e(88857)},76859:(t,a,e)=>{e.d(a,{X:()=>i.X});var i=e(60906)},84078:(t,a,e)=>{e.d(a,{X:()=>i.X});var i=e(59435)},63169:(t,a,e)=>{e(62394)},93614:(t,a,e)=>{e(35789)}}]);