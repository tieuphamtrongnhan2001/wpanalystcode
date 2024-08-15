"use strict";(self.webpackChunktainacan=self.webpackChunktainacan||[]).push([[652,4997],{88838:(t,e,a)=>{a.d(e,{A:()=>p});var n=a(40834),i=a(1580),l=a(74042),o=a(72130),c=a(64997),d=a(34706),s=a(84546);function m(t){return m="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},m(t)}function r(t,e){var a=Object.keys(t);if(Object.getOwnPropertySymbols){var n=Object.getOwnPropertySymbols(t);e&&(n=n.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),a.push.apply(a,n)}return a}function u(t){for(var e=1;e<arguments.length;e++){var a=null!=arguments[e]?arguments[e]:{};e%2?r(Object(a),!0).forEach((function(e){b(t,e,a[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(a)):r(Object(a)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(a,e))}))}return t}function b(t,e,a){return(e=function(t){var e=function(t,e){if("object"!=m(t)||!t)return t;var a=t[Symbol.toPrimitive];if(void 0!==a){var n=a.call(t,e||"default");if("object"!=m(n))return n;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===e?String:Number)(t)}(t,"string");return"symbol"==m(e)?e:e+""}(e))in t?Object.defineProperty(t,e,{value:a,enumerable:!0,configurable:!0,writable:!0}):t[e]=a,t}const p={name:"ItemPage",components:{FileItem:i.A,ActivitiesPage:o.default,RelatedItemsList:s.A,AttachmentsList:d.A},mixins:[l.X3],data:function(){return{collectionId:[String,Number],itemId:Number,itemRequestCancel:void 0,isLoading:!1,isLoadingMetadataSections:!1,open:!0,urls_open:!1,entityName:"item",activeTab:"metadata"}},computed:u(u(u(u({},(0,n.L8)("collection",{collection:"getCollection"})),(0,n.L8)("metadata",{metadataSections:"getMetadataSections"})),(0,n.L8)("item",{item:"getItem",totalAttachments:"getTotalAttachments"})),{},{itemMetadata:function(){var t=this;return JSON.parse(JSON.stringify(this.getItemMetadata())).map((function(e){var a=e.metadatum.metadata_section_id;if(!Array.isArray(a))return e;e.metadatum.metadata_section_id="default_section";var n=t.metadataSections.filter((function(t){return a.includes(""+t.id)&&"default_section"!==t.id}));return 1===n.length&&(e.metadatum.metadata_section_id=n[0].id),e}))},totalRelatedItems:function(){return!(!this.item||!this.item.related_items)&&Object.values(this.item.related_items).reduce((function(t,e){return t+parseInt(e.total_items)}),0)},itemVisibility:function(){return this.collection&&"publish"==this.collection.status&&this.item&&"publish"==this.item.status?"open_access":"restrict_access"},tabs:function(){var t=[{slug:"metadata",icon:"metadata",name:this.$i18n.get("metadata"),total:this.itemMetadata.length}];return this.totalRelatedItems&&t.push({slug:"related",icon:"processes tainacan-icon-rotate-270",name:this.$i18n.get("label_related_items"),total:this.totalRelatedItems}),t},shouldDisplayItemSingleDocument:function(){return!this.$adminOptions.hideItemSingleDocument&&this.collection&&this.collection.item_enabled_document_types&&(this.collection.item_enabled_document_types.attachment&&"yes"===this.collection.item_enabled_document_types.attachment.enabled||this.collection.item_enabled_document_types.text&&"yes"===this.collection.item_enabled_document_types.text.enabled||this.collection.item_enabled_document_types.url&&"yes"===this.collection.item_enabled_document_types.url.enabled)},shouldDisplayItemSingleThumbnail:function(){return!this.$adminOptions.hideItemSingleThumbnail&&this.collection&&"yes"===this.collection.item_enable_thumbnail},shouldDisplayItemSingleAttachments:function(){return!this.$adminOptions.hideItemSingleAttachments&&this.collection&&"yes"===this.collection.item_enable_attachments}}),watch:{item:function(){this.updateExtraFormData(this.item)}},created:function(){var t=this;this.collectionId=this.$route.params.collectionId,this.itemId=this.$route.params.itemId,this.isLoading=!0,null!=this.itemRequestCancel&&this.itemRequestCancel.cancel("Item search Canceled."),this.fetchItem({itemId:this.itemId,contextEdit:!0,fetchOnly:"title,thumbnail,status,modification_date,document_type,document_mimetype,document,comment_status,document_as_html,related_items"}).then((function(e){e.request.then((function(e){t.$emitter.emit("onCollectionBreadCrumbUpdate",[{path:t.$routerHelper.getCollectionPath(t.collectionId),label:t.$i18n.get("items")},{path:"",label:e.title}]),t.loadMetadata()})).catch((function(){return t.isLoading=!1})),t.itemRequestCancel=e.source})).catch((function(){return t.isLoading=!1})),this.isLoadingMetadataSections=!0,this.fetchMetadataSections({collectionId:this.collectionId}).then((function(e){t.metadataSectionCollapses=Array(e.length).fill(!0),t.isLoadingMetadataSections=!1})).catch((function(e){t.isLoadingMetadataSections=!1,t.$console.error("Error loading metadata sections ",e)}))},methods:u(u(u(u({},(0,n.i0)("item",["fetchItem","fetchItemMetadata"])),(0,n.L8)("item",["getItemMetadata"])),(0,n.i0)("metadata",["fetchMetadataSections"])),{},{loadMetadata:function(){var t=this;this.fetchItemMetadata(this.itemId).then((function(){t.isLoading=!1}))},openExposersModal:function(){this.$buefy.modal.open({parent:this,component:c.default,hasModalCard:!0,props:{collectionId:this.collectionId,itemId:this.itemId,itemURL:this.item.url,totalItems:1},trapFocus:!0,customClass:"tainacan-modal",closeButtonAriaLabel:this.$i18n.get("close")})},openActivitiesModal:function(){this.$buefy.modal.open({parent:this,component:o.default,customClass:"tainacan-modal",closeButtonAriaLabel:this.$i18n.get("close")})}})}},95017:(t,e,a)=>{a.d(e,{X:()=>Ct});var n=a(6934),i=function(t){return(0,n.Qi)("data-v-81fbb9d6"),t=t(),(0,n.jt)(),t},l={key:0,class:"status-tag"},o={style:{"font-weight":"600"}},c={key:1,class:"icon has-text-gray4",style:{"margin-left":"0.5em"}},d={class:"tainacan-form"},s={class:"columns"},m=["innerHTML"],r={class:"b-tabs"},u={key:0,role:"list",class:"tabs"},b=["id","onClick"],p={class:"icon has-text-gray4"},f={key:0,class:"has-text-gray"},g={key:0,class:"tab-item",role:"tabpanel","aria-labelledby":"metadata-tab-label"},h={class:"metadata-area"},v={class:"metadata-section-header section-label"},_=i((function(){return(0,n.Lk)("span",{class:"icon has-text-gray4"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-metadata"})],-1)})),y={key:0,class:"has-text-gray has-text-weight-normal",style:{"font-size":"0.875em"}},k={class:"label"},x={key:0,class:"icon has-text-gray"},L=i((function(){return(0,n.Lk)("br",null,null,-1)})),w=["innerHTML"],C={key:1,class:"tab-item",role:"tabpanel","aria-labelledby":"related-tab-label",tabindex:"0"},I={class:"related-items-list-heading"},$={key:0,class:"column is-5"},E={class:"sticky-container"},X=["innerHTML"],S={key:1,class:"section-label"},A={class:"icon has-text-gray4 tainacan-icon-1-125em"},M={key:2,class:"section-box document-field"},Q=["innerHTML"],j={key:1},O={key:3,class:"section-label"},T=i((function(){return(0,n.Lk)("span",{class:"icon has-text-gray4"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-1-125em tainacan-icon-image"})],-1)})),D={key:4,class:"section-box section-thumbnail"},F={class:"thumbnail-field"},H={key:1,class:"image"},q={key:0,class:"image-placeholder"},P=["alt","src"],z=i((function(){return(0,n.Lk)("br",null,null,-1)})),R={key:0,class:"thumbnail-alt-input"},W={class:"label"},B={key:5,class:"section-label"},N=i((function(){return(0,n.Lk)("span",{class:"icon has-text-gray4"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-1-125em tainacan-icon-attachments"})],-1)})),V={key:0,class:"has-text-gray has-text-weight-normal"},K={key:6,class:"section-box section-attachments"},U=["innerHTML"],J={class:"footer"},G={key:0,class:"column is-narrow"},Y={class:"section-label"},Z={class:"section-status"},tt={class:"field has-addons"},et={style:{display:"flex"}},at={class:"icon has-text-gray4"},nt={key:0,class:"tainacan-icon tainacan-icon-see"},it={key:1,class:"tainacan-icon tainacan-icon-svg",style:{display:"flex"}},lt=[i((function(){return(0,n.Lk)("svg",{"xmlns:svg":"http://www.w3.org/2000/svg",xmlns:"http://www.w3.org/2000/svg",width:"24px",height:"24px",viewBox:"-1 -1 8 8"},[(0,n.Lk)("g",{id:"layer1",transform:"translate(-71.664352,-160.89128)"},[(0,n.Lk)("path",{id:"path5508",style:{fill:"var(--tainacan-gray4)","fill-opacity":"1",stroke:"none","stroke-width":"0.332731"},d:"m 74.839398,162.85685 c 0.09358,0 0.181945,0.0178 0.265146,0.052 0.08321,0.0356 0.153355,0.0831 0.213173,0.14544 0.06238,0.0624 0.110471,0.13511 0.145584,0.21852 0.03768,0.0806 0.05718,0.16896 0.05718,0.26522 0,0.0973 -0.0196,0.18714 -0.05718,0.2702 -0.03494,0.0806 -0.08321,0.14936 -0.145584,0.20783 -0.05978,0.0599 -0.129971,0.10801 -0.213173,0.14544 -0.08321,0.0356 -0.171572,0.052 -0.265146,0.052 -0.09358,0 -0.181945,-0.0179 -0.265146,-0.052 -0.08061,-0.0378 -0.150755,-0.0859 -0.213173,-0.14544 -0.06238,-0.0585 -0.11179,-0.12726 -0.145585,-0.20783 -0.03494,-0.083 -0.05198,-0.17289 -0.05198,-0.2702 0,-0.0962 0.01675,-0.18466 0.05198,-0.26522 0.03386,-0.0831 0.08321,-0.15578 0.145585,-0.21852 0.06238,-0.0624 0.132573,-0.11051 0.213173,-0.14544 0.08321,-0.0321 0.171571,-0.052 0.265146,-0.052 z"}),(0,n.Lk)("path",{id:"path5461",style:{fill:"var(--tainacan-gray4)","fill-opacity":"1",stroke:"none","stroke-width":"0.332732"},d:"m 74.840268,161.8152 c -0.284646,0 -0.556123,0.0421 -0.816062,0.12511 -0.257339,0.0834 -0.494574,0.20141 -0.712908,0.35362 -0.215775,0.15329 -0.404697,0.33189 -0.571064,0.53975 -0.16601,0.20497 -0.301577,0.43572 -0.401586,0.68713 0.100026,0.24634 0.235559,0.47502 0.401586,0.68527 0.166367,0.20817 0.355335,0.38752 0.571064,0.53977 0.218341,0.14936 0.45556,0.267 0.712908,0.35006 0.259942,0.083 0.531423,0.12333 0.816062,0.12333 h 0.123411 c 0.04156,0 0.08074,-0.004 0.11974,-0.0107 -0.01034,-0.0732 -0.01461,-0.14473 -0.01461,-0.21745 0.0027,-0.0378 0.0053,-0.0752 0.0053,-0.11408 0.0028,-0.0417 0.0068,-0.0854 0.01462,-0.13083 -0.07667,0.0143 -0.158987,0.0214 -0.248677,0.0214 -0.211852,0 -0.418798,-0.0285 -0.618955,-0.0884 -0.19756,-0.0584 -0.385072,-0.14258 -0.561853,-0.2506 -0.174173,-0.10658 -0.33177,-0.23526 -0.473425,-0.3887 -0.139059,-0.15578 -0.254594,-0.33009 -0.348169,-0.52131 0.09618,-0.20034 0.216239,-0.37725 0.35921,-0.53053 0.145587,-0.15222 0.304788,-0.28054 0.478964,-0.38867 0.176742,-0.1105 0.362449,-0.19464 0.56001,-0.2506 0.197559,-0.0545 0.401772,-0.0828 0.609743,-0.0828 0.210571,0 0.415875,0.0285 0.613431,0.0884 0.200161,0.0599 0.388758,0.14545 0.565538,0.25596 0.176775,0.10765 0.334374,0.23812 0.473428,0.39422 0.137741,0.15329 0.254594,0.32617 0.348169,0.51583 -0.01426,0.0285 -0.02923,0.0524 -0.04605,0.0774 -0.01426,0.025 -0.03101,0.047 -0.04792,0.072 0.155958,0.0356 0.298689,0.10016 0.427371,0.19357 0.06238,-0.11694 0.114785,-0.23065 0.160271,-0.34259 -0.09749,-0.25201 -0.227859,-0.4818 -0.394219,-0.68713 -0.166368,-0.20818 -0.360082,-0.38646 -0.578427,-0.53975 -0.218343,-0.15221 -0.456649,-0.27056 -0.716588,-0.35362 -0.25734,-0.0831 -0.527216,-0.12512 -0.810547,-0.12512 z m 1.541874,2.02267 c -0.08238,0 -0.158347,0.0179 -0.230248,0.0478 -0.07073,0.0321 -0.131931,0.073 -0.186045,0.12726 -0.0529,0.0528 -0.09635,0.11586 -0.127119,0.18786 -0.03137,0.0706 -0.04605,0.1465 -0.04605,0.2285 v 0.23776 h -0.117885 c -0.0658,0 -0.122129,0.025 -0.167652,0.0699 -0.04613,0.0442 -0.06816,0.0987 -0.06816,0.16397 v 1.18268 c 0,0.0639 0.0221,0.11978 0.06816,0.16576 0.04552,0.0456 0.101846,0.0681 0.167652,0.0681 h 1.416601 c 0.06521,0 0.121522,-0.0214 0.16765,-0.0681 0.04549,-0.0442 0.06816,-0.10051 0.06816,-0.16576 v -1.18268 c 0,-0.0652 -0.02281,-0.11977 -0.06816,-0.16397 -0.04613,-0.0456 -0.102451,-0.0699 -0.16765,-0.0699 h -0.117888 v -0.23776 c 0,-0.0816 -0.01533,-0.15757 -0.04605,-0.2285 -0.03137,-0.072 -0.07483,-0.13511 -0.128937,-0.18786 -0.05286,-0.0542 -0.114108,-0.0959 -0.186045,-0.12726 -0.07073,-0.0321 -0.148473,-0.0478 -0.230283,-0.0478 z m 0,0.23777 c 0.0504,0 0.09881,0.007 0.141841,0.025 0.04242,0.018 0.07917,0.0449 0.110544,0.0773 0.03244,0.0321 0.05707,0.0681 0.07554,0.11051 0.01782,0.0431 0.0278,0.0895 0.0278,0.14011 v 0.23775 h -0.70922 v -0.23775 c 0,-0.0503 0.0093,-0.097 0.02745,-0.14011 0.01782,-0.0424 0.04231,-0.0791 0.07368,-0.11051 0.03244,-0.0321 0.06933,-0.0589 0.112361,-0.0773 0.04242,-0.0178 0.08898,-0.025 0.139987,-0.025 z m 0,1.17897 c 0.06517,0 0.121522,0.025 0.16765,0.0699 0.04552,0.046 0.07002,0.1023 0.07002,0.16755 0,0.0659 -0.02462,0.12226 -0.07002,0.16968 -0.04613,0.046 -0.102451,0.0681 -0.16765,0.0681 -0.0658,0 -0.120276,-0.0214 -0.165798,-0.0681 -0.04613,-0.0474 -0.07002,-0.10374 -0.07002,-0.16968 0,-0.0652 0.02388,-0.12157 0.07002,-0.16755 0.04549,-0.0456 0.09999,-0.0699 0.165798,-0.0699 z"}),(0,n.Lk)("g",{id:"use1344",transform:"matrix(0.157413,0,0,0.157413,74.965914,165.96635)",style:{fill:"var(--tainacan-gray4)","fill-opacity":"1"}})])],-1)}))],ot={key:1,class:"column is-narrow"},ct={class:"section-label"},dt=i((function(){return(0,n.Lk)("span",{class:"icon has-text-gray4"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-comment"})],-1)})),st={class:"section-status"},mt={class:"field has-addons"},rt={key:0,class:"icon"},ut=[i((function(){return(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-close"},null,-1)}))],bt={key:1,class:"icon"},pt=[i((function(){return(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-approved"},null,-1)}))],ft={class:"form-submission-footer"},gt=["aria-label","disabled"],ht=i((function(){return(0,n.Lk)("span",{class:"icon is-large"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-activities"})],-1)})),vt={class:"is-hidden-touch"},_t=["aria-label","disabled"],yt=i((function(){return(0,n.Lk)("span",{class:"icon is-large"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-viewas"})],-1)})),kt={class:"is-hidden-touch"},xt=["href"],Lt=i((function(){return(0,n.Lk)("span",{class:"icon is-large"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-openurl"})],-1)})),wt=i((function(){return(0,n.Lk)("span",{class:"icon is-large"},[(0,n.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-edit"})],-1)}));function Ct(t,e,a,i,Ct,It){var $t=(0,n.g2)("b-loading"),Et=(0,n.g2)("help-button"),Xt=(0,n.g2)("tainacan-title"),St=(0,n.g2)("related-items-list"),At=(0,n.g2)("file-item"),Mt=(0,n.g2)("attachments-list"),Qt=(0,n.g2)("router-link");return(0,n.uX)(),(0,n.CE)("div",null,[(0,n.bF)($t,{modelValue:Ct.isLoading,"onUpdate:modelValue":e[0]||(e[0]=function(t){return Ct.isLoading=t}),"can-cancel":!1},null,8,["modelValue"]),t.$adminOptions.hideItemSinglePageTitle?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.Wv)(Xt,{key:0,"bread-crumb-items":[{path:"",label:t.$i18n.get("item")}]},{default:(0,n.k6)((function(){return[(0,n.Lk)("h1",null,[null==t.item||null==t.item||null==t.item.status||Ct.isLoading?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.CE)("span",l,(0,n.v_)(t.$i18n.get("status_"+t.item.status)),1)),(0,n.eW)(" "+(0,n.v_)(t.$i18n.get("title_item_page")+" ")+" ",1),(0,n.Lk)("span",o,(0,n.v_)(null!=t.item&&null!=t.item?t.item.title:""),1),null==t.item||null==t.item||null==t.item.status||"autodraft"==t.item.status||Ct.isLoading?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.CE)("span",c,[(0,n.Lk)("i",{class:(0,n.C4)(["tainacan-icon tainacan-icon-1em",t.$statusHelper.getIcon(t.item.status)])},null,2),(0,n.bF)(Et,{title:t.$i18n.get("status_"+t.item.status),message:t.$i18n.get("info_item_"+t.item.status)+" "+t.$i18n.get("instruction_edit_item_status")},null,8,["title","message"])]))])]})),_:1},8,["bread-crumb-items"])),(0,n.Lk)("div",d,[(0,n.Lk)("div",s,[(0,n.Lk)("div",{class:(0,n.C4)(["column",It.shouldDisplayItemSingleDocument||It.shouldDisplayItemSingleThumbnail?"is-7":"is-12"])},[t.hasBeginRightForm?((0,n.uX)(),(0,n.CE)("div",{key:0,id:"view-item-begin-right",class:"form-hook-region",innerHTML:t.getBeginRightForm},null,8,m)):(0,n.Q3)("",!0),(0,n.Lk)("div",r,[It.tabs.length>=2?((0,n.uX)(),(0,n.CE)("nav",u,[(0,n.Lk)("ul",null,[((0,n.uX)(!0),(0,n.CE)(n.FK,null,(0,n.pI)(It.tabs,(function(t,e){return(0,n.uX)(),(0,n.CE)("li",{id:t.slug+"-tab-label",key:e,class:(0,n.C4)({"is-active":Ct.activeTab===t.slug}),onClick:function(e){return Ct.activeTab=t.slug}},[(0,n.Lk)("a",null,[(0,n.Lk)("span",p,[(0,n.Lk)("i",{class:(0,n.C4)("tainacan-icon tainacan-icon-18px tainacan-icon-"+t.icon)},null,2)]),(0,n.Lk)("span",null,(0,n.v_)(t.name),1),t.total?((0,n.uX)(),(0,n.CE)("span",f,"  ("+(0,n.v_)(t.total)+") ",1)):(0,n.Q3)("",!0)])],10,b)})),128))])])):(0,n.Q3)("",!0),(0,n.Lk)("section",{style:(0,n.Tr)(It.tabs.length<2?"border-top: none; padding-top: 0;":""),class:"tab-content"},["metadata"===Ct.activeTab?((0,n.uX)(),(0,n.CE)("div",g,[(0,n.Lk)("div",h,[((0,n.uX)(!0),(0,n.CE)(n.FK,null,(0,n.pI)(t.metadataSections,(function(e,a){return(0,n.uX)(),(0,n.CE)("div",{key:a},[(0,n.Lk)("div",v,[(0,n.Lk)("label",null,[_,(0,n.eW)(" "+(0,n.v_)(e.name)+"  ",1),e.metadata_object_list&&e.metadata_object_list.length?((0,n.uX)(),(0,n.CE)("span",y," ("+(0,n.v_)(e.metadata_object_list.length)+") ",1)):(0,n.Q3)("",!0)])]),It.itemMetadata&&Array.isArray(It.itemMetadata)?((0,n.uX)(),(0,n.CE)(n.FK,{key:0},[((0,n.uX)(!0),(0,n.CE)(n.FK,null,(0,n.pI)(It.itemMetadata.filter((function(t){return t.metadatum.metadata_section_id==e.id})),(function(e,a){return(0,n.uX)(),(0,n.CE)("div",{key:a,class:"field"},[(0,n.Lk)("label",k,[(0,n.eW)((0,n.v_)(e.metadatum.name)+" ",1),"publish"!==e.metadatum.status?((0,n.uX)(),(0,n.CE)("span",x,[(0,n.Lk)("i",{class:(0,n.C4)(["tainacan-icon tainacan-icon-1em",t.$statusHelper.getIcon(e.metadatum.status)])},null,2)])):(0,n.Q3)("",!0)]),(0,n.Lk)("div",{class:(0,n.C4)([{"metadata-type-textarea":"tainacan-textarea"==e.metadatum.metadata_type_object.component,"metadata-type-compound":"tainacan-compound"==e.metadatum.metadata_type_object.component,"metadata-type-relationship":"tainacan-relationship"==e.metadatum.metadata_type_object.component},"content"])},[((0,n.uX)(),(0,n.Wv)((0,n.$y)("tainacan-compound"==e.metadatum.metadata_type_object.component||"tainacan-relationship"==e.metadatum.metadata_type_object.component&&e.metadatum.metadata_type_object.options&&e.metadatum.metadata_type_object.options.display_related_item_metadata&&e.metadatum.metadata_type_object.options.display_related_item_metadata.length>1?"div":"p"),{innerHTML:""!=e.value_as_html?e.value_as_html:"<p><span class='has-text-gray is-italic'>"+t.$i18n.get("label_value_not_provided")+"</span></p>"},null,8,["innerHTML"]))],2)])})),128)),L],64)):(0,n.Q3)("",!0)])})),128))]),t.hasEndRightForm?((0,n.uX)(),(0,n.CE)("div",{key:0,id:"view-item-end-right",class:"form-hook-region",innerHTML:t.getEndRightForm},null,8,w)):(0,n.Q3)("",!0)])):(0,n.Q3)("",!0),It.totalRelatedItems&&"related"===Ct.activeTab?((0,n.uX)(),(0,n.CE)("div",C,[(0,n.Lk)("div",I,[(0,n.Lk)("p",null,(0,n.v_)(t.$i18n.get("info_related_items")),1)]),(0,n.bF)(St,{"is-loading":Ct.isLoading,"onUpdate:isLoading":e[1]||(e[1]=function(t){return Ct.isLoading=t}),"item-id":Ct.itemId,"collection-id":Ct.collectionId,"related-items":t.item.related_items,"is-editable":!1},null,8,["is-loading","item-id","collection-id","related-items"])])):(0,n.Q3)("",!0)],4)])],2),It.shouldDisplayItemSingleDocument||It.shouldDisplayItemSingleThumbnail?((0,n.uX)(),(0,n.CE)("div",$,[(0,n.Lk)("div",E,[t.hasBeginLeftForm?((0,n.uX)(),(0,n.CE)("div",{key:0,id:"view-item-begin-left",class:"form-hook-region",innerHTML:t.getBeginLeftForm},null,8,X)):(0,n.Q3)("",!0),It.shouldDisplayItemSingleDocument?((0,n.uX)(),(0,n.CE)("div",S,[(0,n.Lk)("label",null,[(0,n.Lk)("span",A,[(0,n.Lk)("i",{class:(0,n.C4)("tainacan-icon tainacan-icon-"+(t.item.document_type&&"empty"!=t.item.document_type?"attachment"==t.item.document_type?"attachments":t.item.document_type:"item"))},null,2)]),(0,n.eW)(" "+(0,n.v_)(t.collection&&t.collection.item_document_label?t.collection.item_document_label:null!=t.item.document&&null!=t.item.document&&""!=t.item.document?t.$i18n.get("label_document"):t.$i18n.get("label_document_empty")),1)])])):(0,n.Q3)("",!0),It.shouldDisplayItemSingleDocument?((0,n.uX)(),(0,n.CE)("div",M,[void 0!==t.item.document&&null!==t.item.document&&void 0!==t.item.document_type&&null!==t.item.document_type&&""!==t.item.document&&"empty"!==t.item.document_type?((0,n.uX)(),(0,n.CE)("div",{key:0,class:(0,n.C4)(["document-field-content","document-field-content--"+t.item.document_type])},[(0,n.Lk)("div",{innerHTML:t.item.document_as_html},null,8,Q)],2)):((0,n.uX)(),(0,n.CE)("div",j,[(0,n.Lk)("p",null,(0,n.v_)(t.$i18n.get("info_no_document_to_item")),1)]))])):(0,n.Q3)("",!0),It.shouldDisplayItemSingleThumbnail?((0,n.uX)(),(0,n.CE)("div",O,[(0,n.Lk)("label",null,[T,(0,n.eW)(" "+(0,n.v_)(t.collection&&t.collection.item_thumbnail_label?t.collection.item_thumbnail_label:t.$i18n.get("label_thumbnail")),1)])])):(0,n.Q3)("",!0),It.shouldDisplayItemSingleThumbnail?((0,n.uX)(),(0,n.CE)("div",D,[(0,n.Lk)("div",F,[null!=t.item.thumbnail&&(null!=t.item.thumbnail["tainacan-medium"]&&0!=t.item.thumbnail["tainacan-medium"]||null!=t.item.thumbnail.medium&&0!=t.item.thumbnail.medium)?((0,n.uX)(),(0,n.Wv)(At,{key:0,"show-name":!1,"modal-on-click":!1,size:125,file:{media_type:"image",thumbnails:{"tainacan-medium":[t.$thumbHelper.getSrc(t.item.thumbnail,"tainacan-medium",t.item.document_mimetype)]},title:t.$i18n.get("label_thumbnail"),description:"<img alt='"+t.$i18n.get("label_thumbnail")+"' src='"+t.$thumbHelper.getSrc(t.item.thumbnail,"full",t.item.document_mimetype)+"'/>"}},null,8,["file"])):(0,n.Q3)("",!0),null!=t.item.thumbnail&&(null!=t.item.thumbnail.medium&&0!=t.item.thumbnail.medium||null!=t.item.thumbnail["tainacan-medium"]&&0!=t.item.thumbnail["tainacan-medium"])?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.CE)("figure",H,["empty"==t.item.document_type?((0,n.uX)(),(0,n.CE)("span",q,(0,n.v_)(t.$i18n.get("label_empty_thumbnail")),1)):(0,n.Q3)("",!0),(0,n.Lk)("img",{alt:t.$i18n.get("label_thumbnail"),src:t.$thumbHelper.getEmptyThumbnailPlaceholder(t.item.document_mimetype)},null,8,P)]))]),z,t.item.thumbnail_id?((0,n.uX)(),(0,n.CE)("div",R,[(0,n.Lk)("label",W,(0,n.v_)(t.$i18n.get("label_thumbnail_alt")),1),(0,n.bF)(Et,{title:t.$i18n.get("label_thumbnail_alt"),message:t.$i18n.get("info_thumbnail_alt")},null,8,["title","message"]),(0,n.Lk)("p",null,(0,n.v_)(t.item.thumbnail_alt),1)])):(0,n.Q3)("",!0)])):(0,n.Q3)("",!0),It.shouldDisplayItemSingleAttachments?((0,n.uX)(),(0,n.CE)("div",B,[(0,n.Lk)("label",null,[N,(0,n.Lk)("span",null,[(0,n.eW)((0,n.v_)(t.collection&&t.collection.item_attachment_label?t.collection.item_attachment_label:t.$i18n.get("label_attachments"))+"  ",1),t.totalAttachments?((0,n.uX)(),(0,n.CE)("span",V," ("+(0,n.v_)(t.totalAttachments)+") ",1)):(0,n.Q3)("",!0)])])])):(0,n.Q3)("",!0),null!=t.item&&null!=t.item.id&&!Ct.isLoading&&It.shouldDisplayItemSingleAttachments?((0,n.uX)(),(0,n.CE)("div",K,[(0,n.bF)(Mt,{item:t.item,form:t.item,collection:t.collection},null,8,["item","form","collection"])])):(0,n.Q3)("",!0),t.hasEndLeftForm?((0,n.uX)(),(0,n.CE)("div",{key:7,id:"view-item-end-left",class:"form-hook-region",innerHTML:t.getEndLeftForm},null,8,U)):(0,n.Q3)("",!0)])])):(0,n.Q3)("",!0)]),(0,n.Lk)("footer",J,[t.$adminOptions.hideItemSingleCurrentVisibility?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.CE)("div",G,[(0,n.Lk)("div",Y,[(0,n.Lk)("label",null,(0,n.v_)(t.$i18n.get("label_visibility")),1)]),(0,n.Lk)("div",Z,[(0,n.Lk)("div",tt,[(0,n.Lk)("span",et,[(0,n.Lk)("span",at,["open_access"==It.itemVisibility?((0,n.uX)(),(0,n.CE)("i",nt)):((0,n.uX)(),(0,n.CE)("i",it,lt))]),(0,n.eW)(" "+(0,n.v_)(t.$i18n.get("label_"+It.itemVisibility)),1)])])])])),t.collection&&t.collection.allow_comments&&"open"==t.collection.allow_comments&&!t.$adminOptions.hideItemSingleCommentsOpen?((0,n.uX)(),(0,n.CE)("div",ot,[(0,n.Lk)("div",ct,[dt,(0,n.Lk)("label",null,(0,n.v_)(t.$i18n.get("label_comments")),1)]),(0,n.Lk)("div",st,[(0,n.Lk)("div",mt,[(0,n.Lk)("span",null,["open"!=t.item.comment_status?((0,n.uX)(),(0,n.CE)("span",rt,ut)):(0,n.Q3)("",!0),"open"==t.item.comment_status?((0,n.uX)(),(0,n.CE)("span",bt,pt)):(0,n.Q3)("",!0),(0,n.eW)(" "+(0,n.v_)("open"==t.item.comment_status?t.$i18n.get("label_allowed"):t.$i18n.get("label_not_allowed")),1)])])])])):(0,n.Q3)("",!0),(0,n.Lk)("div",ft,[t.item.current_user_can_edit&&1==t.$route.query.recent?((0,n.uX)(),(0,n.Wv)(Qt,{key:0,class:"button is-secondary",style:{"margin-right":"auto"},to:{path:t.$routerHelper.getNewItemPath(Ct.collectionId)}},{default:(0,n.k6)((function(){return[(0,n.Lk)("span",null,(0,n.v_)(t.$i18n.get("label_create_another_item")),1)]})),_:1},8,["to"])):(0,n.Q3)("",!0),t.$adminOptions.hideItemSingleActivities?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.CE)("button",{key:1,class:"button sequence-button","aria-label":t.$i18n.get("label_view_activity_logs"),disabled:Ct.isLoading,onClick:e[2]||(e[2]=function(t){return It.openActivitiesModal()})},[ht,(0,n.Lk)("span",vt,(0,n.v_)(t.$i18n.get("label_view_activity_logs")),1)],8,gt)),t.$adminOptions.hideItemSingleExposers?(0,n.Q3)("",!0):((0,n.uX)(),(0,n.CE)("button",{key:2,class:"button sequence-button","aria-label":t.$i18n.get("label_view_as"),disabled:Ct.isLoading,onClick:e[3]||(e[3]=function(t){return It.openExposersModal()})},[yt,(0,n.Lk)("span",kt,(0,n.v_)(t.$i18n.get("label_view_as")),1)],8,_t)),(0,n.Lk)("a",{target:"_blank",class:"button sequence-button is-pulled-right",href:t.item.url},[Lt,(0,n.Lk)("span",null,(0,n.v_)(t.$i18n.get("label_item_page_on_website")),1)],8,xt),t.item.current_user_can_edit?((0,n.uX)(),(0,n.Wv)(Qt,{key:3,class:"button is-secondary",to:{path:t.$routerHelper.getItemEditPath(Ct.collectionId,Ct.itemId)}},{default:(0,n.k6)((function(){return[wt,(0,n.Lk)("span",null,(0,n.v_)(t.$i18n.getFrom("items","edit_item")),1)]})),_:1},8,["to"])):(0,n.Q3)("",!0)])])])])}},91366:(t,e,a)=>{a.d(e,{A:()=>c});var n=a(31601),i=a.n(n),l=a(76314),o=a.n(l)()(i());o.push([t.id,".page-container[data-v-81fbb9d6]{padding:0px 0px 60px 0px}.page-container>.tainacan-form[data-v-81fbb9d6]{margin-bottom:60px}.page-container>.tainacan-form .field[data-v-81fbb9d6]:not(:last-child){margin-bottom:0.5em}.page-container .tainacan-page-title[data-v-81fbb9d6]{margin-top:var(--tainacan-container-padding);padding:0 var(--tainacan-one-column)}.page-container .tainacan-page-title .status-tag[data-v-81fbb9d6]{color:var(--tainacan-white);background:var(--tainacan-turquoise5);padding:0.15em 0.5em;font-size:0.75em;margin:0 1em 0 0;font-weight:600;position:relative;top:-2px;border-radius:2px}@media screen and (max-width: 769px){.page-container .tainacan-page-title[data-v-81fbb9d6]{padding:0 0.5em;margin-bottom:1.25rem !important}}.page-container .tainacan-form>.columns[data-v-81fbb9d6]{margin-left:var(--tainacan-one-column);margin-right:var(--tainacan-one-column)}.page-container .tainacan-form>.columns .column.is-5[data-v-81fbb9d6]{padding-top:0;padding-left:var(--tainacan-one-column);padding-right:var(--tainacan-one-column)}@media screen and (min-width: 770px){.page-container .tainacan-form>.columns .column.is-5 .sticky-container[data-v-81fbb9d6]{position:relative;position:sticky;top:0;margin:0;max-height:calc(100vh - 202px);overflow-y:auto;overflow-x:hidden}}.page-container .tainacan-form>.columns .column.is-7[data-v-81fbb9d6]{padding-top:0;padding-left:var(--tainacan-one-column);padding-right:0}.page-container .tainacan-form>.columns .column.is-7 .columns[data-v-81fbb9d6]{flex-wrap:wrap;justify-content:space-between}.page-container .tainacan-form>.columns .column.is-7 .columns .column[data-v-81fbb9d6]{padding:1em 12px 0 12px}.page-container .tainacan-form>.columns .column.is-7 .field[data-v-81fbb9d6]{padding:10px 0 14px 0px;margin-left:-3px}@media screen and (max-width: 769px){.page-container .tainacan-form>.columns .column.is-7[data-v-81fbb9d6]{padding-right:var(--tainacan-one-column);width:100%}}@media screen and (max-width: 1440px){.page-container .tainacan-form>.columns>.column.is-7[data-v-81fbb9d6]{padding-left:0.75em}.page-container .tainacan-form>.columns>.column.is-5[data-v-81fbb9d6]{padding-right:0.75em}}@media screen and (max-width: 769px){.page-container .tainacan-form>.columns[data-v-81fbb9d6]{margin-left:0;margin-right:0;display:flex;flex-direction:column-reverse}.page-container .tainacan-form>.columns>.column.is-7[data-v-81fbb9d6]{padding-left:0;padding-right:0;max-width:100%;width:100%}.page-container .tainacan-form>.columns>.column.is-7 .sub-header[data-v-81fbb9d6]{padding-right:0.5em;padding-left:0.5em}.page-container .tainacan-form>.columns>.column.is-7 .field[data-v-81fbb9d6]{padding:1em 0.75em}.page-container .tainacan-form>.columns>.column.is-7 .field[data-v-81fbb9d6] .collapse-handle{font-size:1em;margin-left:0;margin-right:22px;width:100%;display:block}.page-container .tainacan-form>.columns>.column.is-7 .field[data-v-81fbb9d6] .collapse-handle .label{margin-left:2px}.page-container .tainacan-form>.columns>.column.is-7 .field[data-v-81fbb9d6] .collapse-handle .icon{float:right;width:3em;justify-content:flex-end}.page-container .tainacan-form>.columns>.column.is-7 .tab-content[data-v-81fbb9d6]{padding-left:0;padding-right:0}.page-container .tainacan-form>.columns>.column.is-7 .tab-item>.field[data-v-81fbb9d6]:last-child{margin-bottom:24px}.page-container .tainacan-form>.columns>.column.is-7>.columns[data-v-81fbb9d6]{display:flex}.page-container .tainacan-form>.columns>.column.is-5[data-v-81fbb9d6]{max-width:100%;width:100%;padding-left:0.5em;padding-right:0.5em}}.page-container .b-tabs[data-v-81fbb9d6]{overflow:hidden !important;margin-top:-7px}@media screen and (max-width: 769px){.page-container[data-v-81fbb9d6] .section-attachments .table-container{padding-left:0;padding-right:0}}.metadata-area .metadata-section-header[data-v-81fbb9d6]{padding:0.5em 0.25em 0.5em 0em;border-bottom:1px solid var(--tainacan-input-border-color)}.metadata-area .field[data-v-81fbb9d6]{border-bottom:1px solid var(--tainacan-gray1);padding:10px var(--tainacan-container-padding) !important;margin-left:1em !important}.metadata-area .field .label[data-v-81fbb9d6]{font-size:0.875em;font-weight:500;margin-bottom:0.5em;display:inline-flex;align-items:center}.metadata-area .field .label span[data-v-81fbb9d6]{margin-right:18px}.metadata-area .field p[data-v-81fbb9d6]:empty{display:none;visibility:hidden}.section-label[data-v-81fbb9d6]{position:relative}.section-label label[data-v-81fbb9d6]{font-size:1em !important;font-weight:500 !important;color:var(--tainacan-label-color) !important;line-height:1.2em}.section-box+.section-label[data-v-81fbb9d6]{border-top:1px solid var(--tainacan-gray1);padding-top:6px}.section-box[data-v-81fbb9d6]{padding:0 1em 0 1.875em;margin-top:10px;margin-bottom:16px;position:relative}.section-status[data-v-81fbb9d6]{font-size:0.875em}.section-status .field[data-v-81fbb9d6]{border-bottom:none}.section-status .field .icon[data-v-81fbb9d6]{font-size:1.125em !important;color:var(--tainacan-info-color)}.section-thumbnail[data-v-81fbb9d6]{display:flex}.section-thumbnail .thumbnail-alt-input[data-v-81fbb9d6]{margin-left:1em}.document-field .document-field-content[data-v-81fbb9d6]{max-height:32vh}.document-field .document-field-content.document-field-content--text[data-v-81fbb9d6]{padding-bottom:2rem}.document-field .document-field-content.document-field-content--text[data-v-81fbb9d6] article{max-height:calc(32vh - 2rem);overflow-y:auto}.document-field .document-field-content[data-v-81fbb9d6] img,.document-field .document-field-content[data-v-81fbb9d6] video,.document-field .document-field-content[data-v-81fbb9d6] figure{max-width:100%;max-height:32vh;width:auto;margin:0}.document-field .document-field-content[data-v-81fbb9d6] img{width:auto !important}.document-field .document-field-content[data-v-81fbb9d6] a{min-height:60px;display:block}.document-field .document-field-content[data-v-81fbb9d6] audio,.document-field .document-field-content[data-v-81fbb9d6] iframe,.document-field .document-field-content[data-v-81fbb9d6] blockquote{max-width:100%;max-height:32vh;width:100%;margin:0;min-height:150px}.document-field .document-field-content[data-v-81fbb9d6] audio{min-height:80px}@media screen and (max-height: 760px){.document-field .document-field-content[data-v-81fbb9d6]{max-height:25vh}.document-field .document-field-content[data-v-81fbb9d6] img,.document-field .document-field-content[data-v-81fbb9d6] video,.document-field .document-field-content[data-v-81fbb9d6] figure,.document-field .document-field-content[data-v-81fbb9d6] audio,.document-field .document-field-content[data-v-81fbb9d6] iframe,.document-field .document-field-content[data-v-81fbb9d6] blockquote{max-height:25vh}}.section-attachments[data-v-81fbb9d6]{padding-left:0;padding-right:0}.uploaded-files[data-v-81fbb9d6]{display:flex;flex-flow:wrap;margin-left:-15px;margin-right:-15px}.thumbnail-field .content[data-v-81fbb9d6]{padding:10px;font-size:0.8em}.thumbnail-field img[data-v-81fbb9d6]{height:125px;width:125px}.thumbnail-field .image-placeholder[data-v-81fbb9d6]{position:absolute;margin-left:20px;margin-right:20px;font-size:0.8em;font-weight:bold;z-index:99;text-align:center;color:var(--tainacan-info-color);top:45px;max-width:84px}.related-items-list-heading[data-v-81fbb9d6]{display:flex;align-items:center;justify-content:space-between;margin-left:1.5em;margin-top:10px;margin-bottom:var(--tainacan-container-padding)}.related-items-list-heading p[data-v-81fbb9d6]{color:var(--tainacan-info-color)}@media screen and (max-width: 768px){.related-items-list-heading[data-v-81fbb9d6]{flex-wrap:wrap}}.footer[data-v-81fbb9d6]{padding:14px var(--tainacan-one-column);position:fixed;bottom:0;right:0;z-index:9999;background-color:var(--tainacan-gray1);width:calc(100% - var(--tainacan-sidebar-width, 3.25em));height:60px;display:flex;justify-content:space-between;align-items:center}.footer .form-submission-footer[data-v-81fbb9d6]{width:100%;display:flex;flex-wrap:wrap;justify-content:flex-end}.footer .form-submission-footer .button[data-v-81fbb9d6]{margin-left:16px;margin-right:6px}.footer .form-submission-footer .button.is-outlined[data-v-81fbb9d6]{margin-left:0px;margin-right:auto}.footer .sequence-button[data-v-81fbb9d6]{background-color:transparent;color:var(--tainacan-turquoise5);border:none}.footer .sequence-button .icon[data-v-81fbb9d6]{margin-right:5px !important}.footer .sequence-button[data-v-81fbb9d6]:hover,.footer .sequence-button[data-v-81fbb9d6]:focus,.footer .sequence-button[data-v-81fbb9d6]:active{background-color:transparent !important;color:var(--tainacan-turquoise5) !important}@media screen and (max-width: 769px){.footer[data-v-81fbb9d6]{padding:13px 0.5em;width:100%;flex-wrap:wrap;height:auto;position:fixed}}\n",""]);const c=o},57353:(t,e,a)=>{var n=a(85072),i=a.n(n),l=a(97825),o=a.n(l),c=a(77659),d=a.n(c),s=a(55056),m=a.n(s),r=a(10540),u=a.n(r),b=a(63494),p=a.n(b),f=a(91366),g={};g.styleTagTransform=p(),g.setAttributes=m(),g.insert=d().bind(null,"head"),g.domAPI=o(),g.insertStyleElement=u();i()(f.A,g),f.A&&f.A.locals&&f.A.locals},64997:(t,e,a)=>{a.d(e,{default:()=>l});var n=a(64355),i=a(94130);a(11057);const l=(0,a(66262).A)(i.A,[["render",n.X],["__scopeId","data-v-363112fd"]])},40652:(t,e,a)=>{a.r(e),a.d(e,{default:()=>l});var n=a(19048),i=a(38047);a(26738);const l=(0,a(66262).A)(i.A,[["render",n.X],["__scopeId","data-v-81fbb9d6"]])},38047:(t,e,a)=>{a.d(e,{A:()=>n.A});var n=a(88838)},19048:(t,e,a)=>{a.d(e,{X:()=>n.X});var n=a(95017)},26738:(t,e,a)=>{a(57353)}}]);