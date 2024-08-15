"use strict";(self.webpackChunktainacan=self.webpackChunktainacan||[]).push([[9989],{80756:(t,e,a)=>{a.d(e,{A:()=>s});var i=a(40834);function n(t){return n="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},n(t)}function o(t,e){var a=Object.keys(t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);e&&(i=i.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),a.push.apply(a,i)}return a}function l(t){for(var e=1;e<arguments.length;e++){var a=null!=arguments[e]?arguments[e]:{};e%2?o(Object(a),!0).forEach((function(e){r(t,e,a[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(a)):o(Object(a)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(a,e))}))}return t}function r(t,e,a){return(e=function(t){var e=function(t,e){if("object"!=n(t)||!t)return t;var a=t[Symbol.toPrimitive];if(void 0!==a){var i=a.call(t,e||"default");if("object"!=n(i))return i;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===e?String:Number)(t)}(t,"string");return"symbol"==n(e)?e:e+""}(e))in t?Object.defineProperty(t,e,{value:a,enumerable:!0,configurable:!0,writable:!0}):t[e]=a,t}const s={name:"AttachmentsList",components:{FileItem:a(1580).A},props:{item:Object,form:Object,collection:Object,shouldLoadAttachments:Boolean,isEditable:Boolean},emits:["on-delete-attachment"],data:function(){return{attachmentsPage:1,attachmentsPerPage:12,isLoading:!1}},computed:l({},(0,i.L8)("item",{attachments:"getAttachments",totalAttachments:"getTotalAttachments"})),watch:{shouldLoadAttachments:function(){this.loadAttachments()}},created:function(){this.loadAttachments()},methods:l(l({},(0,i.i0)("item",["fetchAttachments"])),{},{onChangeAttachmentsPerPage:function(t){var e=this;t!=this.attachmentsPerPage&&this.$userPrefs.set("attachments_per_page",t).then((function(t){e.attachmentsPerPage=t})).catch((function(){e.$console.log("Error settings user prefs for attachments per page")})),this.attachmentsPerPage=t,this.loadAttachments()},onPageChange:function(t){this.attachmentsPage=t,this.loadAttachments()},getLastAttachmentsNumber:function(){var t=Number(this.attachmentsPerPage*(this.attachmentsPage-1))+Number(this.attachmentsPerPage);return t>this.totalAttachments?this.totalAttachments:t},loadAttachments:function(){var t=this;this.isLoading=!0,this.fetchAttachments({page:this.attachmentsPage,attachmentsPerPage:this.attachmentsPerPage,itemId:this.item.id}).then((function(){t.isLoading=!1})).catch((function(e){t.isLoading=!1,t.$console.error(e)}))},onDeleteAttachment:function(t){this.$emit("on-delete-attachment",t)}})}},18728:(t,e,a)=>{a.d(e,{A:()=>s});var i=a(40834);function n(t){return n="function"==typeof Symbol&&"symbol"==typeof Symbol.iterator?function(t){return typeof t}:function(t){return t&&"function"==typeof Symbol&&t.constructor===Symbol&&t!==Symbol.prototype?"symbol":typeof t},n(t)}function o(t,e){var a=Object.keys(t);if(Object.getOwnPropertySymbols){var i=Object.getOwnPropertySymbols(t);e&&(i=i.filter((function(e){return Object.getOwnPropertyDescriptor(t,e).enumerable}))),a.push.apply(a,i)}return a}function l(t){for(var e=1;e<arguments.length;e++){var a=null!=arguments[e]?arguments[e]:{};e%2?o(Object(a),!0).forEach((function(e){r(t,e,a[e])})):Object.getOwnPropertyDescriptors?Object.defineProperties(t,Object.getOwnPropertyDescriptors(a)):o(Object(a)).forEach((function(e){Object.defineProperty(t,e,Object.getOwnPropertyDescriptor(a,e))}))}return t}function r(t,e,a){return(e=function(t){var e=function(t,e){if("object"!=n(t)||!t)return t;var a=t[Symbol.toPrimitive];if(void 0!==a){var i=a.call(t,e||"default");if("object"!=n(i))return i;throw new TypeError("@@toPrimitive must return a primitive value.")}return("string"===e?String:Number)(t)}(t,"string");return"symbol"==n(e)?e:e+""}(e))in t?Object.defineProperty(t,e,{value:a,enumerable:!0,configurable:!0,writable:!0}):t[e]=a,t}const s={name:"RelatedItemsList",props:{relatedItems:Object,isLoading:Boolean,isEditable:Boolean,itemId:String,collectionId:[String,Number],isMobileScreen:Boolean},data:function(){return{editMetadataId:!1,editItemId:!1,editCollectionId:!1,editItemModal:!1,adminURL:tainacan_plugin.admin_url+"?",isUpdatingRelatedItems:!1}},computed:{relatedItemsArray:function(){return this.relatedItems?Object.values(this.relatedItems).filter((function(t){return t.total_items})):[]},displayLoading:function(){return this.isLoading||this.isUpdatingRelatedItems}},watch:{editItemModal:function(){this.editItemModal?window.addEventListener("message",this.updateReloadItemsAfterModal,!1):(this.editItemId=!1,this.editCollectionId=!1,this.editMetadataId=!1,window.removeEventListener("message",this.updateReloadItemsAfterModal))}},methods:l(l({},(0,i.i0)("item",["fetchOnlyRelatedItems"])),{},{openItemOnNewTab:function(t){if(t&&t.id&&t.collection_id){var e=this.$router.resolve(this.$routerHelper.getItemPath(t.collection_id,t.id));window.open(e.href,"_blank")}},setItemForEdit:function(t,e){this.editItemId=t.id,this.editCollectionId=t.collection_id,this.editMetadataId=e.metadata_id,this.editItemModal=!0},reloadRelatedItems:function(){var t=this;this.isUpdatingRelatedItems=!0,this.fetchOnlyRelatedItems({itemId:this.itemId,contextEdit:!0}).then((function(){return t.isUpdatingRelatedItems=!1})).catch((function(e){t.$console.error(e),t.isUpdatingRelatedItems=!1}))},updateReloadItemsAfterModal:function(t){var e=t[t.message?"message":"data"];"itemEditionMessage"==e.type&&null!==e.item&&(this.editItemModal=!1)}})}},30642:(t,e,a)=>{a.d(e,{X:()=>y});var i=a(6934),n=function(t){return(0,i.Qi)("data-v-35b2d1c1"),t=t(),(0,i.jt)(),t},o={style:{position:"relative"},class:"table-container"},l={key:0,class:"table-wrapper"},r={class:"uploaded-files"},s={key:0,class:"file-attachment-document-tag"},c={key:1,class:"file-item-control"},d=["onClick"],m=[n((function(){return(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-1-25em tainacan-icon-delete"},null,-1)}))],u={key:1},p={class:"section"},h={class:"content has-text-grey has-text-centered"},b=n((function(){return(0,i.Lk)("p",null,[(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-30px tainacan-icon-attachments"})])],-1)})),g={key:0,class:"pagination-area"},f={class:"shown-items"},v={class:"pagination"};function y(t,e,a,n,y,_){var k=(0,i.g2)("b-loading"),I=(0,i.g2)("file-item"),L=(0,i.g2)("b-pagination"),w=(0,i.gN)("tooltip");return(0,i.uX)(),(0,i.CE)("div",null,[(0,i.Lk)("div",o,[(0,i.bF)(k,{modelValue:y.isLoading,"onUpdate:modelValue":e[0]||(e[0]=function(t){return y.isLoading=t}),"is-full-page":!1},null,8,["modelValue"]),t.attachments.length>0?((0,i.uX)(),(0,i.CE)("div",l,[(0,i.Lk)("div",r,[((0,i.uX)(!0),(0,i.CE)(i.FK,null,(0,i.pI)(t.attachments,(function(e,n){return(0,i.uX)(),(0,i.CE)("div",{key:n,class:(0,i.C4)(["file-item-container",{"is-file-document":a.form.document==e.id,"is-file-thumbnail":a.item.thumbnail_id==e.id}])},[a.form.document==e.id?((0,i.uX)(),(0,i.CE)("span",s,(0,i.v_)(a.collection&&a.collection.item_document_label?a.collection.item_document_label:t.$i18n.get("label_document")),1)):(0,i.Q3)("",!0),(0,i.bF)(I,{"show-name":!0,"modal-on-click":!0,file:e},null,8,["file"]),a.isEditable&&a.form.document!=e.id?((0,i.uX)(),(0,i.CE)("span",c,[(0,i.bo)(((0,i.uX)(),(0,i.CE)("a",{class:"icon",onClick:function(t){return _.onDeleteAttachment(e)}},m,8,d)),[[w,{content:t.$i18n.get("delete"),autoHide:!0,placement:"bottom",popperClass:["tainacan-tooltip","tooltip"]}]])])):(0,i.Q3)("",!0)],2)})),128))])])):(0,i.Q3)("",!0),!(t.totalAttachments<=0)&&t.totalAttachments||y.isLoading?(0,i.Q3)("",!0):((0,i.uX)(),(0,i.CE)("div",u,[(0,i.Lk)("section",p,[(0,i.Lk)("div",h,[b,(0,i.Lk)("p",null,(0,i.v_)(t.$i18n.getWithVariables("info_no_%s_on_item_yet",[a.collection&&a.collection.item_attachment_label?a.collection.item_attachment_label:t.$i18n.get("label_attachments")])),1)])])]))]),t.attachments.length>0?((0,i.uX)(),(0,i.CE)("div",g,[(0,i.Lk)("div",f,(0,i.v_)(t.$i18n.getWithVariables("info_showing_%s",[a.collection&&a.collection.item_attachment_label?a.collection.item_attachment_label:t.$i18n.get("label_attachments")])+" "+(y.attachmentsPerPage*(y.attachmentsPage-1)+1)+t.$i18n.get("info_to")+_.getLastAttachmentsNumber()+t.$i18n.get("info_of")+t.totalAttachments+"."),1),(0,i.Lk)("div",v,[(0,i.bF)(L,{modelValue:y.attachmentsPage,"onUpdate:modelValue":e[1]||(e[1]=function(t){return y.attachmentsPage=t}),total:t.totalAttachments,order:"is-centered",size:"is-small","per-page":y.attachmentsPerPage,"aria-next-label":t.$i18n.get("label_next_page"),"aria-previous-label":t.$i18n.get("label_previous_page"),"aria-page-label":t.$i18n.get("label_page"),"aria-current-label":t.$i18n.get("label_current_page"),onChange:_.onPageChange},null,8,["modelValue","total","per-page","aria-next-label","aria-previous-label","aria-page-label","aria-current-label","onChange"])])])):(0,i.Q3)("",!0)])}},84799:(t,e,a)=>{a.d(e,{X:()=>X});var i=a(6934),n=function(t){return(0,i.Qi)("data-v-9c81ee4c"),t=t(),(0,i.jt)(),t},o={class:"table-container"},l={class:"table-wrapper"},r={class:"related-items-list"},s={class:"columns is-vcentered is-multiline"},c={class:"column is-narrow"},d={class:"section-status"},m={class:"field has-addons"},u=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-collection"})],-1)})),p={class:"column is-narrow"},h={class:"section-status"},b={class:"field has-addons"},g=n((function(){return(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon tainacan-icon-metadata"})],-1)})),f={key:0,style:{"margin-left":"auto"},class:"column is-narrow"},v={class:"section-status"},y={class:"field"},_={class:"related-item-group__items-list"},k=["onClick"],I={key:0,class:"icon has-text-gray"},L=["onClick"],w={class:"table-thumb"},A=["onClick"],P=["innerHTML"],x=["label"],O={class:"actions-container"},C=["aria-label","onClick"],E={class:"icon"},$=[n((function(){return(0,i.Lk)("i",{class:"has-text-secondary tainacan-icon tainacan-icon-1-25em tainacan-icon-edit"},null,-1)}))],j=["src"];function X(t,e,a,n,X,S){var M=(0,i.g2)("b-loading"),H=(0,i.g2)("b-button"),R=(0,i.g2)("blur-hash-image"),V=(0,i.g2)("b-modal"),F=(0,i.gN)("tooltip");return(0,i.uX)(),(0,i.CE)("div",null,[(0,i.Lk)("div",o,[(0,i.bF)(M,{modelValue:S.displayLoading,"onUpdate:modelValue":e[0]||(e[0]=function(t){return S.displayLoading=t}),"is-full-page":!1},null,8,["modelValue"]),(0,i.Lk)("div",l,[(0,i.Lk)("div",r,[((0,i.uX)(!0),(0,i.CE)(i.FK,null,(0,i.pI)(S.relatedItemsArray,(function(e,n){return(0,i.uX)(),(0,i.CE)("div",{key:n,class:"related-item-group"},[(0,i.Lk)("div",s,[(0,i.Lk)("div",c,[(0,i.Lk)("div",d,[(0,i.Lk)("div",m,[(0,i.Lk)("span",null,[u,(0,i.eW)(" "+(0,i.v_)(e.collection_name?e.collection_name:""),1)])])])]),(0,i.Lk)("div",p,[(0,i.Lk)("div",h,[(0,i.Lk)("div",b,[(0,i.Lk)("span",null,[g,(0,i.eW)(" "+(0,i.v_)(e.metadata_name?e.metadata_name:""),1)])])])]),e.total_items&&e.total_items>1?((0,i.uX)(),(0,i.CE)("div",f,[(0,i.Lk)("div",v,[(0,i.Lk)("div",y,[(0,i.bF)(H,{class:"button is-secondary",tag:"router-link",to:t.$routerHelper.getCollectionItemsPath(e.collection_id,{metaquery:[{key:e.metadata_id,value:[a.itemId],compare:"IN"}]})},{default:(0,i.k6)((function(){return[(0,i.eW)((0,i.v_)(t.$i18n.getWithVariables("label_view_all_%s_related_items",[e.total_items])),1)]})),_:2},1032,["to"])])])])):(0,i.Q3)("",!0)]),(0,i.Lk)("ul",_,[((0,i.uX)(!0),(0,i.CE)(i.FK,null,(0,i.pI)(e.items,(function(n,o){return(0,i.uX)(),(0,i.CE)("li",{key:o},[(0,i.Lk)("div",{class:"status-cell",onClick:function(t){return S.openItemOnNewTab(n)}},[t.$statusHelper.hasIcon(n.status)?(0,i.bo)(((0,i.uX)(),(0,i.CE)("span",I,[(0,i.Lk)("i",{class:(0,i.C4)(["tainacan-icon tainacan-icon-1em",t.$statusHelper.getIcon(n.status)])},null,2)])),[[F,{content:t.$i18n.get("status_"+n.status),autoHide:!0,placement:"top",popperClass:["tainacan-tooltip","tooltip"]}]]):(0,i.Q3)("",!0)],8,k),(0,i.Lk)("div",{onClick:function(t){return S.openItemOnNewTab(n)}},[(0,i.Lk)("span",w,[(0,i.bF)(R,{width:t.$thumbHelper.getWidth(n.thumbnail,"tainacan-small",40),height:t.$thumbHelper.getHeight(n.thumbnail,"tainacan-small",40),hash:t.$thumbHelper.getBlurhashString(n.thumbnail,"tainacan-small"),src:t.$thumbHelper.getSrc(n.thumbnail,"tainacan-small",n.document_mimetype),alt:n.thumbnail_alt?n.thumbnail_alt:t.$i18n.get("label_thumbnail"),"transition-duration":500},null,8,["width","height","hash","src","alt"])])],8,L),(0,i.Lk)("div",{style:{width:"100%"},onClick:function(t){return S.openItemOnNewTab(n)}},[(0,i.bo)((0,i.Lk)("p",{innerHTML:null!=n.title&&""!=n.title?n.title:"<span class='has-text-gray3 is-italic'>"+t.$i18n.get("label_value_not_provided")+"</span>"},null,8,P),[[F,{delay:{show:500,hide:300},content:null!=n.title&&""!=n.title?n.title:"<span class='has-text-gray3 is-italic'>"+t.$i18n.get("label_value_not_provided")+"</span>",html:!0,autoHide:!1,placement:"top",popperClass:["tainacan-tooltip","tooltip"]}]])],8,A),a.isEditable&&n.current_user_can_edit?((0,i.uX)(),(0,i.CE)("div",{key:0,class:"actions-cell",label:t.$i18n.get("label_actions")},[(0,i.Lk)("div",O,["trash"!=!n.status?((0,i.uX)(),(0,i.CE)("a",{key:0,id:"button-edit","aria-label":t.$i18n.getFrom("items","edit_item"),onClick:(0,i.D$)((function(t){return S.setItemForEdit(n,e)}),["prevent","stop"])},[(0,i.bo)(((0,i.uX)(),(0,i.CE)("span",E,$)),[[F,{delay:{show:500,hide:100},content:t.$i18n.get("edit"),autoHide:!0,placement:"auto",popperClass:["tainacan-tooltip","tooltip"]}]])],8,C)):(0,i.Q3)("",!0)])],8,x)):(0,i.Q3)("",!0)])})),128))])])})),128))]),(0,i.bF)(V,{modelValue:X.editItemModal,"onUpdate:modelValue":e[1]||(e[1]=function(t){return X.editItemModal=t}),width:1200,"custom-class":"tainacan-modal","close-button-aria-label":t.$i18n.get("close"),onAfterLeave:S.reloadRelatedItems},{default:(0,i.k6)((function(){return[(0,i.Lk)("iframe",{width:"100%",style:(0,i.Tr)({height:a.isMobileScreen?"100vh":"85vh"}),src:X.adminURL+"itemEditionMode=true"+(t.$adminOptions.mobileAppMode?"&mobileAppMode=true":"")+"&page=tainacan_admin#"+t.$routerHelper.getItemEditPath(X.editCollectionId,X.editItemId)+"?editingmetadata="+X.editMetadataId},null,12,j)]})),_:1},8,["modelValue","close-button-aria-label","onAfterLeave"])])])])}},74829:(t,e,a)=>{a.d(e,{A:()=>r});var i=a(31601),n=a.n(i),o=a(76314),l=a.n(o)()(n());l.push([t.id,".table-container[data-v-35b2d1c1]{width:100%}.uploaded-files[data-v-35b2d1c1]{display:flex;flex-wrap:wrap}.uploaded-files .file-item-container[data-v-35b2d1c1]{display:inline-block;margin:10px 12px;position:relative}.uploaded-files .file-item-container:hover .file-item-control[data-v-35b2d1c1]{display:block;visibility:visible;opacity:1}.uploaded-files .file-item-container .file-attachment-document-tag[data-v-35b2d1c1]{background-color:var(--tainacan-primary);color:var(--tainacan-secondary);display:block;position:absolute;z-index:9;padding:0.25em 0.5em;font-size:0.6875em;border-radius:3px;bottom:10px;left:4px;font-weight:500;border:1px solid var(--tainacan-secondary);opacity:0.25;transition:opacity 0.2s ease}.uploaded-files .file-item-container:hover .file-attachment-document-tag[data-v-35b2d1c1]{opacity:1.0}.uploaded-files .file-item-container .file-item-control[data-v-35b2d1c1]{position:absolute;background-color:var(--tainacan-gray1);width:94px;margin:6px 0;bottom:0px;padding:2px 8px 4px 8px;text-align:right;display:none;visibility:hidden;opacity:0;transition:opacity ease 0.2s, visibility ease 0.2s, display ease 0.2s}.uploaded-files .file-item-container .file-item-control .icon[data-v-35b2d1c1]{cursor:pointer}@media screen and (max-width: 769px){.table-container[data-v-35b2d1c1]{padding-left:1em;padding-right:1em}.pagination-area[data-v-35b2d1c1]{margin-left:0;margin-right:0;justify-content:center}.uploaded-files[data-v-35b2d1c1]{justify-content:center}.uploaded-files .file-item-container[data-v-35b2d1c1]{margin:5px 7px}}\n",""]);const r=l},41416:(t,e,a)=>{a.d(e,{A:()=>r});var i=a(31601),n=a.n(i),o=a(76314),l=a.n(o)()(n());l.push([t.id,".section-status[data-v-9c81ee4c]{margin-left:-0.875rem;font-size:0.875em}.section-status .field .icon[data-v-9c81ee4c]{font-size:1.125em !important;color:var(--tainacan-info-color)}.related-items-list .related-item-group[data-v-9c81ee4c]:not(:last-child){border-bottom:1px dashed var(--tainacan-gray3);margin-bottom:2rem}.related-items-list .related-item-group .related-item-group__items-list[data-v-9c81ee4c]{list-style:none;padding:0px;margin-bottom:1rem;-moz-column-count:2;-webkit-column-count:2;column-count:2}@media screen and (max-width: 768px){.related-items-list .related-item-group .related-item-group__items-list[data-v-9c81ee4c]{-moz-column-count:1;-webkit-column-count:1;column-count:1}}.related-items-list .related-item-group .related-item-group__items-list li[data-v-9c81ee4c]{display:flex;align-items:center;padding:8px 32px 8px 6px;width:100%;position:relative;overflow-x:hidden}.related-items-list .related-item-group .related-item-group__items-list li[data-v-9c81ee4c]:hover{cursor:pointer;background-color:var(--tainacan-item-hover-background-color)}.related-items-list .related-item-group .related-item-group__items-list li:hover .actions-cell[data-v-9c81ee4c]{opacity:1;visibility:1;right:0}.related-items-list .related-item-group .related-item-group__items-list .actions-cell[data-v-9c81ee4c]{position:absolute;right:-32px;padding:0 6px;min-height:28px;min-width:28px;opacity:0;visibility:0;transition:right 0.3s ease}.related-items-list .related-item-group .related-item-group__items-list .table-thumb[data-v-9c81ee4c]{display:block;min-height:28px;min-width:28px;margin-left:2px;margin-right:8px}\n",""]);const r=l},70826:(t,e,a)=>{var i=a(85072),n=a.n(i),o=a(97825),l=a.n(o),r=a(77659),s=a.n(r),c=a(55056),d=a.n(c),m=a(10540),u=a.n(m),p=a(63494),h=a.n(p),b=a(74829),g={};g.styleTagTransform=h(),g.setAttributes=d(),g.insert=s().bind(null,"head"),g.domAPI=l(),g.insertStyleElement=u();n()(b.A,g),b.A&&b.A.locals&&b.A.locals},92027:(t,e,a)=>{var i=a(85072),n=a.n(i),o=a(97825),l=a.n(o),r=a(77659),s=a.n(r),c=a(55056),d=a.n(c),m=a(10540),u=a.n(m),p=a(63494),h=a.n(p),b=a(41416),g={};g.styleTagTransform=h(),g.setAttributes=d(),g.insert=s().bind(null,"head"),g.domAPI=l(),g.insertStyleElement=u();n()(b.A,g),b.A&&b.A.locals&&b.A.locals},34706:(t,e,a)=>{a.d(e,{A:()=>o});var i=a(48519),n=a(36421);a(85726);const o=(0,a(66262).A)(n.A,[["render",i.X],["__scopeId","data-v-35b2d1c1"]])},84546:(t,e,a)=>{a.d(e,{A:()=>o});var i=a(63814),n=a(7337);a(30988);const o=(0,a(66262).A)(n.A,[["render",i.X],["__scopeId","data-v-9c81ee4c"]])},36421:(t,e,a)=>{a.d(e,{A:()=>i.A});var i=a(80756)},7337:(t,e,a)=>{a.d(e,{A:()=>i.A});var i=a(18728)},48519:(t,e,a)=>{a.d(e,{X:()=>i.X});var i=a(30642)},63814:(t,e,a)=>{a.d(e,{X:()=>i.X});var i=a(84799)},85726:(t,e,a)=>{a(70826)},30988:(t,e,a)=>{a(92027)}}]);