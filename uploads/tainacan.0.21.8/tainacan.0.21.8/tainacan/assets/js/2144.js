"use strict";(self.webpackChunktainacan=self.webpackChunktainacan||[]).push([[2144,9763],{93353:(e,t,a)=>{a.d(t,{A:()=>i});const i={props:{itemMetadatum:Object,value:[String,Number,Array],disabled:!1},emits:["update:value","blur"],data:function(){return{isPreviewingHtml:!1,singleHTMLPreview:""}},methods:{onInput:function(e){this.isPreviewingHtml=!1,this.singleHTMLPreview="",this.$emit("update:value",e)},onBlur:function(){this.$emit("blur")},createElementFromHTML:function(e){var t=document.createElement("div");return t.innerHTML=e.trim(),t},previewHtml:function(){var e=this;if(!this.isPreviewingHtml)if("yes"==this.itemMetadatum.metadatum.multiple){var t=this.createElementFromHTML(this.itemMetadatum.value_as_html),a=Object.values(t.children).filter((function(e){return'<span class="multivalue-separator"> | </span>'!=e.outerHTML})),i=this.itemMetadatum.value.findIndex((function(t){return t==e.value}));i>=0&&(this.singleHTMLPreview=a[i].outerHTML)}else this.singleHTMLPreview=this.itemMetadatum.value_as_html;this.isPreviewingHtml=!this.isPreviewingHtml}}}},8330:(e,t,a)=>{a.d(t,{X:()=>d});var i=a(6934),n={key:0},l={key:0,class:"add-new-term"},r=(0,i.Lk)("span",{class:"icon"},[(0,i.Lk)("i",{class:"tainacan-icon has-text-secondary tainacan-icon-see"})],-1),u={style:{"font-size":"0.75em"}},m=["innerHTML"];function d(e,t,a,d,s,c){var o=(0,i.g2)("b-input");return a.itemMetadatum?((0,i.uX)(),(0,i.CE)("div",n,[(0,i.bF)(o,{id:"tainacan-item-metadatum_id-"+a.itemMetadatum.metadatum.id+(a.itemMetadatum.parent_meta_id?"_parent_meta_id-"+a.itemMetadatum.parent_meta_id:""),disabled:a.disabled,"model-value":a.value,placeholder:a.itemMetadatum.metadatum.placeholder?a.itemMetadatum.metadatum.placeholder:"[link](https://url.com)","onUpdate:modelValue":t[0]||(t[0]=function(e){return c.onInput(e)}),onBlur:c.onBlur},null,8,["id","disabled","model-value","placeholder","onBlur"]),a.itemMetadatum.item.id?((0,i.uX)(),(0,i.CE)("div",l,[a.value?((0,i.uX)(),(0,i.CE)("a",{key:0,class:"add-link",onClick:t[1]||(t[1]=function(){return c.previewHtml&&c.previewHtml.apply(c,arguments)})},[r,(0,i.Lk)("span",u," "+(0,i.v_)(e.$i18n.get("label_preview","tainacan")),1)])):(0,i.Q3)("",!0)])):(0,i.Q3)("",!0),(0,i.bF)(i.eB,{name:"filter-item"},{default:(0,i.k6)((function(){return[s.isPreviewingHtml?((0,i.uX)(),(0,i.CE)("div",{key:0,innerHTML:s.singleHTMLPreview},null,8,m)):(0,i.Q3)("",!0)]})),_:1})])):(0,i.Q3)("",!0)}},39763:(e,t,a)=>{a.r(t),a.d(t,{default:()=>l});var i=a(56099),n=a(95864);const l=(0,a(66262).A)(n.A,[["render",i.X]])},95864:(e,t,a)=>{a.d(t,{A:()=>i.A});var i=a(93353)},56099:(e,t,a)=>{a.d(t,{X:()=>i.X});var i=a(8330)}}]);