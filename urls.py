"""IRMNP URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from mnpapp import views
from rspapp import views as v2
from django.contrib import admin
from django.urls import path, re_path
from django.urls import path, include

from django.contrib.auth import views as auth_views
from rest_framework.authtoken import views as authviews

from django.conf.urls.static import static
from django.conf import settings

from django.views.static import serve






urlpatterns = [
    path('admin/', admin.site.urls),
    path('proposal/', views.proposal, name="proposal"),
    path('dropdowndata/',views.dropdowndata, name="dropdowndata"),
    path('save_records/',views.save_records, name="save_records"),
    path('rateofreturn/',views.rateofreturn, name="rateofreturn"),
    path('save_ror/',views.save_ror, name="save_ror"),
    path('add_justntext/',views.add_justntext, name="add_justntext"),
    path('delete_justntext/',views.delete_justntext, name="delete_justntext"),
    path('get_key/',views.get_key,name='get_key'),
    path('',views.login_user,name="login"),
    path('headqtr/', views.headqtr_view, name='headqtr'),
    path('headqtr1/', views.headqtr_view1, name='headqtr1'),
    path('headqtr2/', views.headqtr_view2, name='headqtrfinance'),
    path('headqtr3/', views.headqtr_view3, name='divwrkshop'),
    path('headqtr4/', views.headqtr_view4, name='headqtr4'),
    path('headqtr5/', views.headqtr_view5, name='headqtr5'),
    path('headqtr6/', views.headqtr_view6, name='headqtr6'),
    path('headqtr7/', views.headqtr_view7, name='headqtr7'),
    path('headqtr8/', views.headqtr_view8, name='headqtr8'),
    path('headqtr9/', views.headqtr_view9, name='headqtr9'),
    path('headqtr10/', views.headqtr_view10, name='headqtr10'),
    #path('homepage/',views.homepage,name='homepage'),

    #<----------chatbot()----------->
    path('api/chatbot/categories/', views.chatbot_categories, name='chatbot_categories'),
    path('api/chatbot/questions/<path:category>/', views.chatbot_questions, name='chatbot_questions'),
    path('api/chatbot/answer/', views.chatbot_answer, name='chatbot_answer'),
    
    path('login/',views.login_user,name="login"),
    path('loginUser/',views.login_user,name="login"),
    path('itemcostdetails/',views.itemcostdetails,name="itemcostdetails"),
    path('generate_pdf/',views.generate_pdf,name="generate_pdf"),
    #rajesh
    path('postmaster/',views.postmaster,name='postmaster'),  
    #department master
    path('submit_department/',views.submit_department, name='submit_department'),
    path('detailss/',views.detailss,name='detailss'),#need to merge with submit_department url 
    path('savehqq/',views.savehqq,name='savehqq'),#need to merge with submit_department url 
    path('able_rlyorgg/',views.able_rlyorgg,name='able_rlyorgg'),#need to merge with submit_department url 
    path('save/', views.save, name='save'),#need to merge with submit_department url 
    path('savee/', views.savee, name='savee'),#need to merge with submit_department url 
    path("deletee/", views.deletee, name="deletee"),#need to merge with submit_department url 
    path("updatedata/", views.updatedata, name="updatedata"),#need to merge with submit_department url 
    #railwaymaster Entries      
    path('railwayMaster/',views.railwayMaster, name='railwayMaster'),
    path('adminuserHome/', views.adminuserHome, name='adminuserHome'),#Need to merge with railwaymaster
    path('admin_changePassword/', views.admin_changePassword, name='admin_changePassword'),#Need to merge with railwaymaster
    path('admin_logout/', views.admin_logout, name='admin_logout'),#Need to merge with railwaymaster
    path('details/', views.details, name='details'),#Need to merge with railwaymaster
    path('getDesigbyDepartment/', views.getDesigbyDepartment, name='getDesigbyDepartment'),#Need to merge with railwaymaster
    path('division_by_rly/', views.division_by_rly, name='division_by_rly'),#Need to merge with railwaymaster
    path('filter/', views.filter, name='filter'),#Need to merge with railwaymaster
    path('fetch_details/', views.fetch_details, name='fetch_details'),#Need to merge with railwaymaster
    path('savehq/', views.savehq, name='savehq'),#Need to merge with railwaymaster
    path('savediv/', views.savediv, name='savediv'),#Need to merge with railwaymaster
    path('able_rlyorg/', views.able_rlyorg, name='able_rlyorg'),#Need to merge with railwaymaster
    path('designation_request/', views.designation_request, name='designation_request'),#Need to merge with railwaymaster
    path('masterTable/', views.masterTable, name='masterTable'),#Need to merge with railwaymaster
    path('roster/', views.roster, name='roster'),#Need to merge with railwaymaster
    path('user_list/', views.user_list, name='user_list'),#Need to merge with railwaymaster
    path('addPostAjax/', views.addPostAjax, name='addPostAjax'),#Need to merge with railwaymaster
    #level_desig
    path('add_designation/',views.add_designation,name='add_designation'),
    
    
    path('logout_request/',views.logout_request, name="logout_request"),

    path('createuser/',views.createuser, name="createuser"),
    # path('getdivision/',views.getdivision, name="getdivision"),
    # path('save_userform/',views.save_userform, name="save_userform"),
    # path('save_userform/',views.save_userform, name="save_Records"),

    # path('createdivision/',views.createdivisions, name="createdivisions"),
    #  path('createusers/',views.createusers, name="createusers"),
 

    # path('checkifexist/',views.checkifexist,name="checkifexist"),
    path('checkifexist1/',views.checkifexist1,name="checkifexist1"),
    # path('checkifexist2/',views.checkifexist2,name="checkifexist2"),
    path('showdivhq/', views.showdivhq, name='showdivhq'),

    
    path('changePassword/',views.changePassword,name="changePassword"),

    path('showdivs/',views.showdivs, name="showdivs"),
    # path('userinfo/',views.user_personalinfo, name="user_personalinfo"),
    # path('fetchUserDataFromMEM/',views.fetchUserDataFromMEM,name='fetchUserDataFromMEM'),  

    # path('editUser/',views.editUser, name="editUser"),
    # path('finAssociate/',views.finAssociate, name="finAssociate"),
   
    path('add_new_item/', views.add_new_item, name='add_new_item'),
    path('add_new_item_pdf/', views.add_new_item_pdf, name='add_new_item_pdf'),
    path('add_new_item_excel/',views.add_new_item_excel,name='add_new_item_excel'),


    path('mysave/',views.mysave, name='mysave'),
    path('updateview/',views.updateview,name='updateview'),
    path('editview/',views.editview,name='editview'),
    path('deleteview/',views.deleteview,name='deleteview'),
    # path('deleteview2/',views.deleteview2,name='deleteview2'),
    path('deleteview3/',views.deleteview3,name='deleteview3'),
    path('viewDetails/', views.viewDetails, name='viewDetails'),
    # path('exportExcel/',views.exportExcel,name='exportExcel'),

   path('monthly_progress/',views.monthly_progress, name='monthly_progress'),
   path('monthly_progress_pdf/',views.monthly_progress_pdf, name='monthly_progress_pdf'),
   path('monthly_progress_excel/',views.monthly_progress_excel, name='monthly_progress_excel'),
   path('vetted/',views.vetted, name='vetted'),
   path('vetting/',views.vetting, name='vetting'),
   path('nonvetted/',views.nonvetted, name='nonvetted'),
   path('nonvetting/',views.nonvetting, name='nonvetting'),
   path('fetch_vetted_by/',views.fetch_vetted_by,name='fetch_vetted_by'),
   path('get_appr_data/',views.get_appr_data,name='get_appr_data'),
   path('fetch_hist_data/',views.fetch_hist_data,name='fetch_hist_data'),
   path('otherremarks/',views.otherremarks,name='otherremarks'),
   path('div_replyhis/',views.div_replyhis,name='div_replyhis'),
   path('fetch_remark/',views.fetch_remark,name='fetch_remark'),  
   path('fetch_reply/',views.fetch_reply,name='fetch_reply'),  
   path('div_replyviw/',views.div_replyviw ,name='div_replyviw'),
   path('div_reply2/',views.div_reply2,name='div_reply2'),
   path('fetch_remark1/',views.fetch_remark1,name='fetch_remark1'),
   path('fetch_reply1/',views.fetch_reply1,name='fetch_reply1'),
   path('procurement_rlyboard/',views.procurement_rlyboard,name='procurement_rlyboard'),
   path('procurement_gmpower/',views.procurement_gmpower,name='procurement_gmpower'),
   path('sanctioned_cost/',views.sanctioned_cost,name='sanctioned_cost'),
   path('board_summary/',views.board_summary,name='board_summary'),

   
   path('hfsave/',views.hfsave, name='hfsave'),
   path('list_of_proposal_finance/',views.list_of_proposal_finance,name='list_of_proposal_finance'),
   path('submitt_proposlHQF/',views.submitt_proposlHQF,name='submitt_proposlHQF'),
   path('approve_HQF/',views.approve_HQF,name='approve_HQF'),
   path('reject_proposal3/',views.reject_proposal3,name='reject_proposal3'),
   path('get_remarks/',views.get_remarks,name='get_remarks'),
   path('get_reject_remarks/',views.get_reject_remarks,name='get_reject_remarks'),
   path('Qsave/',views.Qsave,name='Qsave'),
   path('rmksave/',views.rmksave,name='rmksave'),
   path('add_asset/',views.add_asset,name='add_asset'),
   path('add_asset_pdf/',views.add_asset_pdf,name='add_asset_pdf'),
   path('add_asset_excel/',views.add_asset_excel,name='add_asset_excel'),
   path('editview1/',views.editview1,name='editview1'),
   path('updateview1/',views.updateview1,name='updateview1'),
   path('selectPeriod123/',views.selectPeriod123,name='selectPeriod123'),
   path('covernote/',views.covernote, name="covernote"),
   path('covernote_pdf/',views.covernote_pdf, name="covernote_pdf"),
   path('printtdocuments/',views.printtdocuments, name="printtdocuments"),
   path('print/',views.print1, name="print1"),
   path('save_n_add_pdf/',views.save_n_add_pdf,name='save_n_add_pdf'),  
   path('delete_pdf/',views.delete_pdf,name='delete_pdf'),  
   path('delete_justntext/',views.delete_justntext,name='delete_justntext'),  
   path('add_justntext/',views.add_justntext,name='add_justntext'),  
   path('save_ror/',views.save_ror,name='save_ror'),  
   path('fetch_machineid/',views.fetch_machineid,name='fetch_machineid'),  
   path('rateofreturn/',views.rateofreturn,name='rateofreturn'),  
   path('save_comment/',views.save_comment,name='save_comment'),  
   path('justfnprt2saving/',views.justfnprt2saving,name='justfnprt2saving'),  
   path('save_replacementjustfn/',views.save_replacementjustfn,name='save_replacementjustfn'),  
   path('save_replacement/',views.save_replacement,name='save_replacement'),  
   path('dropdowndata/',views.dropdowndata,name='dropdowndata'),  
   path('save_records/',views.save_records,name='save_records'),  
   path('fetchcofmowdata/',views.fetchcofmowdata,name='fetchcofmowdata'),  
   path('program/',views.program,name='program'),  
   path('deletion/',views.delete,name='deletionofzonalrailway'),
   path('Indent/',views.Indent,name='Indent'),
   path('wip_summary/',views.wip_summary,name='wip_summary'),
   path('zonal_level_proposal/',views.zonal_level_proposal,name='zonal_level_proposal'),
   path('viewprioritylist/',views.viewprioritylist,name='viewprioritylist'),
   path('submission/',views.submission,name='submission'),
   path('sectionsummary/',views.sectionsummary,name='sectionsummary'),
   path('sanctioned_proposal/',views.sanctioned_proposal,name='sanctioned_proposal'),
   path('reply/',views.reply,name='reply'),
   path('proposaljustificationn/',views.proposaljustificationn,name='proposaljustificationn'),
   path('priority_of_proposal/',views.priority_of_proposal,name='priority_of_proposal'),
   path('proposalremarkss/',views.proposalremarkss,name='proposalremarkss'),
   path('proposalstatuss/',views.proposalstatuss,name='proposalstatuss'),
   path('proposalstatustable/',views.proposalstatustable,name='proposalstatustable'),
   path('pinkbookitem/',views.pinkbookitem,name='pinkbookitem'),
   path('viewprioritylist/',views.viewprioritylist,name='viewprioritylist'),
   path('financequery/',views.financequery,name='financequery'),
   path('pinkbookgeneration/',views.pinkbookgeneration,name='pinkbookgeneration'),
   path('pinkbookgeneration2/',views.pinkbookgeneration2,name='pinkbookgeneration2'),
   path('workinprogress/',views.workinprogress,name='workinprogress'),
   path('mech/',views.mech,name='mech'),
   path('finaljustificationform/',views.finaljustificationform,name='finaljustificationform'),
   path('listofcreatedproposal/',views.listofcreatedproposal,name='listofcreatedproposal'),
   path('printtdocuments/',views.printtdocuments,name='printtdocuments'),
   path('Submitted_proposal/',views.Submitted_proposal,name='Submitted_proposal'),
   path('submitted_programm/',views.submitted_programm,name='submitted_programm'),
   path('summaryprop_processedRB/',views.summaryprop_processedRB,name='summaryprop_processedRB'),
   
   path('insert_monthly_progress/',views.insert_monthly_progress,name='insert_monthly_progress'),  
   path('list_of_proposal/',views.list_of_proposal,name="list_of_proposal"),
   path('list_of_proposal_divi_pdf/',views.list_of_proposal_divi_pdf,name="list_of_proposal_divi_pdf"),
   path('cpd/',views.cpd,name="cpd"),
   path('Quantitydetails/',views.Quantitydetails,name="Quantitydetails"),
   path('listofcp/',views.listofcp,name="listofcp"),
   path('RORR/',views.RORR,name="RORR"),
   path('proposaljustification/',views.proposaljustification,name="proposaljustification"),
   path('deleteview1/',views.deleteview1,name='deleteview1'),
   path('add_newitem/',views.add_newitem,name='add_newitem'),
   path('mysave1/',views.mysave1, name='mysave1'),
   path('submit_proposal/',views.submit_proposal, name='submit_proposal'),
   path('submitt_proposal1/',views.submitt_proposal1, name='submitt_proposal1'),  
   path('list_of_proposal_for_edting/',views.list_of_proposal_for_edting,name='list_of_proposal_for_edting'),
   path('list_of_proposal_HQ/',views.list_of_proposal_HQ,name='list_of_proposal_HQ'),  
   path('submit_proposal3/',views.submit_proposal3,name='submit_proposal3'),  
   path('submitt_proposal/',views.submitt_proposal,name='submitt_proposal'),  
   path('submitt_proposal2/',views.submitt_proposal2,name='submitt_proposal2'),  
   path('div_reply/',views.div_reply,name='div_reply'), 
   path('deleteremark/',views.deleteremark,name='deleteremark'), 
   path('fetch_forwd/',views.fetch_forwd,name='fetch_forwd'), 
   path('editremark/',views.editremark,name='editremark'), 
   path('editremark1/',views.editremark1,name='editremark1'), 
   
   #email test
   path('sendmail_otp/',views.sendmail_otp,name='sendmail_otp'),





#    RSP
   path('rspproposal/',v2.rspproposal,name='rspproposal'),
   path('list_of_rsp_proposal/', v2.list_of_rsp_proposal, name='list_of_rsp_proposal'),

path('pdfandexcelgeneration/',views.pdfandexcelgeneration,name='pdfandexcelgeneration'),

   #-----------------------------------urls for user master-------------------------------------


    path('get_hrms/', views.get_hrms, name='get_hrms'),
    path('hrms_emp/',views.hrms_emp, name='hrms_emp'),
    path('fetch_designation/', views.fetch_designation, name='fetch_designation'),
    path('check_hrms/', views.check_hrms, name="check_hrms"),
    path('coordinator_check/', views.coordinator_check, name="coordinator_check"),

    path('createuser/',views.createuser, name="createuser"),
    path('getdivision/',views.getdivision, name="getdivision"),
    path('save_userform/',views.save_userform, name="save_userform"),
    path('checkifexist/',views.checkifexist,name="checkifexist"),
    path('finAssociate/',views.finAssociate, name="finAssociate"),   

    #added new
    path('ajax/creatuser_ajax_function/',views.creatuser_ajax_function, name="creatuser_ajax_function"),


#---------------------------------------------------------------------------------------------

#-----------------------------------urls for user info-------------------------------------

path('userinfo/',views.user_personalinfo, name="user_personalinfo"),
path('editUser/',views.editUser, name="editUser"),
path('fetchUserDataFromMEM/',views.fetchUserDataFromMEM,name='fetchUserDataFromMEM'),
path('get_pincode/',views.get_pincode,name='get_pincode'),
path('editUserinfo/',views.editUserinfo,name='editUserinfo'),
path('check_phone/', views.check_phone, name='check_phone'),
path('check_email/', views.check_email, name='check_email'),


#---------------------------------------------------------------------------------------------

    path('user_preference/', views.user_preference, name = 'user_preference'),

    ###########  added for workflow 24-07-24
    path('create_workflow_status/', views.create_workflow_status, name = 'create_workflow_status'),
    path('create_workflow_type/', views.create_workflow_type, name = 'create_workflow_type'),
    path('create_user_work_assigned/', views.create_user_work_assigned, name = 'create_user_work_assigned'),
    path('create_level_work_assigned/', views.create_level_work_assigned, name = 'create_level_work_assigned'),
    path('workflow_application/', views.workflow_application, name = 'workflow_application'),
    path('workflow_application_call/', views.workflow_application_call, name = 'workflow_application_call'),
    path('workflow_search_desc/', views.workflow_search_desc, name='workflow_search_desc'),
    path('mnp_document_pdf/<int:id>/', views.mnp_document_pdf, name='mnp_document_pdf'), 
    path('workflow_pdf/<int:workflow_id>/', views.workflow_pdf, name='workflow_pdf'),
    path('rsp_document_pdf/<int:id>/', v2.rsp_document_pdf, name='rsp_document_pdf'),

    path('mnp_preview_pdf/', views.mnp_preview_pdf, name='mnp_preview_pdf'), 

    path('mnp_document_pdf_combine/', views.mnp_document_pdf_combine, name='mnp_document_pdf_combine'),
    path('mnp_document_pdf_comparision/', views.mnp_document_pdf_comparision, name='mnp_document_pdf_comparision'),



    path('create_workflow_activity/', views.create_workflow_activity, name = 'create_workflow_activity'), 

    path('mail_server/', views.mail_server, name = 'mail_server'),  
    path('message_search_desc/', views.message_search_desc, name='message_search_desc'),  
    


    path('remove_hrms_id/', views.remove_hrms_id, name = 'remove_hrms_id'),
    path('default_file_movement/', views.default_file_movement, name = 'default_file_movement'),
    
#BULK 
#path('financial_year/', v2.financial_year_view, name='financial_year_view'),
path('proposal_form/', v2.proposal_form_view, name='proposal_form'),
path('biproposals/', v2.biproposals, name='biproposals'),
path('bi_document_pdf/<int:id>/', v2.bi_document_pdf, name='bi_document_pdf'), 

path('add-proposal/', v2.proposal_form_view, name='proposal_form_view'),
path('proposals/<str:financial_year>/<str:proposal_id>/', v2.proposal_data_view, name='proposal_data_view'),
path('save-item-data/', v2.save_item_data, name='save_item_data'),
path('add-item/<str:financial_year>/<str:proposal_id>/', v2.add_item_form_view, name='add_item_form'),
path('save_proposal/', v2.save_proposal, name='save_proposal'),
path('delete_item/<int:item_id>/', v2.delete_item, name='delete_item'),
path('view-item/<int:item_id>/', v2.view_item, name='view_item'),  
path('edit-item/<int:item_id>/', v2.edit_item, name='edit_item'),  
path('bulk-indent-proposals/', v2.bulk_indent_proposals_view, name='bulk_indent_proposals'),
path('delete-proposal/', v2.delete_proposal, name='delete_proposal'),  
path('proposal-form/', v2.proposal_form_view, name='proposal_form_view'),
path('existing-proposal-data/<str:financial_year>/', v2.existing_proposal_data, name='existing_proposal_data'),
path('create-new-proposal/<str:financial_year>/', v2.create_new_proposal, name='create_new_proposal'),

# MISC 
path('misc-bulk-indent-proposals/', v2.misc_bulk_indent_proposals_view, name='misc_bulk_indent_proposals'),
path('misc-proposal-form/', v2.misc_proposal_form_view, name='misc_proposal_form_view'),
path('misc_document_pdf/<int:id>/', v2.misc_document_pdf, name='misc_document_pdf'), 
path('miscproposals/', v2.miscproposals, name='miscproposals'),

path('misc_proposals/<str:financial_year>/<str:proposal_id>/', v2.misc_proposal_data_view, name='misc_proposal_data_view'),
path('misc-add-item/<str:financial_year>/<str:proposal_id>/', v2.misc_add_item_form_view, name='misc_add_item_form'),
path('misc_save_proposal/', v2.misc_save_proposal, name='misc_save_proposal'),
path('misc_delete-proposal/', v2.misc_delete_proposal, name='misc_delete_proposal'), 
path('misc_save-item-data/', v2.misc_save_item_data, name='misc_save_item_data'),
path('misc-view-item/<int:item_id>/', v2.misc_view_item, name='misc_view_item'), 
path('misc-edit-item/<int:item_id>/', v2.misc_edit_item, name='misc_edit_item'),  
path('misc-existing-proposal-data/<str:financial_year>/', v2.misc_existing_proposal_data, name='misc_existing_proposal_data'),
path('misc-create-new-proposal/<str:financial_year>/', v2.misc_create_new_proposal, name='misc_create_new_proposal'),
path('get-categories/', v2.get_categories, name='get_categories'),
path('misc_delete_item/<int:item_id>/', v2.misc_delete_item, name='misc_delete_item'),



path('login_from_icms/', views.login_from_icms, name='login_from_icms'),
path("request_user_mapping/", views.request_user_mapping, name="request_user_mapping"),
path('login_to_icms/', views.login_to_icms, name='login_to_icms'),




]

urlpatterns += static(settings.STATIC_URL, document_root=settings.STATIC_ROOT)
if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)