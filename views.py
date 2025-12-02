from django.shortcuts import render,reverse
# from .models import MEM_PRSLN
from mnpapp.models import *
from mnpapp import models
from rspapp.models import *
from rspapp import models as modelsrsp
import json
from email import message
from rest_framework.authtoken import views as authviews
from django.db import connection
from django.core.files.storage import FileSystemStorage
from django.shortcuts import render,redirect,HttpResponseRedirect
from django.http import  JsonResponse,HttpResponse
#prity
from django.contrib import messages 
from django.contrib.auth import authenticate, logout,login, update_session_auth_hash
from django.contrib.auth.hashers import make_password
from django.contrib.auth import get_user_model
user = get_user_model() 
user = MEM_usersn
from django.contrib.sessions.models import Session
import datetime
from django.shortcuts import get_object_or_404

from mnpapp.utils import render_to_pdf
from io import BytesIO
from django.template.loader import get_template
from xhtml2pdf import pisa
from random import randint
import os
import base64 
from datetime import timedelta
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from django.db.models.functions import Cast, Concat
from django.db.models import Max, F, IntegerField


from mnpapp.message_center import *

global ekey
BLOCK_SIZE = 32

def sendmail_otp(request):
    user=User.objects.get(username=username)
    
    subject = 'OTP for Warranty Module Login'
    message = f'Hi {user.first_name},your one time password to login into your Warranty Module account is 12345 and it is valid upto 12.12.12.Not to be shared please. Thank you.'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = ['dhanabalan.rajesh@gmail.com', ]            
    send_mail( subject, message, email_from, recipient_list )

# def login_user(request):
#     if request.method == "POST":
#         username = request.POST.get('username')
#         password = request.POST.get('password')
#         user_obj = authenticate(request, MAV_userid=username, password=password)
#         if user_obj is not None:
#             login(request, user_obj)

#             return render(request, 'proposal.html')
#         else:

#             return render(request, 'login.html', {'error': 'Invalid credentials'})

#     return render(request, 'login.html')

# # def getSidebarData(request):
# #     # Fetch sidebar menu data from the database
# #     sidebar_data = []
    
# #     user11 =MEM_usersn.objects.filter(email = request.user).values('user_role')
# #     user_role=user11[0]['user_role']

# #     # Fetch main headings from the databases
# #     main_headings = custom_menu.objects.filter(parent_id=0,role=user_role)
# #     for main_heading in main_headings:
# #         submenu_items =custom_menu.objects.filter(parent_id=main_heading.id)
# #         main_heading_dict = {
# #             'url': main_heading.url,
# #             'menu': main_heading.menu,
# #             'icon': main_heading.icon,
# #             'submenu_items': [{
# #                 'url': submenu_item.url,
# #                 'menu': submenu_item.menu
# #             } for submenu_item in submenu_items]
# #         }
# #         sidebar_data.append(main_heading_dict)

# #     return JsonResponse(sidebar_data, safe=False)   







ekey='MANDPNPDELHIMUGU'
def get_key(request):
    if request.method == 'GET' or request.is_ajax():
        print("OK")
        PASS_KEY = ekey
        print(PASS_KEY)
        return JsonResponse(PASS_KEY, safe=False)
    return JsonResponse({'success': False}, status=404)
# Encryption & Decryption
def encrypt(raw):
    raw = pad(raw.encode(),16)
    key = ekey
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return base64.b64encode(cipher.encrypt(raw))

def decrypt(enc):
    enc = base64.b64decode(enc)
    key = ekey
    cipher = AES.new(key.encode('utf-8'), AES.MODE_ECB)
    return unpad(cipher.decrypt(enc),16)



################  login logout

def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
    else:
        ip = request.META.get('REMOTE_ADDR')
    return ip

def extract_browser_and_os(user_agent_string):
    if not user_agent_string:
        return 'Unknown', 'Unknown'

    browsers = ['Chrome', 'Firefox', 'Safari', 'Edge', 'Opera', 'Internet Explorer']
    operating_systems = ['Windows', 'Macintosh', 'Linux', 'Android', 'iOS']

    browser_name = 'Unknown'
    browser_version = 'Unknown'
    os_name = 'Unknown'

    for browser in browsers:
        if browser in user_agent_string:
            browser_name = browser
            version_index = user_agent_string.find(browser) + len(browser) + 1
            browser_version = user_agent_string[version_index:].split(' ')[0]
            break

    for os in operating_systems:
        if os in user_agent_string:
            # Extract OS name
            os_name = os
            break

    return f'{browser_name} {browser_version}', os_name

def logout_request(request):
    try:
        import datetime
        session_key = request.session.session_key
        login_history.objects.filter(username = request.user,session_key = session_key).update(logout_date_time = datetime.datetime.now())
        logout(request)
        return HttpResponseRedirect('/')
    except Exception as e: 
        try:
            MED_ERORTBLE.objects.create(fun_name="logout",MAV_userid=request.user,MATERORDTLS=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "errorspage.html", {}) 

def login_user(request):
    if request.method == "POST":
        try:
            username = request.POST.get('username')
            password = request.POST.get('password')
            ###FOR DISABLING ENCRYPTION START
            # print("Password--",password)
            # decrypted = decrypt(password) 
            # print("Password--",password)
            # password=decrypted.decode("utf-8", "ignore")  
            ###FOR DISABLING ENCRYPTION END

            user_obj = authenticate(request,  username=username, password=password)

            if user_obj is not None:
                login(request, user_obj)
                a = MEM_usersn.objects.get(MAV_username=username)

                ############  code added to manage session and login history
                session_key = request.session.session_key
                session_mgmt.objects.update_or_create(
                    defaults = {'session_key' : session_key},  
                    username = request.user
                )

                user_agent_string = request.META.get('HTTP_USER_AGENT', 'Unknown')
                browser_details, os_details = extract_browser_and_os(user_agent_string)
                client_ip = get_client_ip(request)
                login_history.objects.create(
                    username = request.user,session_key = session_key,browser_type = browser_details,os_type = os_details,ip_address = client_ip, userlvlcode = request.user.MAV_userlvlcode_id
                )
                

                pref = list(MED_userprsninfo.objects.filter(MAV_userid = a.MAV_userid).values())
                if len(pref) ==0:
                    preference = 'M'
                else:
                    preference = pref[0]['preference']
                request.session["username"] = str(request.user)
                request.session["department"] = a.MAV_deptcode.MACDEPTCODE
                request.session["rly"] = a.MAV_rlycode.rly_unit_code
                request.session["division"] = a.MAV_divcode_id
                request.session["userrole"] = request.user.MAV_userlvlcode_id
                request.session["nav"] = custommenu2(request.user.MAV_userlvlcode_id, request.user.MAV_userid)

                # print(request.user.MAV_userlvlcode_id,request.session["department"],request.session["rly"],request.session["division"],request.session["userrole"],request.session["nav"])
                # if request.user.MAV_userlvlcode_id == '21':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr'))

                #     # return render(request, 'headqtr.html')
                # elif request.user.MAV_userlvlcode_id == '20':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr1'))
                #     # return render(request, 'headqtr.html')
                # elif request.user.MAV_userlvlcode_id == '29':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtrfinance'))
                #     # return render(request, 'headqtrfinance.html')
                # elif request.user.MAV_userlvlcode_id == '11':
                #     # print("OK")
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('divwrkshop'))
                #     # return render(request, 'divwrkshop.html')
                # elif request.user.MAV_userlvlcode_id == '19':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr4'))
                #     # return render(request, 'divfinance.html')
                # elif request.user.MAV_userlvlcode_id == '30':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr5'))

                #     # return render(request, 'superadmin.html')
                # elif request.user.MAV_userlvlcode_id == '39':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr6'))

                #     # return render(request, 'rlyboardfinance.html')
                # elif request.user.MAV_userlvlcode_id == '31':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr7'))

                #     # return render(request, 'rlyboardexecutive.html')
                # elif request.user.MAV_userlvlcode_id == '10':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr8'))

                #     # return render(request, 'divhead.html')
                # elif request.user.MAV_userlvlcode_id == '90':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr9'))

                #     # return render(request, 'guest.html')
                # elif request.user.MAV_userlvlcode_id == '35':
                #     if preference == 'M':
                #         return HttpResponseRedirect(reverse('list_of_proposal'))
                #     elif preference == 'R':
                #         return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
                #     return HttpResponseRedirect(reverse('headqtr10'))

                #     # return render(request, 'rlyboardofficial.html')

                # return render(request, 'superadmin.html')
                
                return redirect('user_personalinfo')
                if request.user.MAV_userlvlcode_id != 1:
                    return render(request, 'superadmin.html')
                return HttpResponseRedirect(reverse('list_of_proposal'))
            
            else:
                messages.error(request,"Invalid credentials...")
                return render(request, 'login.html')
        except:
            messages.error(request,"Please contact Admin")
    return render(request, 'login.html')



#def login_user(request):
#    if request.method == "POST":
#        username = request.POST.get('username')
#        password = request.POST.get('password')
####FOR DISABLING ENCRYPTION START
#        # print("Password--",password)
#        # decrypted = decrypt(password) 
#        # print("Password--",password)
#        # password=decrypted.decode("utf-8", "ignore")  
#        ###FOR DISABLING ENCRYPTION END
#        user_obj = authenticate(request,  username=username, password=password)
#        # user_obj = authenticate(request,  username=username, password=password)
#
#        if user_obj is not None:
#            login(request, user_obj)
#            a=MEM_usersn.objects.get(MAV_username=username)
#            # print(a.MAV_deptcode,a.MAV_rlycode.rly_unit_code)
#            # b=railwayLocationMaster.objects.get(rly_unit_code=a.MAV_rlycode)
#            # c=MEM_DEPTMSTN.objects.get(MACDEPTCODE=a.MAV_deptcode)
#            request.session["username"]=username
#            request.session["userid"]=a.MAV_userid
#            request.session["department"]=a.MAV_deptcode.MACDEPTCODE
#            request.session["rly"]=a.MAV_rlycode.rly_unit_code
#            request.session["division"]=a.MAV_divcode
#            request.session["userrole"]=request.user.MAV_userlvlcode_id
#            request.session["nav"] = custommenu2(request.user.MAV_userlvlcode_id)
#            # print(request.user.MAV_userlvlcode_id,request.session["department"],request.session["rly"],request.session["division"],request.session["userrole"],request.session["nav"])
#            if request.user.MAV_userlvlcode_id == '21':
#                return HttpResponseRedirect(reverse('headqtr'))
#
#                # return render(request, 'headqtr.html')
#            elif request.user.MAV_userlvlcode_id == '20':
#                return HttpResponseRedirect(reverse('headqtr1'))
#                # return render(request, 'headqtr.html')
#            elif request.user.MAV_userlvlcode_id == '29':
#                return HttpResponseRedirect(reverse('headqtrfinance'))
#                # return render(request, 'headqtrfinance.html')
#            elif request.user.MAV_userlvlcode_id == '11':
#                # print("OK")
#                return HttpResponseRedirect(reverse('divwrkshop'))
#                # return render(request, 'divwrkshop.html')
#            elif request.user.MAV_userlvlcode_id == '19':
#                return HttpResponseRedirect(reverse('headqtr4'))
#                # return render(request, 'divfinance.html')
#            elif request.user.MAV_userlvlcode_id == '30':
#                return HttpResponseRedirect(reverse('headqtr5'))
#
#                # return render(request, 'superadmin.html')
#            elif request.user.MAV_userlvlcode_id == '39':
#                return HttpResponseRedirect(reverse('headqtr6'))
#
#                # return render(request, 'rlyboardfinance.html')
#            elif request.user.MAV_userlvlcode_id == '31':
#                return HttpResponseRedirect(reverse('headqtr7'))
#
#                # return render(request, 'rlyboardexecutive.html')
#            elif request.user.MAV_userlvlcode_id == '10':
#                return HttpResponseRedirect(reverse('headqtr8'))
#
#                # return render(request, 'divhead.html')
#            elif request.user.MAV_userlvlcode_id == '90':
#                return HttpResponseRedirect(reverse('headqtr9'))
#
#                # return render(request, 'guest.html')
#            elif request.user.MAV_userlvlcode_id == '35':
#                return HttpResponseRedirect(reverse('headqtr10'))
#
#                # return render(request, 'rlyboardofficial.html')
#
#            return render(request, 'superadmin.html')
#        
#        else:
#            messages.error(request,"Invalid credentials...")
#            return render(request, 'login.html')
#
#    return render(request, 'login.html')



# def login_user(request):
#     if request.method == "POST":
#         username = request.POST.get('username')
#         password = request.POST.get('password')
# ###FOR DISABLING ENCRYPTION START
#         # print("Password--",password)
#         # decrypted = decrypt(password) 
#         # print("Password--",password)
#         # password=decrypted.decode("utf-8", "ignore")  
#         ###FOR DISABLING ENCRYPTION END
#         user_obj = authenticate(request,  username=username, password=password)
#         # user_obj = authenticate(request,  username=username, password=password)

#         if user_obj is not None:
#             login(request, user_obj)
#             a=MEM_usersn.objects.get(MAV_userid=username)
#             # print(a.MAV_deptcode,a.MAV_rlycode.rly_unit_code)
#             # b=railwayLocationMaster.objects.get(rly_unit_code=a.MAV_rlycode)
#             # c=MEM_DEPTMSTN.objects.get(MACDEPTCODE=a.MAV_deptcode)
#             pref = MED_userprsninfo.objects.get(MAV_userid = username)
#             request.session["username"]=username
#             request.session["department"]=a.MAV_deptcode.MACDEPTCODE
#             request.session["rly"]=a.MAV_rlycode.rly_unit_code
#             request.session["division"]=a.MAV_divcode
#             request.session["userrole"]=request.user.MAV_userlvlcode_id
#             request.session["nav"] = custommenu2(request.user.MAV_userlvlcode_id)
#             # print(request.user.MAV_userlvlcode_id,request.session["department"],request.session["rly"],request.session["division"],request.session["userrole"],request.session["nav"])
#             if request.user.MAV_userlvlcode_id == '21':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr'))

#                 # return render(request, 'headqtr.html')
#             elif request.user.MAV_userlvlcode_id == '20':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr1'))
#                 # return render(request, 'headqtr.html')
#             elif request.user.MAV_userlvlcode_id == '29':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtrfinance'))
#                 # return render(request, 'headqtrfinance.html')
#             elif request.user.MAV_userlvlcode_id == '11':
#                 # print("OK")
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('divwrkshop'))
#                 # return render(request, 'divwrkshop.html')
#             elif request.user.MAV_userlvlcode_id == '19':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr4'))
#                 # return render(request, 'divfinance.html')
#             elif request.user.MAV_userlvlcode_id == '30':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr5'))

#                 # return render(request, 'superadmin.html')
#             elif request.user.MAV_userlvlcode_id == '39':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr6'))

#                 # return render(request, 'rlyboardfinance.html')
#             elif request.user.MAV_userlvlcode_id == '31':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr7'))

#                 # return render(request, 'rlyboardexecutive.html')
#             elif request.user.MAV_userlvlcode_id == '10':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr8'))

#                 # return render(request, 'divhead.html')
#             elif request.user.MAV_userlvlcode_id == '90':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr9'))

#                 # return render(request, 'guest.html')
#             elif request.user.MAV_userlvlcode_id == '35':
#                 if pref.preference == 'M':
#                     return HttpResponseRedirect(reverse('list_of_proposal'))
#                 elif pref.preference == 'R':
#                     return HttpResponseRedirect(reverse('list_of_rsp_proposal'))
#                 return HttpResponseRedirect(reverse('headqtr10'))

#                 # return render(request, 'rlyboardofficial.html')

#             return render(request, 'superadmin.html')
        
#         else:
#             messages.error(request,"Invalid credentials...")
#             return render(request, 'login.html')

#     return render(request, 'login.html')




    
def headqtr_view1(request):
    return render(request, 'headqtr1.html')

def headqtr_view(request):
    return render(request, 'headqtr.html')

def headqtr_view2(request):
    return render(request, 'headqtrfinance.html')

def headqtr_view3(request):
    return render(request, 'divwrkshop.html')

def headqtr_view4(request):
    return render(request, 'divwrkshop.html')

def headqtr_view5(request):
    return render(request, 'superadmin.html')

def headqtr_view6(request):
    return render(request, 'rlyboardfinance.html')

def headqtr_view7(request):
    return render(request, 'rlyboardexecutive.html')

def headqtr_view8(request):
    return render(request, 'divhead.html')

def headqtr_view9(request):
    return render(request, 'guest.html')

def headqtr_view10(request):
    return render(request, 'rlyboardofficial.html')

def custommenu2(role , userid):
    menustr = ''
    if MED_userlvls.objects.filter(MAV_userlvlcode = role, MAV_userlvlname__startswith = 'Admin').exists():
        roles = ['00']
    elif MED_userlvls.objects.filter(MAV_userlvlcode = role, admin_flag = True).exists():
        roles = ['00','0']
    else:
        roles = ['0']
    
    if MEM_usersn.objects.filter(MAV_userid = userid, admin_flag = True).exists():
        if '00' not in roles:
            roles.append('00')

    for role in roles:
        navmenu = custom_menu.objects.filter(role=role).all().order_by('m_id')
        for menu in navmenu:
            if menu.perent_id == 0:
                menustr += "<li><div class='iocn-link'><a href='{}'><i style='font-size:24px;' class='{}'></i><span class='link_name'>{}</span></a><i class='bx bxs-chevron-down arrow'></i></div>".format(
                    menu.url or "", menu.icons or "", menu.menu or ""
                )

                pid = menu.m_id
                sb1 = custom_menu.objects.filter(role=role, m_id=pid).values('menu')
                menuname2 = sb1[0]['menu']
                substr = submenu2(navmenu, pid, menuname2, role)
                menustr += substr
                menustr += "</li>"
            
    return menustr

def submenu2(menubar,sid,menuname2,role):
    menustr=""
    sb=custom_menu.objects.filter(role=role,perent_id=sid).all().order_by('m_id')
    if len(sb)>0:   
        menustr="<ul class='sub-menu'><li><a class='link_name' href='#'>"+menuname2+"</a></li>"
        for menu in menubar: 
            if menu.perent_id == sid :     
                if menustr is None:
                    menustr=""   
                
                else:
                    menustr+="<li><a href="+menu.url+">"+menu.menu+"</a></li>"
                    # menustr += "<li><a href="
                    # if menu.url is not None:
                    #     menustr += str(menu.url)
                    # menustr += ">"
                    # if menu.menu is not None:
                    #     menustr += str(menu.menu)
                    # menustr += "</a></li>"

                pid=menu.m_id
                substr=submenu2(menubar,pid,menuname2,role)
                menustr+=substr 
                menustr+="</li>"      
        menustr+="</ul>"
    return menustr



# def user_personalinfo(request):
#     if request.method == 'POST':
#         print('userinfo')
#         user
#         userid = request.POST.get('userid')
#         password = request.POST.get('password')
#         designation = request.POST.get('desig')
#         fname = request.POST.get('fname')
#         mname = request.POST.get('mname')
#         lname = request.POST.get('lname')
#         offname = request.POST.get('offname')
#         roomno = request.POST.get('roomno')
#         city = request.POST.get('city')
#         state = request.POST.get('state')
#         offdph = request.POST.get('offdph')
#         offpph = request.POST.get('offpph')
#         rlyoffph = request.POST.get('rlyoffph')
#         mobno = request.POST.get('mobno')
#         email = request.POST.get('email')
#         fax = request.POST.get('fax')
#         offpincode = request.POST.get('offpincode')
#         rlyresph = request.POST.get('rlyresph')
#         if MEM_usersn.objects.filter(MAV_userid =userid).exists():
#             print('yes')
#             MEM_usersn.objects.filter(MAV_userid = userid).update(MAV_mail = email,MAV_ph = mobno)
#             print('Usersn Table Updated-----')
        
#         if MED_userprsninfo.objects.filter(MAV_userid_id = userid).exists():
#             MED_userprsninfo.objects.filter(MAV_userid_id = userid).update(MAV_offaddr1 = offname,MAV_offaddr2=roomno,MAV_offaddr3=city,MAV_mail=email,MAV_mobno=mobno,MAV_wrkphno1=offdph,MAV_wrkphno2=offpph,MAV_wrkphno3=rlyoffph,MAV_faxno=fax,MAV_offpin=offpincode,MAV_offpaph=rlyresph,MAV_offaddr4=state)
#             print('Personal User Information Updated')
#         else:
#             userObj1 = MED_userprsninfo.objects.create(MAV_userid_id=userid, MAV_offaddr1=offname, MAV_offaddr2=roomno, MAV_offaddr3=city, MAV_offaddr4=state, MAV_wrkphno1=offdph, MAV_wrkphno2=offpph, MAV_wrkphno3=rlyoffph,
#                                                    MAV_mobno=mobno, MAV_mail=email, MAV_faxno=fax, MAV_offpin=offpincode, MAV_offpaph=rlyresph)
            
#             userObj1.save()
#             print('Personal User Information Created')

#         # userObj1 = MED_userprsninfo.objects.create(MAV_userid=userid, MAV_offaddr1=offname, MAV_offaddr2=roomno, MAV_offaddr3=city, MAV_offaddr4=state, MAV_wrkphno1=offdph, MAV_wrkphno2=offpph, MAV_wrkphno3=rlyoffph,
#         #                                            MAV_mobno=mobno, MAV_mail=email, MAV_faxno=fax, MAV_offpin=offpincode, MAV_offpaph=rlyresph)
#         # userObj1.save()

#         # Update object in usersn table if it exists
#         try:
#             usersnObj = MEM_usersn.objects.get(MAV_userid=userid)
#             usersnObj.MAV_userdesig = designation
#             usersnObj.MAV_fname = fname
#             usersnObj.Mav_mname = mname
#             usersnObj.Mav_lname = lname
#             usersnObj.MAV_mail = email
#             usersnObj.MAV_ph = mobno

#             if password:
#                 hashed_password = make_password(password)
#                 usersnObj.MAV_userpass = hashed_password

#             usersnObj.save()
#         except MEM_usersn.DoesNotExist:
           
#             pass

#         desig = Level_Desig.objects.values('designation').order_by('designation')
#         state = MED_stat.objects.all().order_by('-id')
#         context = {
#             'desig': desig,
#             'state': state,
#         }

#         return render(request, 'user_personalinfo.html', context)

#     elif request.method == 'GET':

#         print(request.user)
#         current_user = request.user
#         obj2 = MEM_usersn.objects.filter(MAV_userid=current_user).values(
#         "MAV_userid",
#         "MAV_userdesig",
#         "MAV_fname",
#         "Mav_mname",
#         "Mav_lname",
        
#     )[0]
        
#         current_user1 = request.user
#         obj3 = MED_userprsninfo.objects.filter(MAV_userid_id=current_user1).values(
#         "MAV_offaddr1",
#         "MAV_offaddr2",
#         "MAV_offaddr3",
#         "MAV_wrkphno1",
#         "MAV_wrkphno2",
#         "MAV_wrkphno3",
#         "MAV_mobno",
#         "MAV_mail",
#         "MAV_faxno",
#         "MAV_offpin",
#     )[0]
         
#         desig = Level_Desig.objects.values('designation').order_by('designation')
#         state = MED_stat.objects.all().order_by('-id')
#         context = {
#             'desig': desig,
#             'state': state,
#             'obj2': obj2,
#             'obj3': obj3,

#         }

#         return render(request, 'user_personalinfo.html', context)

#     return HttpResponse("Invalid request")




#divisionRB
def showdivs(request):
    if request.method == 'POST':
        divisioncode = request.POST.get('divisioncode')
        divisionname = request.POST.get('divisionname')
        divisionhead = request.POST.get('divisionhead')
        location = request.POST.get('location')
        state = request.POST.get('state')
        rail = request.POST.get('rail')
        print('kkkkkkkkk',divisioncode)
        if MED_dvsnmstn.objects.filter(MAV_dvsncode=divisioncode).exists():
            obj = list(MED_dvsnmstn.objects.filter(MAV_dvsncode=divisioncode).values())
            return JsonResponse({'obj':obj})

        else:
            MED_dvsnmstn.objects.create(MAV_dvsncode=divisioncode, MAV_dvsnname=divisionname, MAV_dvsnhead=divisionhead, MAV_locname=location, MAV_stt=state,MAV_railcode_id=rail)
            return JsonResponse({'success':'saved successfully'})
            return render(request,'showdivs.html')
       
    obj = MED_dvsnmstn.objects.values('MAV_dvsncode','MAV_dvsnname','MAV_dvsnhead','MAV_locname','MAV_stt','MAV_railcode')
    state =  MED_stat.objects.all().order_by('-id')
    location = station_master.objects.values('station_name').distinct().order_by('station_name')
    userid = request.user
    print(userid)
    divname =MED_dvsnmstn.objects.values('MAV_dvsnhead').distinct().order_by('MAV_dvsnhead')
    railway = list(railwayLocationMaster.objects.filter(location_type_desc__in=['HEAD QUATER', 'RAILWAY BOARD', 'RDSO', 'PRODUCTION UNIT', 'OFFICE', 'PSU']).values('location_code', 'rly_unit_code'))
    obj1 = MED_dvsnmstn.objects.values('MAV_dvsncode','MAV_dvsnname','MAV_dvsnhead','MAV_locname','MAV_stt','MAV_railcode_id__location_code')

    context={
        'state':state,
        'location':location,
        'obj':obj,
        'obj1':obj1,
        'railway':railway,
        'divname':divname,
     }
    return render(request,'showdivs.html',context)

  


#def changePassword(request):
#    if request.method == "POST":
#        current_password = request.POST.get('oldPassword').strip()
#        new_password = request.POST.get('newPassword').strip()
#        confirm_password = request.POST.get('confirmNewPassword').strip()
#
#        if new_password != confirm_password:
#            return render(request, 'changePassword.html', {'error': 'New passwords do not match.'})
#
#        user = request.user
#        if user.check_password(current_password):
#            user.set_password(new_password)
#            user.save()
#            update_session_auth_hash(request, user)  
#            messages.success(request,"Password changed successfully...")
#            return render(request, 'changePassword.html')
#        else:
#            messages.error(request,"Incorrect current password...")
#            return render(request, 'changePassword.html')
#
#    return render(request, 'changePassword.html')


#vivek

def proposal(request):
    cuser=request.session['username'] 
    a = railwayLocationMaster.objects.get(rly_unit_code=request.session['rly'])
    context={}
    rly = a.location_code
    division , railway = find_div_railway(request.user.MAV_rlycode_id)
    
    b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=request.session['department'])
    dept=b.MAVDEPTNAME
    udets=MEM_usersn.objects.get(MAV_username=cuser)

    ### M&P PROPOASL type id = 1
    type_id = 1
    permission = list(workflow_user_power.objects.filter(user_flag = type_id, for_user = request.user.MAV_userid).values())
    if len(permission) == 0:
        try:
            user_lvl = request.user.MAV_userlvlcode.MAV_userlvlcode
        except:
            user_lvl = 90
        permission = list(MED_userlvls.objects.filter(delete_flag = False, MAV_userlvlcode = user_lvl).values())

    if request.method == "GET" and request.is_ajax():
        op=request.GET.get('op')
        if op == "fetchcofmowdata":
            val=request.GET.get('val')
            data=list(MEM_ITEMDTLN.objects.filter(MAV_ITEMDETWDE__icontains=val).values('MAV_ITEMDETWDE','MAV_ITEMDESC','MAV_MDESC1','MAV_CPCT1','MAV_CPCT2','MAD_COST2324','MAV_SPFNNO2324'))
            # data=list(MEM_ITEMDTLN.objects.filter(MAV_ITEMDETWDE__icontains=val).values('MAV_ITEMDETWDE','MAV_ITEMDESC','MAV_OFCR','MAV_MDESC1','MAV_MDESC2','MAV_CPCT1','MAV_CPCT2','MAD_COST2223','MAD_COST2223','MAV_SPFNNO2324'))
            print(data)
            return JsonResponse(data,safe=False)
        elif op == "deletepdf":
            entry_id = request.GET.get('id')
            if MED_PRSLUPLDFILE_DRAFT.objects.filter(id=entry_id).exists():
                file_name = list(MED_PRSLUPLDFILE_DRAFT.objects.filter(id=entry_id).values('MAVORGPDFNAME'))[0]['MAVORGPDFNAME']
                MED_PRSLUPLDFILE_DRAFT.objects.filter(id=entry_id).delete()
                up_relative_path = f'media/{file_name}'
                file_path = os.path.abspath(up_relative_path)
                if os.path.exists(file_path):
                    os.remove(file_path)
            return JsonResponse({'status': True})
        elif op == "editproposal":
            id = request.GET.get('id')
            print("ididididid",id)
            # Delete the entry from the screen data (not the database)
            # You can replace "ModelName" with the appropriate model name for the table
            # and "pk_field" with the appropriate primary key field name
            # ModelName.objects.filter(pk=entry_id).delete()
            data=list(MEM_PRSLN_DRAFT.objects.filter(ID=id).values())
            print("data---",data)            
            return JsonResponse (data, safe = False)
        elif op == "savereplacement":
            pk= request.GET.get('pk')
            type= request.GET.get('type')
            catg= request.GET.get('catg')
            localplantno= request.GET.get('localplantno')
            yofpurch= request.GET.get('yofpurch')
            descr= request.GET.get('descr')
            costrs= request.GET.get('costrs')
            explife= request.GET.get('explife')
            catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = catg)
            catgg=catg_id.MAV_ITEM_CODE
            catggg=catg_id.MAV_ITEM_NAME

            if type=='D':
                
                if MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk).update(MAVASSTCODE=catgg,MAIYEARPURC=int(yofpurch),MAVITEMCODE=localplantno,MAVDESC=descr,MAICOST=int(costrs),MAIEXPLIFE=int(explife))
                else:
                    MED_ASSTRGNN_DRAFT.objects.create(MAVPRSLNO=pk,MAVASSTCODE=catgg,MAIYEARPURC=int(yofpurch),MAVITEMCODE=localplantno,MAVDESC=descr,MAICOST=int(costrs),MAIEXPLIFE=int(explife))
                data1 = list(MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk).values('MAVPRSLNO','MAVASSTCODE','MAVCAT','MAIYEARPURC','MAVDESC','MAICOST','MAIEXPLIFE','MAVITEMCODE'))
            elif type=='M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO=pk).values())
                if MED_ASSTRGNN.objects.filter(MAVPRSLNO=pk).exists():
                    MED_ASSTRGNN.objects.filter(MAVPRSLNO=pk).update(MAVASSTCODE=catgg,MAVCAT=catggg,MAIYEARPURC=int(yofpurch),MAVITEMCODE=localplantno,MAVDESC=descr,MAICOST=int(costrs),MAIEXPLIFE=int(explife))
                else:
                    MED_ASSTRGNN.objects.create(MAVPRSLNO=pk,MAVASSTCODE=catgg,MAVCAT=catggg,MAIYEARPURC=int(yofpurch),MAVITEMCODE=localplantno,MAVDESC=descr,MAICOST=int(costrs),MAIEXPLIFE=int(explife))
                
                prev_data = prev_data[0]
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                        pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                    
                latest_data = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO=pk).values())
                if len(latest_data):
                    latest_data = latest_data[0]
                    different_values = {key: (prev_data[key], latest_data[key]) 
                                for key in prev_data 
                                if key in latest_data and prev_data[key] != latest_data[key]}
                    
                    if len(different_values) > 0:
                        different = {}
                        different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                        different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                        different_values = convert_decimals_to_strings(different_values)
                        different['changed_data'] = different_values
                        obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                        if isinstance(obj.prslreplacement_data, list):
                            obj.prslreplacement_data.append(different)
                        else:
                            obj.prslreplacement_data = [different]
                        obj.save()

                data1 = list(MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk).values('MAVPRSLNO','MAVASSTCODE','MAVCAT','MAIYEARPURC','MAVDESC','MAICOST','MAIEXPLIFE','MAVITEMCODE'))
                
            else:
                data1=[]
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            context = {'data1':data1}
            return JsonResponse(context,safe=False)
        elif op == "replacementjusti":
            pk= request.GET.get('pk')
            type= request.GET.get('type')
            shiftmchn= request.GET.get('shiftmchn')
            jobloaded= request.GET.get('jobloaded')
            wrkload= request.GET.get('wrkload')
            simmchn= request.GET.get('simmchn')
            cpctsrtfall= request.GET.get('cpctsrtfall')
            breakdown= request.GET.get('breakdown')
            perbreakdown= request.GET.get('perbreakdown')
            accuracyrequirement= request.GET.get('accuracyrequirement')
            actlcpct= request.GET.get('actlcpct')
            if type=='D':
                if MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk).update(MANSIFTNO=int(shiftmchn),MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall,MAVBREKDWNFRQN=breakdown,MAVBREKDWNVLUE=perbreakdown,MAVACCRRQRM=accuracyrequirement,MAACTLCAPB=actlcpct)
                else:
                    MED_PRSLRPLCDTLS_DRAFT.objects.create(MAVPRSLNO=pk,MANSIFTNO=int(shiftmchn),MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall,MAVBREKDWNFRQN=breakdown,MAVBREKDWNVLUE=perbreakdown,MAVACCRRQRM=accuracyrequirement,MAACTLCAPB=actlcpct)
            elif type=='M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).values())

                if MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).update(MANSIFTNO=int(shiftmchn),MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall,MAVBREKDWNFRQN=breakdown,MAVBREKDWNVLUE=perbreakdown,MAVACCRRQRM=accuracyrequirement,MAACTLCAPB=actlcpct)
                else:
                    MED_PRSLRPLCDTLS.objects.create(MAVPRSLNO=pk,MANSIFTNO=int(shiftmchn),MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall,MAVBREKDWNFRQN=breakdown,MAVBREKDWNVLUE=perbreakdown,MAVACCRRQRM=accuracyrequirement,MAACTLCAPB=actlcpct)
                prev_data = prev_data[0]
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                        pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                    
                latest_data = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).values())
            
                if len(latest_data):
                    latest_data = latest_data[0]
                    different_values = {key: (prev_data[key], latest_data[key]) 
                                for key in prev_data 
                                if key in latest_data and prev_data[key] != latest_data[key]}
                    
                    if len(different_values) > 0:
                        different = {}
                        different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                        different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                        different_values = convert_decimals_to_strings(different_values)
                        different['changed_data'] = different_values
                        obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                        if isinstance(obj.prslrepjust_data, list):
                            obj.prslrepjust_data.append(different)
                        else:
                            obj.prslrepjust_data = [different]
                        obj.save()

            else:
                pass
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse({"msg":"data saved successfully"},safe=False)
        elif op == "deljutification":
            entry_id = request.GET.get('id')
            if MED_PRSLJSTN_DRAFT.objects.filter(pk=entry_id).exists():
                MED_PRSLJSTN_DRAFT.objects.filter(pk=entry_id).update(DLTFLAG=True)
            return JsonResponse({'status': True})
        elif op == "savecost":
            code_i = request.GET.get('code')
            pro= request.GET.get('pro')
            dept=request.GET.get('dept')
            cat=request.GET.get('cat')
            pa=request.GET.get('pa')
            desc=request.GET.get('des')
            sdesc=request.GET.get('sdesc')
            bcost=request.GET.get('bcost')
            tuc=request.GET.get('tuc')
            qty=request.GET.get('qty')
            tcost=request.GET.get('tcost')
            locn=request.GET.get('locn')
            cnse=request.GET.get('cnse')
            check1=request.GET.get('check1')
            check2=request.GET.get('check2')
            primaryKey=request.GET.get('primarykey')
            type = request.GET.get('type')
            x=json.loads(request.GET.get('main_arr'))
            if type=='D':
                code = list(MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = primaryKey).values_list('MANCPCODE', flat=True))
                for i in range(len(x)):
                    xa=x[i]['code']
                    xb=x[i]['data1']
                    xc=x[i]['data2']   
                    if MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = primaryKey, MANCPCODE=xa).exists():  
                        MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = primaryKey, MANCPCODE=xa).update(MANCPAMNT=xb,MANCPPER=xc) 
                        if int(xa) in code:
                            code.remove(int(xa))
                    else:
                        MED_PRSLCOST_DRAFT.objects.create(MANPRSNNO=primaryKey,MANCPCODE=xa,MANCPAMNT=xb,MANCPPER=xc) 
                        if int(xa) in code:
                            code.remove(int(xa))
                
                if len(code):
                    MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = primaryKey, MANCPCODE__in = code ).delete()
                
                MEM_PRSLN_DRAFT.objects.filter(MAVPRSLNO=primaryKey).update(MAVALCNCODE_id=pro,MAVDEPTCODE=dept,
                                                                            MAVITEMCODE=code_i,MANCOST=tuc,MAVPRCHFROM=pa,MAVDESC=desc,
                                                                            MAVSHRTDESC=sdesc,MANBASCCOST=bcost,MANQTY=qty,
                                                                            MANTTLCOST=tcost,MAVLOCN=locn,MAVCNSN=cnse,MAVGMSANC=check1,
                                                                            MAVDRMSANC=check2,MAVCATCODE=cat)       

                context = {
                    'msg':'Cost Data saved Successfully...',
                    'id':primaryKey
                } 
            elif type == 'M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = primaryKey).values('MANCPCODE','MANCPAMNT','MANCPPER'))
                code = list(MED_PRSLCOST.objects.filter(MANPRSNNO = primaryKey).values_list('MANCPCODE', flat=True))
                for i in range(len(x)):
                    xa=x[i]['code']
                    xb=x[i]['data1']
                    xc=x[i]['data2']   
                    if MED_PRSLCOST.objects.filter(MANPRSNNO = primaryKey, MANCPCODE=xa).exists():  
                        MED_PRSLCOST.objects.filter(MANPRSNNO = primaryKey, MANCPCODE=xa).update(MANCPAMNT=xb,MANCPPER=xc) 
                        if int(xa) in code:
                            code.remove(int(xa))
                    else:
                        MED_PRSLCOST.objects.create(MANPRSNNO=primaryKey,MANCPCODE=xa,MANCPAMNT=xb,MANCPPER=xc) 
                        if int(xa) in code:
                            code.remove(int(xa))
                if len(code):
                    MED_PRSLCOST.objects.filter(MANPRSNNO = primaryKey, MANCPCODE__in = code ).delete()
                
                latest_cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = primaryKey).values('MANCPCODE','MANCPAMNT','MANCPPER'))
                dict1 = {item['MANCPCODE']: item for item in prev_cost}
                dict2 = {item['MANCPCODE']: item for item in latest_cost}
                differences = []
                all_keys = set(dict1.keys()).union(dict2.keys())
                for key in all_keys:
                    entry1 = dict1.get(key)
                    entry2 = dict2.get(key)
                    
                    if entry1 and entry2:
                        for k in set(entry1.keys()).union(entry2.keys()):
                            val1 = entry1.get(k)
                            val2 = entry2.get(k)
                            if val1 != val2:
                                differences.append({
                                    'MANCPCODE': key,
                                    'field': k,
                                    'prev': val1,
                                    'present': val2
                                })
                    elif entry1:
                        for k in entry1.keys():
                            differences.append({
                                'MANCPCODE': key,
                                'field': k,
                                'prev': entry1.get(k),
                                'present': None
                            })
                    elif entry2:
                        for k in entry2.keys():
                            differences.append({
                                'MANCPCODE': key,
                                'field': k,
                                'prev': None,
                                'present': entry2.get(k)
                            })

                pk = primaryKey
                prev_data = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())

                MEM_PRSLN.objects.filter(MAVPRSLNO=primaryKey).update(MAVALCNCODE_id=pro,MAVDEPTCODE=dept,
                                                                            MAVITEMCODE=code_i,MANCOST=tuc,MAVPRCHFROM=pa,MAVDESC=desc,
                                                                            MAVSHRTDESC=sdesc,MANBASCCOST=bcost,MANQTY=qty,
                                                                            MANTTLCOST=tcost,MAVLOCN=locn,MAVCNSN=cnse,MAVGMSANC=check1,
                                                                            MAVDRMSANC=check2,MAVCATCODE=cat)   
                
                prev_data = prev_data[0]
                version = prev_data['version'] - 1 

                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                    prev_data['version'] = version
                
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                
                if len(differences):
                    different = {}
                    different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                    different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                    different['changed_data'] = differences
                    print(different)
                    obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                    if isinstance(obj.prslcost_data, list):
                        obj.prslcost_data.append(different)
                    else:
                        obj.prslcost_data = [different]
                    obj.save()

                latest_data = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())
                if len(latest_data):
                    latest_data = latest_data[0]
                    del latest_data['version']
                    del prev_data['version']
                    different_values = {key: (prev_data[key], latest_data[key]) 
                                for key in prev_data 
                                if key in latest_data and prev_data[key] != latest_data[key]}
                    
                    if len(different_values) > 0:
                        different = {}
                        different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                        different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                        different_values = convert_decimals_to_strings(different_values)
                        different['changed_data'] = different_values
                        obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                        if isinstance(obj.prsln_data, list):
                            obj.prsln_data.append(different)
                        else:
                            obj.prsln_data = [different]
                        obj.save()


                    

                context = {
                    'msg':'Cost Data saved Successfully...',
                    'id':primaryKey
                }       
            else:
                context = {
                    'msg':'Something Went Wrong, Contact Admin.',
                    'id':primaryKey
                }
            data="1"
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(primaryKey)).exists():
                    initiate_mnp_draft(primaryKey)
            return JsonResponse(context,safe=False)
        elif op == "rorjustsave":
            pk= request.GET.get('pk')
            type= request.GET.get('type')
            jobloaded= request.GET.get('jobloaded')
            wrkload= request.GET.get('wrkload')
            simmchn= request.GET.get('simmchn')
            cpctsrtfall= request.GET.get('cpctsrtfall')
            msg="data saved successfully"
            if type == "D":
                if not MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRPLCDTLS_DRAFT.objects.create(MAVPRSLNO=pk,MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall)
                else:
                    MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk).update(MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall)
            
            elif type == "M":
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).values())

                if not MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRPLCDTLS.objects.create(MAVPRSLNO=pk,MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall)
                else:
                    MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).update(MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall)
                prev_data = prev_data[0]
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                        pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                    
                latest_data = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=pk).values())
            
                if len(latest_data):
                    latest_data = latest_data[0]
                    different_values = {key: (prev_data[key], latest_data[key]) 
                                for key in prev_data 
                                if key in latest_data and prev_data[key] != latest_data[key]}
                    
                    if len(different_values) > 0:
                        different = {}
                        different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                        different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                        different_values = convert_decimals_to_strings(different_values)
                        different['changed_data'] = different_values
                        obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                        if isinstance(obj.prslrepjust_data, list):
                            obj.prslrepjust_data.append(different)
                        else:
                            obj.prslrepjust_data = [different]
                        obj.save()
   

            else:
                pass
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse({"msg":msg},safe=False)
        elif op == "fetchcofmowdataname":
            val=request.GET.get('val')
            data=list(MEM_ITEMDTLN.objects.filter(MAV_ITEMDESC__icontains=val).values('MAV_ITEMDETWDE','MAV_ITEMDESC','MAV_MDESC1','MAV_CPCT1','MAV_CPCT2','MAD_COST2324','MAV_SPFNNO2324'))
            return JsonResponse(data,safe=False)
        elif op == "fetchcofmowdataspec":
            val=request.GET.get('val')
            data=list(MEM_ITEMDTLN.objects.filter(MAV_SPFNNO__icontains=val).values('MAV_ITEMDETWDE','MAV_ITEMDESC','MAV_OFCR','MAV_MDESC1','MAV_MDESC2','MAV_CPCT1','MAV_CPCT2','MAD_COST2223','MAD_COST2223','MAV_SPFNNO2324'))
            return JsonResponse(data,safe=False)
        elif op == "takemachinedetails":
            val=request.GET.get('fname')
            rep=request.GET.get('rep')
            data=list(MEM_ITEMDTLN.objects.filter(MAV_ITEMDETWDE=val).values('MAV_ITEMDETWDE','MAV_ITEMDESC','MAV_OFCR','MAV_MDESC1','MAV_MDESC2','MAV_CPCT1','MAV_CPCT2','MAD_COST2223','MAD_COST2223','MAV_SPFNNO2324'))
            a=[]
            if rep=='R':
                a=list(MED_ASSTRGNN.objects.filter(MAV_COFCODE=data[0]['MAV_ITEMDETWDE'],MAVDEPTCODE_id=udets.MAV_deptcode_id,MAVDVSNCODE=udets.MAV_divcode).values())
            dat={'data':data,'asset':a}
            print(a)
            return JsonResponse(dat,safe=False)
        elif op == "fetchirepsdata":
            val=request.GET.get('val')
            data=list(MEM_PRCHORDR.objects.filter(Q(MAV_PRCHORDRNUM__contains=val)|Q(MAV_DESC__contains=val)).values('MAV_PRCHORDRNUM','MAT_PRCHORDRDATE','MAF_RATE','MAV_DESC','MAV_UNIT','MAF_PRCHORDRQTY','MAV_RLY','MAV_PRCHORDRSR').order_by('-MAT_PRCHORDRDATE')[:300])
            for i in range(len(data)):
                data[i]['MAT_PRCHORDRDATE']=data[i]['MAT_PRCHORDRDATE'].strftime('%d-%m-%Y')
            return JsonResponse(data,safe=False)
        elif op == "fetchirepspo":
            val=request.GET.get('val')
            val=val.split('~')
            data=list(MEM_PRCHORDR.objects.filter(MAV_PRCHORDRNUM=val[0],MAV_PRCHORDRSR=val[1],MAV_RLY=val[2]).values('MAV_PRCHORDRNUM','MAT_PRCHORDRDATE','MAF_RATE','MAV_DESC','MAV_UNIT','MAF_PRCHORDRQTY','MAV_RLY','MAV_PRCHORDRSR'))
            return JsonResponse(data,safe=False)
        elif op == "addjustification":
            pk= request.GET.get('pk') 
            type= request.GET.get('type') 
            globaljustId = request.GET.get('globaljustId') 
            Justification = request.GET.get('Justification')
            if type=='D':
                if MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk).update(MATJSFN=Justification)

                else:
                    obj = MED_PRSLJSTN_DRAFT.objects.create(MAVPRSLNO=pk,MATJSFN=Justification)
                # else:
                #     obj = MED_PRSLJSTN_DRAFT.objects.filter(id=globaljustId).update(MATJSFN=Justification)
                data = list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
            else:
                data=list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
                pass
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse(data,safe=False)
        elif op=="saveror":
            pk= int(request.GET.get('pk'))
            type= request.GET.get('type')
            roi=request.GET.get('roi')
            rordet=request.GET.get('rordet')
            ror = request.GET.get('ror')
            if type == 'D':
                if not MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRORN_DRAFT.objects.create(MAVPRSLNO=pk,MARRORPER=roi,MATRORDETL=rordet,MAIROWN = ror)
                else:
                    MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).update(MARRORPER=roi,MATRORDETL=rordet,MAIROWN = ror)
                data='1'
            else:
                pass
                data='1'
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse(data,safe=False)        
        elif op=="finalsubmit":
            import datetime
            pk=request.GET.get('pk')
            y = initiate_mnp_draft(pk)
            MEM_PRSLN.objects.filter(MAVPRSLNO = str(y)).update(form_status = 1)
            
            MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = pk).delete()
            MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
            MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
            # MEM_PRSLN_DRAFT.objects.filter(MAVPRSLNO=str(pk)).delete()
            MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
            MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
            
            return JsonResponse(y, safe = False)
        elif op == "previewdraft":
            id=request.GET.get('pk')
            m=list(MEM_PRSLN_DRAFT.objects.filter(MAVPRSLNO=id).values())
            # print("===============",m)
            r=MEM_usersn.objects.get(MAV_userid=m[0]['MAVCRTRC'])
            just=list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values('MATJSFN','MAVPRSLNO'))
            # print(r.MAV_rlycode.rly_unit_code)
            a=railwayLocationMaster.objects.get(rly_unit_code=int(r.MAV_rlycode.rly_unit_code))
            rly=a.location_code
            division=a.location_type
            b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=request.session['department'])
            c=MED_rlymstr.objects.get(MAV_shrtraildesc=a.location_code)
            attach=list(MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            dept=b.MAVDEPTNAME
            asset=list(MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            replacement=list(MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror=list(MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            cost=list(MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO=m[0]['MAVPRSLNO']).values())
            if m[0]['MAVALCNCODE_id']!= None:
                a=MED_ALCNN.objects.get(MAVALCNCODE=m[0]['MAVALCNCODE_id'])
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=m[0]['MAVDEPTCODE_id'])
                allocation=a.MAVALCN
                department=b.MAVDEPTNAME
            else:
                allocation=''
                department=''
            # print("asset---------------------\\",ror)
            context.update({'old':'Y','proposal':m,'dept':dept,'rly':rly,'division':division,'just':just,'attach':attach,'id':m[0]['MAVPRSLNO'],'asset':asset,'replacement':replacement,'ror':ror,'type':'D','cost':cost,'alloc':allocation,'dept':department})
            # print("==========",just)
            return JsonResponse(context, safe = False)
        elif op=="mainpagesave":
            cuser=request.user
            mop=request.GET.get('mop3')
            pk=request.GET.get('pk')
            finyear=request.GET.get('finance_year')
            replacement=request.GET.get('rep')
            Indigeneous=request.GET.get('ind')
            type=request.GET.get('type')
            cofmow=request.GET.get('yes')
            department=request.GET.get('depart') 
            import datetime 
            if type=='D':
                if pk=='':
                    x = MEM_PRSLN_DRAFT.objects.values('MAVPRSLNO').last()
                    if x== None:
                        y=1
                    else:  
                        y = int(x['MAVPRSLNO']) + 1
                    chk2 = MEM_PRSLN_DRAFT.objects.create(created_by_user_id = request.user.MAV_userid,MAVUSERID=str(cuser),MAVCRTRC=str(cuser),MAVPRSLTYPE=mop,
                                                               MAIFINYEAR=finyear,MAVPRSLNO=str(y),MAVADDNRPLC=replacement,
                                                               MAVINDG=Indigeneous,MAVCFMW=cofmow,MADVRSNDATETIME=datetime.datetime.now(),
                                                               DEPTCODE_id = request.session['department'], MAVRLYCODE_id = request.user.MAV_rlycode_id,
                                                               MAVDIVCODE = request.session['division'])
                    z = list(MEM_ITEMMSTN.objects.values_list('MAV_ITEM_CODE', 'MAV_ITEM_NAME'))
                else:
                    y=int(pk)
                    MEM_PRSLN_DRAFT.objects.filter(MAVPRSLNO=y).update(MAVUSERID=str(cuser),MAVCRTRC=str(cuser),MAVPRSLTYPE=mop,MAIFINYEAR=finyear,MAVADDNRPLC=replacement,MAVINDG=Indigeneous,MAVCFMW=cofmow,MADVRSNDATETIME=datetime.datetime.now())
                if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(y)).exists():
                    initiate_mnp_draft(y)
                
                context = {
                    'msg' : "Data saved Successfully and Draft ID is " + str(y),
                    'id' : y
                }
                return JsonResponse(context , safe = False)
            
            elif type=='M':
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())
                if len(prev_data):
                    prev_data = prev_data[0]
                    version = prev_data['version'] - 1 

                    if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                        prev_data['version'] = version
                    
                    else:
                        version = version + 1
                        MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                        MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                    
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk).update(MAVPRSLTYPE = mop, MAIFINYEAR = finyear, MAVADDNRPLC = replacement, MAVINDG = Indigeneous,
                                                                          MAVCFMW = cofmow)
                    
                    latest_data = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values())
                    if len(latest_data):
                        latest_data = latest_data[0]
                        del latest_data['version']
                        del prev_data['version']
                        different_values = {key: (prev_data[key], latest_data[key]) 
                                    for key in prev_data 
                                    if key in latest_data and prev_data[key] != latest_data[key]}
                        
                        if len(different_values) > 0:
                            different = {}
                            different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                            different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                            different['changed_data'] = different_values
                            obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                            if isinstance(obj.prsln_data, list):
                                obj.prsln_data.append(different)
                            else:
                                obj.prsln_data = [different]
                            obj.save()


                
                context = {
                    'msg' : "Data Revised Successfully with Proposal Id " + str(pk),
                    'id' : pk
                }
                return JsonResponse(context , safe = False)
            else:
                context = {
                    'msg' : "Something Went Wrong, Contact Admin",
                    'id' : pk
                }
        elif op=="DraftInitiate":
            pk = request.GET.get('pk')
            y = initiate_mnp_draft(pk)
            msg = 'Proposal Initiated successfully and the proposal number is ' + str(y) + '...'
            main = MEM_PRSLN.objects.filter(MAVPRSLNO = y)
            try:
                a11 = request.user.MAV_rlycode.location_code
                b11 = request.user.MAV_rlycode.location_type
                railway_initiate = a11 +'/'+b11
            except:
                railway_initiate = ' - '
            if main.exists():
                data = main.last()
                id = data.ID
                description = data.MAVDESC 
                if description != None:
                    description = description[:500]
                module = 'MNP'
                status = 'Initiate'
                doc = '/mnp_document_pdf'
                if doc == 'doc' or doc == '':
                    doc = None
                url = '/proposal'
                if url == 'url' or url == '':
                    url = None
                msg = ''
                import datetime
                curr_date = datetime.datetime.now()
                ws = list(workflow_status.objects.filter(status_name = status).values('status_id'))
                if len(ws) > 0:
                    status_id = ws[0]['status_id']
                    wt = list(workflow_type.objects.filter(module_name = module).values('type_id'))
                    if len(wt) > 0:
                        type_id = wt[0]['type_id']
                        if workflow_activity_request.objects.filter(mod_id = id,type_id = type_id ).exists():
                            msg = f'Cannot {status}, as this {module} is already present in Workflow.'
                        else:
                            workflow_id = workflow_activity_request.objects.create(type_id_id = type_id,
                                                                    status_id = status_id, 
                                                                    url = url,
                                                                    doc_url = doc,
                                                                    mod_id = id,
                                                                    mod_name = y,
                                                                    pending_with_id = request.user.MAV_userid,
                                                                    desc = description,
                                                                    railway = railway_initiate)
                            
                            workflow_transaction.objects.create(workflow_id = workflow_id,
                                        by_user_id = request.user.MAV_userid,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = 'Initiated By Self'
                                        )
                            
                            msg = f'Successfully {status}, Please go to workflow application for further Action.'
                    else:
                        msg = f'Cannot {status}, as this module is not linked with Workflow. Please contact Admin.'
                    
                else:
                    msg = f'Cannot {status}, as this Status is not linked with Workflow. Please contact Admin.'
           
            return JsonResponse(msg, safe = False)        
        
        return JsonResponse({'status':False},status=400)
    elif request.method == "POST" and request.is_ajax():
        op= request.POST.get('op')
        if op=="savepdf":
            import datetime
            pk = request.POST.get('pk')
            type = request.POST.get('type')
            title = request.POST.get('title')
            supdoc = request.FILES.get('file11', False)
            folder = 'media/images'
            fs = FileSystemStorage(location=folder)
            _, file_extension = os.path.splitext(supdoc.name)
            new_file_name = f"file_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"
            files = fs.save(new_file_name, supdoc)
            upload_pdf = fs.url(files)
            upload_pdf = str(upload_pdf).split('media/')
            upload_pdf = 'images/' + upload_pdf[1]
            if type == 'D':
                pdf_record = MED_PRSLUPLDFILE_DRAFT.objects.create(
                    MAVPRSLNO=pk,
                    MAVPDFNAME=title,
                    MAVORGPDFNAME=upload_pdf,
                    MADUPLDDATETIME=datetime.datetime.now()
                )
                data = list(MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
            elif type == 'M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                pdf_record = MED_PRSLUPLDFILE.objects.create(
                    MAVPRSLNO=pk,
                    MAVPDFNAME=title,
                    MAVORGPDFNAME=upload_pdf,
                    MADUPLDDATETIME=datetime.datetime.now()
                )
                
                data = list(MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values('version'))[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                    pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                
                
                different = {}
                different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                different['changed_data'] = upload_pdf
                obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                if isinstance(obj.prsldoc_data, list):
                    obj.prsldoc_data.append(different)
                else:
                    obj.prsldoc_data = [different]
                obj.save()

            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse({'success': 'Data saved successfully','data':data})
        elif op=="saverornotapplicable":
            import datetime
            pk = request.POST.get('pk')
            type = request.POST.get('type')
            rorremarks = request.POST.get('rorremarks')
            supdoc = request.FILES.get('rorimages', False)
            try:
                folder = 'media/images'
                fs = FileSystemStorage(location=folder)
                _, file_extension = os.path.splitext(supdoc.name)
                new_file_name = f"file_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}{file_extension}"
                files = fs.save(new_file_name, supdoc)
                upload_pdf = fs.url(files)
                upload_pdf = str(upload_pdf).split('media/')
                upload_pdf = 'images/' + upload_pdf[1]
            except:
                upload_pdf = None
            print(type)
            if type == 'D':
                if not MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRORN_DRAFT.objects.create(MAVPRSLNO=pk,RORREQUIRED = 'Y',RORREMARKS = rorremarks,RORPDFNAME = upload_pdf)
                else:
                    href = request.POST.get('href')
                    print(href)
                    if href != 'null':
                        MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).update(RORREQUIRED = 'Y',RORREMARKS = rorremarks)
                    else:
                        MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).update(RORREQUIRED = 'Y',RORREMARKS = rorremarks,RORPDFNAME = upload_pdf)

            elif type == 'M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).values('MARRORPER','MATRORDETL','MAIROWN','RORREQUIRED','RORREMARKS','RORPDFNAME'))
                
                if not MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRORN.objects.create(MAVPRSLNO=pk,RORREQUIRED = 'Y',RORREMARKS = rorremarks,RORPDFNAME = upload_pdf)
                else:
                    href = request.POST.get('href')
                    if href != 'null':
                        MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).update(RORREQUIRED = 'Y',RORREMARKS = rorremarks)
                    else:
                        MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).update(RORREQUIRED = 'Y',RORREMARKS = rorremarks,RORPDFNAME = upload_pdf)

                prev_data = prev_data[0]
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values('version'))[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                    pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                latest_data =  list(MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).values('MARRORPER','MATRORDETL','MAIROWN','RORREQUIRED','RORREMARKS','RORPDFNAME'))
                latest_data = latest_data[0]
                different_values = {key: (prev_data[key], latest_data[key]) 
                                    for key in prev_data 
                                    if key in latest_data and prev_data[key] != latest_data[key]}
                if len(different_values) > 0:
                    different = {}
                    different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                    different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                    different_values = convert_decimals_to_strings(different_values)
                    different['changed_data'] = different_values
                    obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                    if isinstance(obj.prslror_data, list):
                        obj.prslror_data.append(different)
                    else:
                        obj.prslror_data = [different]
                    obj.save()
            else:
                pass
                
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse('1',safe=False)   

        elif op == "addjustification":
            pk= request.POST.get('pk') 
            type= request.POST.get('type') 
            globaljustId = request.POST.get('globaljustId') 
            Justification = request.POST.get('Justification')
            if type=='D':
                if MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk).update(MATJSFN=Justification)

                else:
                    obj = MED_PRSLJSTN_DRAFT.objects.create(MAVPRSLNO=pk,MATJSFN=Justification)
                # else:
                #     obj = MED_PRSLJSTN_DRAFT.objects.filter(id=globaljustId).update(MATJSFN=Justification)
                data = list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
            elif type=='M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk, DLTFLAG=False).values('MATJSFN'))
                if MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk).update(MATJSFN=Justification)
                else:
                    obj = MED_PRSLJSTN.objects.create(MAVPRSLNO=pk,MATJSFN=Justification)

                prev_data = prev_data[0]
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values('version'))[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                    pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                latest_data = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk, DLTFLAG=False).values('MATJSFN'))
                latest_data = latest_data[0]
                different_values = {key: (prev_data[key], latest_data[key]) 
                                    for key in prev_data 
                                    if key in latest_data and prev_data[key] != latest_data[key]}
                if len(different_values) > 0:
                    different = {}
                    different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                    different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                    different['changed_data'] = different_values
                    obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                    if isinstance(obj.prsljust_data, list):
                        obj.prsljust_data.append(different)
                    else:
                        obj.prsljust_data = [different]
                    obj.save()

                data = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk, DLTFLAG=False).values())
                
            else:
                data=list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
                pass
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse(data,safe=False)
        elif op=="saveror":
            pk= int(request.POST.get('pk'))
            type= request.POST.get('type')
            roi=request.POST.get('roi')
            rordet=request.POST.get('rordet')
            ror = request.POST.get('ror')
            print(type)
            if type == 'D':
                if not MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRORN_DRAFT.objects.create(MAVPRSLNO=pk,RORREQUIRED = 'N',MARRORPER=roi,MATRORDETL=rordet,MAIROWN = ror)
                else:
                    MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk).update(RORREQUIRED = 'N', MARRORPER=roi,MATRORDETL=rordet,MAIROWN = ror)


            elif type == 'M':
                import datetime
                user_id = request.user.MAV_userid
                curr_date = datetime.datetime.now()
                prev_data = list(MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).values('MARRORPER','MATRORDETL','MAIROWN'))
                
                if not MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).exists():
                    MED_PRSLRORN.objects.create(MAVPRSLNO=pk,MARRORPER=roi,MATRORDETL=rordet,MAIROWN = ror,RORREQUIRED = 'N')
                else:
                    MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).update(MARRORPER=roi,MATRORDETL=rordet,MAIROWN = ror,RORREQUIRED = 'N')

                prev_data = prev_data[0]
                version = list(MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).values('version'))[0]['version'] - 1
                if MEM_PRSLN_VERSION.objects.filter(prslno = pk, revised_by = user_id, version = version).exists():
                    pass
                else:
                    version = version + 1
                    MEM_PRSLN_VERSION.objects.create(revised_by_id = user_id,version = version, prslno = pk)
                    MEM_PRSLN.objects.filter(MAVPRSLNO = pk, form_status = 1).update(version = version + 1)
                latest_data =  list(MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).values('MARRORPER','MATRORDETL','MAIROWN'))
                latest_data = latest_data[0]
                different_values = {key: (prev_data[key], latest_data[key]) 
                                    for key in prev_data 
                                    if key in latest_data and prev_data[key] != latest_data[key]}
                if len(different_values) > 0:
                    different = {}
                    different['byuser'] = f'{request.user.MAV_username}({request.user.MAV_userid})' 
                    different['date'] = f"{curr_date.strftime('%d-%m-%Y %H:%M:%S')}"
                    different_values = convert_decimals_to_strings(different_values)
                    different['changed_data'] = different_values
                    obj = get_object_or_404(MEM_PRSLN_VERSION, prslno = pk, revised_by = user_id, version = version)
                    if isinstance(obj.prslror_data, list):
                        obj.prslror_data.append(different)
                    else:
                        obj.prslror_data = [different]
                    obj.save()

            else:
                pass
                
            if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = str(pk)).exists():
                initiate_mnp_draft(pk)
            return JsonResponse('1',safe=False)        
        
    elif request.method == "POST":
        cuser=request.user
        mop=request.POST.get('mop3')
        finyear=request.POST.get('finance_year')
        replacement=request.POST.get('rep')
        Indigeneous=request.POST.get('ind')
        cofmow=request.POST.get('yes')
        department=request.POST.get('depart')
        import datetime
        
        
        x = MEM_PRSLN.objects.values('MAVPRSLNO').last()
        
        if x== None:
           
            y=0
       
        else:  
            y = int(x['MAVPRSLNO'])+1

        MEM_PRSLN.objects.create(created_by_user_id = request.user.MAV_userid,MAVUSERID=str(cuser),MAVCRTRC=str(cuser),MAVPRSLTYPE=mop,MAIFINYEAR=finyear,MAVPRSLNO=str(y),MAVADDNRPLC=replacement,MAVINDG=Indigeneous,MAVCFMW=cofmow,MADVRSNDATETIME=datetime.datetime.now())
        chk='Y'

        chk2=MEM_PRSLN.objects.filter(MAVPRSLNO=y).values('MAVPRSLNO','MAVDESC','MANQTY','MAVALCNCODE','MANTTLCOST') 
        messages.success(request,'your record saved successfully'+str(y))
        
    
        z = list(MEM_ITEMMSTN.objects.values_list('MAV_ITEM_CODE', 'MAV_ITEM_NAME'))


        print(z,'zzzzzzzzzzzzzzzzzzzzzzzzz')
        data = MED_ASSTRGNN.objects.values('MAVASSTCODE__MAV_ITEM_CODE','MAVASSTCODE__MAV_ITEM_NAME','MAIYEARPURC','MAVDESC','MAICOST','MAIEXPLIFE','MAVITEMCODE')
        # cate=MEM_ITEMMSTN.objects.all().distinct('MAV_ITEM_NAME').order_by('MAV_ITEM_NAME').values('MAV_ITEM_NAME')
        # print(cate)
        context={
            'chk':chk,
            'z':z,
            'chk2':chk2,
            'pk':y,
            'data':data,
        }


    # return render(request, 'proposal.html',{'chk2':chk2,'pk':y})


        return render(request, 'proposal.html',context)
    elif request.method == "GET":
        submit=request.GET.get('submit')
        if submit == "editcall":
            
            id = request.GET.get('id')
            m = list(MEM_PRSLN_DRAFT.objects.filter(ID=id).values())
            if len(m) == 0:
                return HttpResponse('You cannot edit the proposal as it does not exist')
            
            if len(m):
                m1 = list(MEM_PRSLN.objects.exclude(MAVDRFTPRSLNO__isnull = True).filter(MAVDRFTPRSLNO = m[0]['MAVPRSLNO'], form_status = 1).values())
                if len(m1):
                    return HttpResponse('You cannot edit the proposal as it is Finalized.')

            r = MEM_usersn.objects.get(MAV_username=m[0]['MAVCRTRC'])
            just = list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values('MATJSFN','MAVPRSLNO'))
            if len(just) > 0:
                encrpt = encryption_decription()
                try:
                    just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
                except:
                    just = just[0]['MATJSFN']
            else:
                just = ''
            
            rly = m[0]['MAVRLYCODE_id']
            division , railway = find_div_railway(rly)
            if m[0]['DEPTCODE_id'] != None:
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=m[0]['DEPTCODE_id'])
                dept=b.MAVDEPTNAME
            else:
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=request.session['department'])
                dept=b.MAVDEPTNAME
                
            attach=list(MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            asset=list(MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            replacement=list(MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror=list(MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror_data = ''
            ror_remarks = ''
            rorType = '1'
            if len(ror) > 0:
                encrpt = encryption_decription()
                if ror[0]['RORREQUIRED'] == 'N':
                    rorType = '1'
                    try:
                        ror_data = encrpt.decryptWithAesEinspect(ror[0]['MATRORDETL'])
                    except:
                        ror_data = ror[0]['MATRORDETL']
                else:
                    rorType = '2'
                    try:
                        ror_remarks = encrpt.decryptWithAesEinspect(ror[0]['RORREMARKS'])
                    except:
                        ror_remarks = ror[0]['RORREMARKS']
            
            cost=list(MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO=m[0]['MAVPRSLNO']).values())
            
            

            
            context.update({'old':'Y','ror_data':ror_data, 'rorType':rorType, 'ror_remarks':ror_remarks, 'proposal':m,'dept':dept,'rly':railway,'division':division,'just':just,'attach':attach,'id':m[0]['MAVPRSLNO'],'asset':asset,'replacement':replacement,'ror':ror,'type':'D','cost':cost,'edit_type':'D'})

        elif submit == "WorkflowEdit":
            id=request.GET.get('id')
            m1=list(MEM_PRSLN.objects.exclude(MAVDRFTPRSLNO__isnull = True).filter(ID=id, form_status = 0).values())
            if len(m1) == 0:
                return HttpResponse('You are not not eligible to edit the form or proposal does not exist or proposal already finalize')
            m=list(MEM_PRSLN_DRAFT.objects.filter(MAVPRSLNO = m1[0]['MAVDRFTPRSLNO']).values())
            r = MEM_usersn.objects.get(MAV_username=m[0]['MAVCRTRC'])
            just = list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values('MATJSFN','MAVPRSLNO'))
            if len(just) > 0:
                encrpt = encryption_decription()
                try:
                    just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
                except:
                    just = just[0]['MATJSFN']
            else:
                just = ''
            
            rly = m[0]['MAVRLYCODE_id']
            division , railway = find_div_railway(rly)
            if m[0]['DEPTCODE_id'] != None:
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=m[0]['DEPTCODE_id'])
                dept=b.MAVDEPTNAME
            else:
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=request.session['department'])
                dept=b.MAVDEPTNAME
                
            attach=list(MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            asset=list(MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            replacement=list(MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror=list(MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror_data = ''
            ror_remarks = ''
            rorType = '1'
            if len(ror) > 0:
                encrpt = encryption_decription()
                if ror[0]['RORREQUIRED'] == 'N':
                    rorType = '1'
                    try:
                        ror_data = encrpt.decryptWithAesEinspect(ror[0]['MATRORDETL'])
                    except:
                        ror_data = ror[0]['MATRORDETL']
                else:
                    rorType = '2'
                    try:
                        ror_remarks = encrpt.decryptWithAesEinspect(ror[0]['RORREMARKS'])
                    except:
                        ror_remarks = ror[0]['RORREMARKS']
            
            cost=list(MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO=m[0]['MAVPRSLNO']).values())
            context.update({'old':'Y','ror_data':ror_data, 'rorType':rorType, 'ror_remarks':ror_remarks,'proposal':m,'dept':dept,'rly':railway,'division':division,'just':just,'attach':attach,'id':m[0]['MAVPRSLNO'],'asset':asset,'replacement':replacement,'ror':ror,'type':'D','cost':cost, 'edit_type':'W'})

        elif submit == "editprop":
            id=request.GET.get('id')
            m = list(MEM_PRSLN.objects.filter(ID=id, form_status = 1).values())

            if len(m) == 0:
                return HttpResponse('You are not not eligible to Revise the proposal or Proposal number does not exist.')
            else:
                if workflow_transaction.objects.filter(status__in = [2,9] , workflow_id__in = workflow_activity_request.objects.filter(mod_id = id, type_id__in = workflow_type.objects.filter(module_name = 'MNP').values('type_id')).values('workflow_id')).exists():
                    return HttpResponse('Proposal already Sanctioned or Rejected. So, cannot be revised.')

            r = MEM_usersn.objects.get(MAV_username = m[0]['MAVCRTRC'])
            #r=MEM_usersn.objects.get(MAV_userid=m[0]['MAVCRTRC'])
            just=list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values('MATJSFN','MAVPRSLNO'))
            if len(just) > 0:
                encrpt = encryption_decription()
                try:
                    just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
                except:
                    just = just[0]['MATJSFN']
            else:
                just = ''
            rly = m[0]['MAVRLYCODE_id']
            
            division , railway = find_div_railway(rly)
            
            if m[0]['DEPTCODE_id'] != None:
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=m[0]['DEPTCODE_id'])
                dept=b.MAVDEPTNAME
            else:
                b=MEM_DEPTMSTN.objects.get(MACDEPTCODE=request.session['department'])
                dept=b.MAVDEPTNAME
            
            attach=list(MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            asset=list(MED_ASSTRGNN.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            replacement=list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror=list(MED_PRSLRORN.objects.filter(MAVPRSLNO=m[0]['MAVPRSLNO']).values())
            ror_data = ''
            ror_remarks = ''
            rorType = '1'
            if len(ror) > 0:
                encrpt = encryption_decription()
                if ror[0]['RORREQUIRED'] == 'N':
                    rorType = '1'
                    try:
                        ror_data = encrpt.decryptWithAesEinspect(ror[0]['MATRORDETL'])
                    except:
                        ror_data = ror[0]['MATRORDETL']
                else:
                    rorType = '2'
                    try:
                        ror_remarks = encrpt.decryptWithAesEinspect(ror[0]['RORREMARKS'])
                    except:
                        ror_remarks = ror[0]['RORREMARKS']
            
            cost=list(MED_PRSLCOST.objects.filter(MANPRSNNO=m[0]['MAVPRSLNO']).values())
            print(rorType)
            context.update({'old':'Y','ror_data':ror_data, 'rorType':rorType, 'ror_remarks':ror_remarks,'proposal':m,'dept':dept,'rly':railway,'division':division,'just':just,'attach':attach,'id':m[0]['MAVPRSLNO'],'asset':asset,'replacement':replacement,'ror':ror,'type':'M','cost':cost, 'edit_type':'R'})
        else:
            context.update({'old':'N'})
    import datetime
    tod=datetime.datetime.today()
    m=tod.strftime('%m')
    if int(m) <= 3:
        styr=(int(tod.strftime('%Y'))-1)
    else:
        styr=(int(tod.strftime('%Y')))
    finyear=[]
    for i in range(3):
        styr=styr+i
        yr=str(styr)+"-"+str(int(str(styr)[-2:])+1).zfill(2)        
        finyear.append(yr)
    z = list(MEM_ITEMMSTN.objects.values_list('MAV_ITEM_CODE', 'MAV_ITEM_NAME'))
    activity_obj = list(MED_ALCNN.objects.values('MAVALCN','MAVALCNCODE'))
    obj=list(MED_CTGY.objects.values('MAVCATNAME','MACCATCODE'))
    obj2=list(MEM_DEPTMSTN.objects.values('MAVDEPTNAME','MACDEPTCODE'))
    machine1=list(MEM_ITEMDTLN.objects.all().exclude(MAV_ITEMDETWDE=None).distinct('MAV_ITEMDETWDE').values('MAV_ITEMDETWDE'))
    machine2=list(MEM_ITEMDTLN.objects.all().exclude(MAV_ITEMDESC=None).distinct('MAV_ITEMDESC').values('MAV_ITEMDESC'))
    machine3=list(MEM_ITEMDTLN.objects.all().exclude(Q(MAV_SPFNNO=None)|Q(MAV_SPFNNO='None')|Q(MAV_SPFNNO='N/A')).distinct('MAV_SPFNNO').values('MAV_SPFNNO'))
    location=list(railwayLocationMaster.objects.all().values('location_code').distinct('location_code'))
    
    finalize = False
    initiate = False
    draft = True
    revise = False
    id = context.get('id',None)
    if len(permission) > 0:
        finalize = permission[0]['finalize']
        initiate = permission[0]['drafting']

    if id != None:
        if context.get('edit_type',None) == 'R':
            initiate = False
            draft = False
            finalize = False
            revise = True if permission[0]['revise'] else False
        else:
            data = MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = id)
            if data.exists():
                raw = data.first()
                prsl_no = raw.MAVPRSLNO
                if workflow_activity_request.objects.filter(mod_name = prsl_no, type_id__in = workflow_type.objects.filter(module_name = 'MNP').values('type_id') ).exists():
                    initiate = False
                if (raw).form_status == 1:
                    draft = False
                    finalize = False
                    if len(permission) > 0:
                        revise = permission[0]['revise']
        
        if context.get('edit_type',None) == 'R' and revise == False:
            context['type'] = 'X'

    context.update({
        'finyr':finyear,
        'z':z,
        'machine1':machine1,
        'machine2':machine2,
        'machine3':machine3,
        'activity_obj':activity_obj,
        'obj': obj,
        'obj2': obj2,
        'location':location,
        'draft':draft,
        'finalize':finalize,
        'revise':revise,
        'initiate':initiate})
    if context['old']=='N':
        context.update({
            'dept':dept,
            'rly':railway,
            'division':division,
            'draft':draft,
            'finalize':finalize,
            'revise':revise,
            'initiate':initiate
        })
    
    return render(request, 'proposal.html',context)


def initiate_mnp_draft(pk):
    import datetime
    a = MEM_PRSLN_DRAFT.objects.get(MAVPRSLNO=str(pk))
    if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = a.MAVPRSLNO).exists():
        y = list(MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = a.MAVPRSLNO).values('MAVPRSLNO'))[0]['MAVPRSLNO']
    else:
        x = MEM_PRSLN.objects.values('MAVPRSLNO').last()
        if x == None:
            y = 1
        else:  
            y = int(x['MAVPRSLNO']) + 1
    if MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = a.MAVPRSLNO).exists():
        MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = a.MAVPRSLNO).update(MAVDRFTPRSLNO = a.MAVPRSLNO, MANCOST = a.MANCOST, MAVITEMCODE= a.MAVITEMCODE,MAVUSERID=a.MAVUSERID,MAVCRTRC=a.MAVCRTRC,MAVPRSLTYPE=a.MAVPRSLTYPE,MAIFINYEAR=a.MAIFINYEAR,
                                MAVPRSLNO=str(y), MAVADDNRPLC=a.MAVADDNRPLC,MAVINDG=a.MAVINDG,MAVCFMW=a.MAVCFMW,
                                MADVRSNDATETIME=datetime.datetime.now(),MAVDEPTCODE=a.MAVDEPTCODE,MAVRLYCODE_id=a.MAVRLYCODE_id,
                                MAVDIVCODE=a.MAVDIVCODE,MAVALCNCODE_id=a.MAVALCNCODE_id,MAVPRCHFROM=a.MAVPRCHFROM,
                                MAVDESC=a.MAVDESC,MAVSHRTDESC=a.MAVSHRTDESC,MANBASCCOST=a.MANBASCCOST,MANQTY=a.MANQTY,
                                MANTTLCOST=a.MANTTLCOST,MAVLOCN=a.MAVLOCN,MAVCNSN=a.MAVCNSN,MAVGMSANC=a.MAVGMSANC,MAVDRMSANC=a.MAVDRMSANC,
                                MAVCATCODE=a.MAVCATCODE, status_flag1=4)
        r = MEM_PRSLN.objects.filter(MAVDRFTPRSLNO = a.MAVPRSLNO).get()
    else:
        r = MEM_PRSLN.objects.create(DEPTCODE_id = a.DEPTCODE_id,created_by_user_id = a.created_by_user_id,MAVDRFTPRSLNO = a.MAVPRSLNO, MANCOST = a.MANCOST, MAVITEMCODE= a.MAVITEMCODE,MAVUSERID=a.MAVUSERID,MAVCRTRC=a.MAVCRTRC,MAVPRSLTYPE=a.MAVPRSLTYPE,MAIFINYEAR=a.MAIFINYEAR,
                                MAVPRSLNO=str(y), MAVADDNRPLC=a.MAVADDNRPLC,MAVINDG=a.MAVINDG,MAVCFMW=a.MAVCFMW,
                                MADVRSNDATETIME=datetime.datetime.now(),MAVDEPTCODE=a.MAVDEPTCODE,MAVRLYCODE_id=a.MAVRLYCODE_id,
                                MAVDIVCODE=a.MAVDIVCODE,MAVALCNCODE_id=a.MAVALCNCODE_id,MAVPRCHFROM=a.MAVPRCHFROM,
                                MAVDESC=a.MAVDESC,MAVSHRTDESC=a.MAVSHRTDESC,MANBASCCOST=a.MANBASCCOST,MANQTY=a.MANQTY,
                                MANTTLCOST=a.MANTTLCOST,MAVLOCN=a.MAVLOCN,MAVCNSN=a.MAVCNSN,MAVGMSANC=a.MAVGMSANC,MAVDRMSANC=a.MAVDRMSANC,
                                MAVCATCODE=a.MAVCATCODE, status_flag1=4)
    
    draft = MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = pk)
    if draft.exists():
        b = list(draft.values())
        for i in range(len(b)):
            if MED_PRSLCOST.objects.filter(MANPRSNNO = str(y), MANCPCODE = b[i]['MANCPCODE']).exists():
                MED_PRSLCOST.objects.filter(MANPRSNNO = str(y), MANCPCODE = b[i]['MANCPCODE']).update(MAVFINYEAR = b[i]['MAVFINYEAR'],MANPRSNNO = str(y),MANVRSNNO = b[i]['MANVRSNNO'],MANCPCODE = b[i]['MANCPCODE'],MANCPAMNT = b[i]['MANCPAMNT'],MANCPPER = b[i]['MANCPPER'])
            else:
                MED_PRSLCOST.objects.create(MAVFINYEAR = b[i]['MAVFINYEAR'],MANPRSNNO = str(y),MANVRSNNO = b[i]['MANVRSNNO'],MANCPCODE = b[i]['MANCPCODE'],MANCPAMNT = b[i]['MANCPAMNT'],MANCPPER = b[i]['MANCPPER'])
    
    b = list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk, DLTFLAG=False).values())
    if len(b) > 0:
        if MED_PRSLJSTN.objects.filter(MAVPRSLNO=str(y)).exists():
            MED_PRSLJSTN.objects.filter(MAVPRSLNO=str(y)).update(MATJSFN=b[0]['MATJSFN'])
        else:
            MED_PRSLJSTN.objects.create(MAVPRSLNO=str(y),MATJSFN=b[0]['MATJSFN'])

    c = list(MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
    for j in c:
        if MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO=str(y),MAVORGPDFNAME=j['MAVORGPDFNAME']).exists():
            MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO=str(y),MAVPDFNAME=j['MAVPDFNAME']).update(MAVPRSLNO=str(y),MAVPDFNAME=j['MAVPDFNAME'],MAVORGPDFNAME=j['MAVORGPDFNAME'],MADUPLDDATETIME=j['MADUPLDDATETIME'])
        else:
            MED_PRSLUPLDFILE.objects.create(MAVPRSLNO=str(y),MAVPDFNAME=j['MAVPDFNAME'],MAVORGPDFNAME=j['MAVORGPDFNAME'],MADUPLDDATETIME=j['MADUPLDDATETIME'])
    
    draft = MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk)
    if draft.exists():
        d = draft.first()
        if MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=str(y)).exists():
            MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=str(y)).update(MAVPRSLNO=str(y),MANSIFTNO=d.MANSIFTNO,MAVJOBLOAD=d.MAVJOBLOAD,MAVWORKLOAD=d.MAVWORKLOAD,MAVTOTLSMLRMACN=d.MAVTOTLSMLRMACN,MAVCAPSHRTFALL=d.MAVCAPSHRTFALL,MAVBREKDWNFRQN=d.MAVBREKDWNFRQN,MAVBREKDWNVLUE=d.MAVBREKDWNVLUE,MAVACCRRQRM=d.MAVACCRRQRM,MAACTLCAPB=d.MAACTLCAPB)
        else:
            MED_PRSLRPLCDTLS.objects.create(MAVPRSLNO=str(y),MANSIFTNO=d.MANSIFTNO,MAVJOBLOAD=d.MAVJOBLOAD,MAVWORKLOAD=d.MAVWORKLOAD,MAVTOTLSMLRMACN=d.MAVTOTLSMLRMACN,MAVCAPSHRTFALL=d.MAVCAPSHRTFALL,MAVBREKDWNFRQN=d.MAVBREKDWNFRQN,MAVBREKDWNVLUE=d.MAVBREKDWNVLUE,MAVACCRRQRM=d.MAVACCRRQRM,MAACTLCAPB=d.MAACTLCAPB)
        
    if a.MAVADDNRPLC == 'R':
        draft = MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk)
        if draft.exists():
            e = draft.first()
            if MED_ASSTRGNN.objects.filter(MAVPRSLNO=str(y)).exists():
                MED_ASSTRGNN.objects.filter(MAVPRSLNO=str(y)).update(MAVPRSLNO=str(y),MAVASSTCODE=e.MAVASSTCODE,MAIYEARPURC=e.MAIYEARPURC,MAVITEMCODE=e.MAVITEMCODE,MAVDESC=e.MAVDESC,MAICOST=e.MAICOST,MAIEXPLIFE=e.MAIEXPLIFE)
            else:
                MED_ASSTRGNN.objects.create(MAVPRSLNO=str(y),MAVASSTCODE=e.MAVASSTCODE,MAIYEARPURC=e.MAIYEARPURC,MAVITEMCODE=e.MAVITEMCODE,MAVDESC=e.MAVDESC,MAICOST=e.MAICOST,MAIEXPLIFE=e.MAIEXPLIFE)
    elif a.MAVADDNRPLC == 'A':
        draft = MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO=pk)
        if draft.exists():
            f = draft.first()
            if MED_PRSLRORN.objects.filter(MAVPRSLNO=str(y)).exists():
                MED_PRSLRORN.objects.filter(MAVPRSLNO=str(y)).update(MAVPRSLNO=str(y),MARRORPER=f.MARRORPER,MATRORDETL=f.MATRORDETL,MAIROWN = f.MAIROWN,RORREQUIRED = f.RORREQUIRED,RORREMARKS = f.RORREMARKS,RORPDFNAME = f.RORPDFNAME)
            else:
                MED_PRSLRORN.objects.create(MAVPRSLNO=str(y),MARRORPER=f.MARRORPER,MATRORDETL=f.MATRORDETL,MAIROWN = f.MAIROWN,RORREQUIRED = f.RORREQUIRED,RORREMARKS = f.RORREMARKS,RORPDFNAME = f.RORPDFNAME)
    return y
    

def dropdowndata(request):
    if request.method == 'GET' or request.is_ajax():
        activity_obj = list(MED_ALCNN.objects.values('MAVALCN','MAVALCNCODE'))
        obj=list(MED_CTGY.objects.values('MAVCATNAME','MACCATCODE'))
        obj2=list(MEM_DEPTMSTN.objects.values('MAVDEPTNAME','MACDEPTCODE'))
        print('print ajax edit',activity_obj)
        print('print ajax edit',obj)
        print('print ajax edit',obj2)
        context= {
            'activity_obj':activity_obj,
            'obj': obj,
            'obj2': obj2,
        }
       
        return JsonResponse(context,safe=False)
    return JsonResponse({'success':False},status=400)



def save_records(request):
    if request.method== 'GET' or request.is_ajax():
        print('ye chal rha hai')
        pro= request.GET.get('pro')
        print(type(pro),'pro')
        dept=request.GET.get('dept')
        cat=request.GET.get('cat')
        pa=request.GET.get('pa')
        desc=request.GET.get('des')
        sdesc=request.GET.get('sdesc')
        bcost=request.GET.get('bcost')
        print('LLLLLLLLLLLLLLLLLL',bcost)
        tuc=request.GET.get('tuc')
        print('ddddddddddddddddddddddddddddddddddd',pro,dept,cat,pa)
        print('ddddddddddddddddddddd',desc)
        print('temp',sdesc)
        qty=request.GET.get('qty')
        print('aaaaaaaaaaaaaaaa',qty )
        tcost=request.GET.get('tcost')
        locn=request.GET.get('locn')
        cnse=request.GET.get('cnse')
        check1=request.GET.get('check1')
        check2=request.GET.get('check2')
        print('dddddddddddddddddddddddd',check1)
        primaryKey=request.GET.get('primarykey')
        
        x=json.loads(request.GET.get('main_arr'))
       
       
        for i in range(len(x)):
            xa=x[i]['code']
            xb=x[i]['data1']
            xc=x[i]['data2']
            MED_PRSLCOST.objects.create(MANCPCODE=xa,MANCPAMNT=xb,MANCPPER=xc)  
        print(primaryKey,' primaryKey')
        MEM_PRSLN.objects.filter(MAVPRSLNO=primaryKey).update(MAVALCNCODE_id=pro,MAVDEPTCODE=dept,MAVPRCHFROM=pa,MAVDESC=desc,MAVSHRTDESC=sdesc,MANBASCCOST=bcost,MANQTY=qty,MANTTLCOST=tcost,MAVLOCN=locn,MAVCNSN=cnse,MAVGMSANC=check1,MAVDRMSANC=check2)



    return JsonResponse({'success':'records saved successsfully'})

def rateofreturn(request):
    if request.method== 'GET' or request.is_ajax():
        pk=request.GET.get('pk')
        chk3=list(MEM_PRSLN.objects.filter(MAVPRSLNO=pk).values('MAVPRSLNO','MAVDESC','MANQTY','MAVALCNCODE__MAVALCN','MANTTLCOST'))
        print(chk3)
        return JsonResponse(chk3,safe=False)
    


def save_ror(request):
    if request.method== 'GET' or request.is_ajax():
        pk= request.GET.get('pk')
        print('yyyyyyyyyyyyyyyyy',pk)
        roi=request.GET.get('roi')
        rordet=request.GET.get('rordet')
        if not MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).exists():
            MED_PRSLRORN.objects.create(MAVPRSLNO=pk,MARRORPER=roi,MATRORDETL=rordet)
        
        MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).update(MAVPRSLNO=pk,MARRORPER=roi,MATRORDETL=rordet)
    return JsonResponse({'success':'records saved successsfully'})


def add_justntext(request):
    if request.method == "GET" or request.is_ajax():
        pk= request.GET.get('pk') 
        globaljustId = request.GET.get('globaljustId') 
        Justification = request.GET.get('Justification')
        if globaljustId == '0':
            obj = MED_PRSLJSTN.objects.create(MAVPRSLNO=pk,MATJSFN=Justification)
        else:
            obj = MED_PRSLJSTN.objects.filter(id=globaljustId).update(MATJSFN=Justification)

        data = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values()) 
        print(data)
        return JsonResponse(data,safe=False)
    return JsonResponse({'status':False},status=400)

def delete_justntext(request):
    if request.method == "GET" or request.is_ajax():
        # Retrieve the ID of the entry to be deleted
        entry_id = request.GET.get('id')

        # Delete the entry from the screen data (not the database)
        # You can replace "ModelName" with the appropriate model name for the table
        # and "pk_field" with the appropriate primary key field name
        # ModelName.objects.filter(pk=entry_id).delete()
        if MED_PRSLJSTN.objects.filter(pk=entry_id).exists():
            MED_PRSLJSTN.objects.filter(pk=entry_id).update(DLTFLAG=True)


        return JsonResponse({'status': True})
    
    return JsonResponse({'status': False}, status=400)



# D Rajesh sir

def dropdowndata(request):
    if request.method == 'GET' and request.is_ajax():
        activity_obj = list(MED_ALCNN.objects.values('MAVALCN','MAVALCNCODE'))
        obj=list(MED_CTGY.objects.values('MAVCATNAME','MACCATCODE'))
        obj2=list(MEM_DEPTMSTN.objects.values('MAVDEPTNAME','MACDEPTCODE'))
        print('print ajax edit',activity_obj)
        print('print ajax edit',obj)
        print('print ajax edit',obj2)
        context= {
            'activity_obj':activity_obj,
            'obj': obj,
            'obj2': obj2,
        }
       
        return JsonResponse(context,safe=False)
    return JsonResponse({'success':False},status=400)

def save_replacement(request):
    if request.method== 'GET' or request.is_ajax():
        pk= request.GET.get('pk')
        catg= request.GET.get('catg')
        print('hhhhhhhhhhhhhhhhhhhhh',catg)
        localplantno= request.GET.get('localplantno')
        yofpurch= request.GET.get('yofpurch')
        descr= request.GET.get('descr')
        costrs= request.GET.get('costrs')
        explife= request.GET.get('explife')
        print('hhhhhhhhhhhhhhhhhhhhh',catg,localplantno)
        catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = catg)
        MED_ASSTRGNN.objects.create(MAVPRSLNO=pk,MAVASSTCODE=catg_id,MAIYEARPURC=int(yofpurch),MAVITEMCODE=localplantno,MAVDESC=descr,MAICOST=int(costrs),MAIEXPLIFE=int(explife))
        data1 = list(MED_ASSTRGNN.objects.values('MAVPRSLNO','MAVASSTCODE__MAV_ITEM_CODE','MAVASSTCODE__MAV_ITEM_NAME','MAIYEARPURC','MAVDESC','MAICOST','MAIEXPLIFE','MAVITEMCODE'))
        print(data1)
        context = {'data1':data1}
        print('hhhhhhhhhh')
        return JsonResponse(context,safe=False)
    return JsonResponse({'success':False},status=400)

def save_replacementjustfn(request):
    if request.method== 'GET' or request.is_ajax():
        pk= request.GET.get('pk')
        shiftmchn= request.GET.get('shiftmchn')
        jobloaded= request.GET.get('jobloaded')
        wrkload= request.GET.get('wrkload')
        simmchn= request.GET.get('simmchn')
        cpctsrtfall= request.GET.get('cpctsrtfall')
        breakdown= request.GET.get('breakdown')
        perbreakdown= request.GET.get('perbreakdown')
        accuracyrequirement= request.GET.get('accuracyrequirement')
        actlcpct= request.GET.get('actlcpct')
        MED_PRSLRPLCDTLS.objects.create(MAVPRSLNO=pk,MANSIFTNO=int(shiftmchn),MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall,MAVBREKDWNFRQN=breakdown,MAVBREKDWNVLUE=perbreakdown,MAVACCRRQRM=accuracyrequirement,MAACTLCAPB=actlcpct)
        return JsonResponse({"msg":"data saved successfully"},safe=False)
    return JsonResponse({'success':False},status=400)


def justfnprt2saving(request):
    if request.method== 'GET' or request.is_ajax():
        pk= request.GET.get('pk')
        jobloaded= request.GET.get('jobloaded')
        wrkload= request.GET.get('wrkload')
        simmchn= request.GET.get('simmchn')
        cpctsrtfall= request.GET.get('cpctsrtfall')
        MED_PRSLRPLCDTLS.objects.create(MAVPRSLNO=pk,MAVJOBLOAD=jobloaded,MAVWORKLOAD=wrkload,MAVTOTLSMLRMACN=simmchn,MAVCAPSHRTFALL=cpctsrtfall)
        return JsonResponse({"msg":"data saved successfully"},safe=False)
    return JsonResponse({'success':False},status=400)


def save_comment(request):
    if request.method== 'GET' or request.is_ajax():
        pk= request.GET.get('pk')
        comment= request.GET.get('comment')
        print(comment,'comment')
        MED_PRSLRMRKN.objects.create(MAVPRSLNO=pk, MAVRMRK=comment,MADRMRKDATETIME=datetime.now())
        data=list(MED_PRSLRMRKN.objects.filter(MAVPRSLNO=pk).values())
        return JsonResponse({"data":data},safe=False)
    return JsonResponse({'success':False},status=400)


def rateofreturn(request):
    if request.method== 'GET' or request.is_ajax():
        pk=request.GET.get('pk')
        chk3=list(MEM_PRSLN.objects.filter(MAVPRSLNO=pk).values('MAVPRSLNO','MAVDESC','MANQTY','MAVALCNCODE__MAVALCN','MANTTLCOST'))
        print(chk3)
        return JsonResponse(chk3,safe=False)


def fetchcofmowdata(request):
    if request.method== 'GET' or request.is_ajax():
        data=list(MEM_ITEMDTLN.objects.values('MAV_ITEMDETWDE','MAV_ITEMDESC','MAV_MDESC1','MAV_CPCT1','MAV_CPCT2','MAD_COST2324','MAV_SPFNNO2324'))
        print(data)
        return JsonResponse({'data':data},safe=False)


def fetch_machineid(request):
    if request.method== 'GET' or request.is_ajax():
        id=request.GET.get('id')
        print(id,"id etendra")
        data=list(MEM_ITEMDTLN.objects.filter(MAV_ITEMDETWDE=id).values_list('MAV_ITEMDETWDE',flat=True))
        print(data,"etendra data")
        return JsonResponse({'data':data},safe=False)
    

def save_ror(request):
    if request.method== 'GET' or request.is_ajax():
        pk= request.GET.get('pk')
        print('yyyyyyyyyyyyyyyyy',pk)
        roi=request.GET.get('roi')
        rordet=request.GET.get('rordet')
        if not MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).exists():
            MED_PRSLRORN.objects.create(MAVPRSLNO=pk,MARRORPER=roi,MATRORDETL=rordet)
        
        MED_PRSLRORN.objects.filter(MAVPRSLNO=pk).update(MAVPRSLNO=pk,MARRORPER=roi,MATRORDETL=rordet)
    return JsonResponse({'success':'records saved successsfully'})

def add_justntext(request):
    if request.method == "GET" or request.is_ajax():
        pk= request.GET.get('pk') 
        globaljustId = request.GET.get('globaljustId') 
        Justification = request.GET.get('Justification')
        if globaljustId == '0':
            obj = MED_PRSLJSTN.objects.create(MAVPRSLNO=pk,MATJSFN=Justification)
        else:
            obj = MED_PRSLJSTN.objects.filter(id=globaljustId).update(MATJSFN=Justification)

        data = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values()) 
        print(data)
        return JsonResponse(data,safe=False)
    return JsonResponse({'status':False},status=400)


def delete_justntext(request):
    if request.method == "GET" or request.is_ajax():
        # Retrieve the ID of the entry to be deleted
        entry_id = request.GET.get('id')

        # Delete the entry from the screen data (not the database)
        # You can replace "ModelName" with the appropriate model name for the table
        # and "pk_field" with the appropriate primary key field name
        # ModelName.objects.filter(pk=entry_id).delete()
        if MED_PRSLJSTN.objects.filter(pk=entry_id).exists():
            MED_PRSLJSTN.objects.filter(pk=entry_id).update(DLTFLAG=True)
        return JsonResponse({'status': True})
    return JsonResponse({'status': False}, status=400)


def delete_pdf(request):
    if request.method == "GET" or request.is_ajax():
        # Retrieve the ID of the entry to be deleted
        entry_id = request.GET.get('id')

        # Delete the entry from the screen data (not the database)
        # You can replace "ModelName" with the appropriate model name for the table
        # and "pk_field" with the appropriate primary key field name
        # ModelName.objects.filter(pk=entry_id).delete()
        if MED_PRSLUPLDFILE.objects.filter(pk=entry_id).exists():
            MED_PRSLUPLDFILE.objects.filter(pk=entry_id).update(DLTFLAG=True)


        return JsonResponse({'status': True})
    
    return JsonResponse({'status': False}, status=400)



def save_n_add_pdf(request):
    print(request.method)
    if request.method == "POST" and request.is_ajax():
        print('shukla')
        pk= request.POST.get('pk')
        print(request.FILES.get('file11'),pk)
        myfile=request.FILES.get('file11',False)
        title=request.FILES.get('title',False)
        print(myfile,'  myfile')
        supdoc = request.FILES['file11']
        folder='media/images'
        fs=FileSystemStorage(location=folder)
        files=fs.save(supdoc.name,supdoc)
        upload_pdf=fs.url(files)
        upload_pdf=str(upload_pdf).split('media/')
        upload_pdf='images/'+upload_pdf[1]
        print('upload_pdf',upload_pdf)
        

        pdf_record = MED_PRSLUPLDFILE.objects.create(MAVPRSLNO=pk,MAVPDFNAME=title,MAVORGPDFNAME=upload_pdf,MADUPLDDATETIME=datetime.now())
        data = list(MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO=pk,DLTFLAG=False).values())
    

        return JsonResponse({'success': 'Data saved successfully','data':data})

    return JsonResponse({'error': 'Invalid request method'})

#draftcreateproposal

def draftcreateproposal(request):
    if request.method =="GET" and request.is_ajax():
        print("zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz")
def program(request):
    return render(request,'program.html',context)
def delete(request):
    return render(request,'deletionofzonalrailway.html')



#honey
def add_new_item(request):
    current_year = datetime.datetime.now().year
    years = list(range(2011, current_year + 1))
    years.reverse()  
    if request.method == 'POST':
        selected_status = request.POST.get('current_status')
    statuses = MEM_PRSLTHRWFRWDEVNT.objects.values_list('MAVEVNTDESC', flat=True)

    purchases = MED_PRSLTHRWFRWD.objects.values_list('MAVPRCHFROM', flat=True).distinct()

    allocations = MED_ALCNN.objects.values_list('MAVALCN', flat=True).distinct()

    progs =  MEM_PRSLPRGS.objects.values_list('MAVDESC', flat=True).distinct()
    data = MED_PRSLTHRWFRWD.objects.filter(MABDELTFLAG=False).values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()

    data1 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Completed').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    data2 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Under Progress').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    data3 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Dropped').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    context = {
    'years': years,
    'statuses': statuses,
    'purchases': purchases,
    'allocations': allocations,
    'obj':data,
    'obj1':data1,
    'obj2':data2,
    'obj3':data3,
    'progs':progs,
    }
    return render(request, 'add_new_item.html', context)

def add_new_item_pdf(request):
    abs_path=os.path.abspath('static/images/picture.png')
    # abs_path1=os.path.abspath('static/images/crislogo1.png')
    current_year = datetime.datetime.now().year
    years = list(range(2011, current_year + 1))
    years.reverse()  
    if request.method == 'POST':
        selected_status = request.POST.get('current_status')
    statuses = MEM_PRSLTHRWFRWDEVNT.objects.values_list('MAVEVNTDESC', flat=True)

    purchases = MED_PRSLTHRWFRWD.objects.values_list('MAVPRCHFROM', flat=True).distinct()

    allocations = MED_ALCNN.objects.values_list('MAVALCN', flat=True).distinct()

    progs =  MEM_PRSLPRGS.objects.values_list('MAVDESC', flat=True).distinct()
    data = MED_PRSLTHRWFRWD.objects.filter(MABDELTFLAG=False).values('MAVFINYEAR','MAVPRSLNUM','MAVSCNDCOST','MAVPRCHFROM','MAVSTTS','MAVCURRSTTS','MAVALCN').all()

    data1 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Completed').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    data2 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Under Progress').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    data3 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Dropped').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    context = {
    'abs_path':abs_path,
    'years': years,
    'statuses': statuses,
    'purchases': purchases,
    'allocations': allocations,
    'obj':data,
    'obj1':data1,
    'obj2':data2,
    'obj3':data3,
    'progs':progs,
    }
    template_src='add_new_item_pdf.html'
    return render_to_pdf(template_src, context)

def add_new_item_excel(request):
    current_year = datetime.datetime.now().year
    years = list(range(2011, current_year + 1))
    years.reverse()  
    if request.method == 'POST':
        selected_status = request.POST.get('current_status')
    statuses = MEM_PRSLTHRWFRWDEVNT.objects.values_list('MAVEVNTDESC', flat=True)


    purchases = MED_PRSLTHRWFRWD.objects.values_list('MAVPRCHFROM', flat=True).distinct()

    allocations = MED_ALCNN.objects.values_list('MAVALCN', flat=True).distinct()

    progs =  MEM_PRSLPRGS.objects.values_list('MAVDESC', flat=True).distinct()
    data = MED_PRSLTHRWFRWD.objects.filter(MABDELTFLAG=False).values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()

    data1 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Completed').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    data2 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Under Progress').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    data3 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Dropped').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    context = {
    'years': years,
    'statuses': statuses,
    'purchases': purchases,
    'allocations': allocations,
    'obj':data,
    'obj1':data1,
    'obj2':data2,
    'obj3':data3,
    'progs':progs,
    }
    import xlwt
    from xlwt import Workbook
    from django.http import HttpResponse
    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename="AddNewItemReport.xls"'
    wb = Workbook()
    sheet1 = wb.add_sheet('Sheet 1')
    style = xlwt.easyxf("alignment: wrap off;font: bold on;borders: top_color black, bottom_color black, right_color black, left_color black;")
    style1 = xlwt.easyxf("alignment: wrap off;borders: top_color black, bottom_color black, right_color black, left_color black;")
    style2 = xlwt.easyxf("alignment: wrap off;font: bold on;")
    heading1 = "Machinery and Plant Portal"
    row = 1
    col =4
    sheet1.write_merge(row, row , col, col + 1, heading1, style=style2)
    row = 4
    col = 4
    sheet1.write(row, col, 'Add New Item Report', style=style2)
    
    row = 6
    col = 0
    attributes = ["S.no","Financial year", "Proposal Number", "Procured Through", "Sanctioned Cost(Rs.)", "Status", "Allocation", "Current Status"]
    col_width = {col:len(attr)for col, attr in enumerate(attributes)}
    for idx, attribute in enumerate(attributes):
        sheet1.write_merge(row, row + 0, col, col, attribute, style=style)
        col_width[col] = max(col_width[col],len(attribute))
        col += 1

    data = context['obj']
    row = 7
    data1 = MED_PRSLTHRWFRWD.objects.filter(MAVSTTS='Completed').values('MAVFINYEAR','MAVRAILCODE','MAVPRSLNUM','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()

    for index, item in enumerate(data, start=1):
        sheet1.write(row, 0, index, style=style1)
        sheet1.write(row, 1, item['MAVFINYEAR'], style=style1)
        sheet1.write(row, 2, item['MAVPRSLNUM'], style=style1)
        sheet1.write(row, 3, item['MAVPRCHFROM'], style=style1)
        sheet1.write(row, 4, item['MAVSCNDCOST'], style=style1)
        sheet1.write(row, 5, item['MAVSTTS'], style=style1)
        sheet1.write(row, 6, item['MAVALCN'], style=style1)
        sheet1.write(row, 7, item['MAVCURRSTTS'], style=style1)
        for col, content in enumerate([index,item['MAVFINYEAR'],item['MAVPRSLNUM'], item['MAVPRCHFROM'],item['MAVSCNDCOST'],item['MAVSTTS'],item['MAVALCN'],item['MAVCURRSTTS']]):
            col_width[col]=max (col_width[col],len(str(content)))
        row += 1

    for col,width in col_width.items():
        sheet1.col(col).width=(width + 4)* 256        

    wb.save(response)
    return response

  
def viewDetails(request):
    if request.method == 'GET' and request.is_ajax():
        proposal_no=request.GET.get('MAVSTTS')
        print(proposal_no,"proposal_no")
        # list1 = []

        
        obj5 = list(MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM=proposal_no).values_list('MAVPRSLNUM','MAVRAILCODE','MAVDESC','MAVCNSE','MAVQTY','MAVABOV','MAVLTSTATPDCOST','MAVBLNCTOCOMPWORK','MAVRMRK','MAVTOTLEXPDINCR'))
        print(obj5,"obj5")
        obj6 = list(MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM=proposal_no,MAVSTTS='Completed').values_list('MAVPRSLNUM','MAVRAILCODE','MAVDESC','MAVCNSE','MAVQTY','MAVABOV','MAVLTSTATPDCOST','MAVBLNCTOCOMPWORK','MAVRMRK','MAVTOTLEXPDINCR'))
        print(obj6,"obj6")
        obj7 = list(MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM=proposal_no,MAVSTTS='Under Progress').values_list('MAVPRSLNUM','MAVRAILCODE','MAVDESC','MAVCNSE','MAVQTY','MAVABOV','MAVLTSTATPDCOST','MAVBLNCTOCOMPWORK','MAVRMRK','MAVTOTLEXPDINCR'))
        print(obj7,"obj7")
        obj8 = list(MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM=proposal_no,MAVSTTS='Dropped').values_list('MAVPRSLNUM','MAVRAILCODE','MAVDESC','MAVCNSE','MAVQTY','MAVABOV','MAVLTSTATPDCOST','MAVBLNCTOCOMPWORK','MAVRMRK','MAVTOTLEXPDINCR'))
        print(obj8,"obj8")
        context = {
            'obj5':obj5,
            'obj6':obj6,
            'obj7':obj7,
            'obj8':obj8,
        }
        return JsonResponse({'obj5':obj5,'obj6':obj6,'obj7':obj7,'obj8':obj8},safe=False)

def mysave(request):
    if request.method == 'GET' and request.is_ajax():
        financialyear = request.GET.get('financialyear')
        rail= request.GET.get('rail')
        proposal_n=request.GET.get('proposal_n')
        desc = request.GET.get('desc')
        consignee = request.GET.get('consignee')
        quantity = request.GET.get('quantity')
        processed = request.GET.get('processed')
        current = request.GET.get('current')
        Sanctioned = request.GET.get('Sanctioned')
        above25 = request.GET.get('above25')
        latestAnticipated = request.GET.get('latestAnticipated')
        balance = request.GET.get('balance')
        remark = request.GET.get('remark')
        status = request.GET.get('status')
        totalExpenditure = request.GET.get('totalExpenditure')
        allocation = request.GET.get('allocation')
        MED_PRSLTHRWFRWD.objects.create(MAVFINYEAR=financialyear,MAVRAILCODE=rail,MAVPRSLNUM=proposal_n,MAVDESC=desc,MAVCNSE=consignee,MAVQTY=quantity, MAVPRCHFROM= processed,MAVCURRSTTS=current,MAVSCNDCOST=Sanctioned,MAVABOV=above25,MAVLTSTATPDCOST=latestAnticipated, MAVBLNCTOCOMPWORK=balance,MAVRMRK=remark,MAVSTTS=status,MAVTOTLEXPDINCR=totalExpenditure,MAVALCN =allocation)
        return JsonResponse({'success':'my data is saved'},safe=False)

def updateview(request):
     if request.method == 'GET' and request.is_ajax():
        proposal= request.GET.get('proposal')
        financialyear = request.GET.get('financialyear')
        latestanti  = request.GET.get('latestanti')
        rail_code = request.GET.get('rail_code')
        status = request.GET.get('status')
        balance=request.GET.get('balance')
        curr_stat=request.GET.get('curr_stat')
        desc = request.GET.get('desc')
        print(proposal,"MAVPRSLNUM",financialyear,"financialyear",latestanti ,"latestanti ")
        MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM = proposal).update(MAVFINYEAR=financialyear,MAVRAILCODE=rail_code,MAVPRSLNUM=proposal,MAVDESC=desc,MAVCURRSTTS=curr_stat,MAVLTSTATPDCOST=latestanti, MAVBLNCTOCOMPWORK=balance,MAVSTTS=status)
        return JsonResponse({'success':'my data is saved'}, safe=False)

def editview(request):
    print('hhhh')
    if request.method == "GET" and request.is_ajax():
        print("inside fnnnn")
        id2= request.GET.get('MAVPRSLNUM')
        print(id2,"idddd")
        obj = MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM=id2).values_list()
        obj = [entry for entry in obj]
        print(obj,"objjj")
        #lst=list(obj)
        return JsonResponse({'obj':obj}, safe=False)

def deleteview(request):
    if request.method == "GET" and request.is_ajax():
        print("hii")
        id1 = request.GET.get('MAVPRSLNUM')
        print(id1,"hlo")
        MED_PRSLTHRWFRWD.objects.filter(MAVPRSLNUM=id1).update(MABDELTFLAG=True)
        print("ofgt")
        return JsonResponse({"success":"deleted successfully"}, safe=False)

# def exportExcel(request):
#     response = HttpResponse(content_type='application/ms-excel')
#     response['Content-Disposition'] = 'attachment; filename=Data' + \
#         str(datetime.datetime.now()) + '.xls'
#     wb=xlwt.Workbook(encoding='utf-8')
#     ws=wb.add_sheet('Plantation')
#     row_num = 0
#     font_style =xlwt.XFStyle()
#     font_style.font.bold = True

#     columns = ['f_year','Des','consinee','quantity','Purchase_from','sanc_cost','above','anticipated','balance_complete_work','remark','status','curr_stat','total_expendt_incurred','allo']
#     for col_num in range(len(columns)):
#         ws.write(row_num,col_num,columns[col_num],font_style)

#     font_style =xlwt.XFStyle()

#     rows = MED_PRSLTHRWFRWD.objects.filter(f_year=request.user).values_list('f_year','Des','consinee','quantity','Purchase_from','sanc_cost','above','anticipated','balance_complete_work','remark','status','curr_stat','total_expendt_incurred','allo')

#     for row in rows:
#         row_num+=1

#         for col_num in range(len(row)):
#             ws.write(row_num,col_num,str(row[col_num]),font_style)
    
#     wb.save(response)
#     return response

def fetch_descendants(parent_code, descendants):
    children = railwayLocationMaster.objects.filter(parent_rly_unit_code=parent_code, delete_flag=False, deleted_flag=False)
    for child in children:
        if child.rly_unit_code not in descendants:
            descendants.add(child.rly_unit_code)
            fetch_descendants(child.rly_unit_code, descendants)
    return descendants


from django.contrib.auth.decorators import login_required
@login_required
def list_of_proposal(request):
    cuser = request.user
    user_railway = find_railway(cuser.MAV_rlycode_id)
    descendants = set()
    descendants = fetch_descendants(cuser.MAV_rlycode_id,descendants)
    descendants.add(cuser.MAV_rlycode_id)

    selected_year = None
    selected_type = None   #THIS ONE
    selected_user = None
    selected_forwarded = None
    current_user_level_code =list(MEM_usersn.objects.filter(MAV_username=cuser).values_list('MAV_userlvlcode_id',flat = True))[0]
    
    if request.method == 'POST':
        selected_year = request.POST.get('selected_year')
        selected_type = request.POST.get('selected_type')   # 🔸 Read proposal type from dropdown
        selected_forwarded = request.POST.get('selected_forwarded')
   
        filter_kwargs = {
        'delete_flag': False,
        'MAVRLYCODE__in': descendants,
        }

        if selected_year and not request.POST.get('show_all'):
            filter_kwargs['MADVRSNDATETIME__year'] = int(selected_year)

        if selected_type and selected_type != 'All':
            filter_kwargs['MAVPRSLTYPE'] = selected_type

        obj = MEM_PRSLN.objects.filter(**filter_kwargs).values(
            'ID', 'MAVPRSLNO', 'MADVRSNDATETIME', 'MAVRLYCODE_id__location_code',
            'MAVDESC', 'MAVPRCHFROM', 'MAVALCNCODE_id__MAVALCN', 'MANTTLCOST',
            'MAVCRTRC', 'MAVACTV', 'MAVDEPTCODE_id__MAVDEPTNAME', 'status_flag1',
            'MAVDIVCODE', 'MAVUSERCODE', 'MAVLOCN', 'created_by_user_id__MAV_userdesig',
            'workflow_status', 'form_status', 'version', 'MAVDRFTPRSLNO',
            'MAVGMSANC', 'MAVDRMSANC', 'MAVPRSLTYPE'  # include MAVPRSLTYPE if needed in template
            ).order_by('-ID')
    else:
        obj=MEM_PRSLN.objects.filter(
            delete_flag=False,
            MAVRLYCODE__in=descendants
        ).values(
            'ID', 'MAVPRSLNO', 'MADVRSNDATETIME', 'MAVRLYCODE_id__location_code',
            'MAVDESC', 'MAVPRCHFROM', 'MAVALCNCODE_id__MAVALCN', 'MANTTLCOST',
            'MAVCRTRC', 'MAVACTV', 'MAVDEPTCODE_id__MAVDEPTNAME', 'status_flag1',
            'MAVDIVCODE', 'MAVUSERCODE', 'MAVLOCN', 'created_by_user_id__MAV_userdesig',
            'workflow_status', 'form_status', 'version', 'MAVDRFTPRSLNO',
            'MAVGMSANC', 'MAVDRMSANC', 'MAVPRSLTYPE'
        ).order_by('-ID')

    if request.is_ajax():
        if selected_forwarded == 'Railway Board':
            employees = MEM_usersn.objects.filter(user_level_code=39).values('MAV_username', 'MAV_userdesig')
            combined_data = [f"{emp['MAV_username']} - {emp['MAV_userdesig']}" for emp in employees]
            return JsonResponse(list(combined_data), safe=False)
            print(combined_data,"^^^^^^^^^^^^^^^")

        elif selected_forwarded == 'CME Planning':
            cmes = MEM_usersn.objects.filter(user_level_code=20).values('MAV_username', 'MAV_userdesig')
            combined_data = [f"{cme['MAV_username']} - {cme['MAV_userdesig']}" for cme in cmes]
            return JsonResponse(list(combined_data), safe=False)
        elif selected_forwarded == 'HQF':
            is_hqf = request.POST.get('is_hqf') == 'true'
            if is_hqf:
                hqfs = MEM_usersn.objects.filter(user_level_code=29).values('MAV_username')
                return JsonResponse(list(hqfs), safe=False)
        elif selected_forwarded == 'DF':
            is_df = request.POST.get('is_df') == 'true'
            if is_df:
                dfs = MEM_usersn.objects.filter(user_level_code=19).values('MAV_username')
                return JsonResponse(list(dfs), safe=False)
    
    draft_data = []
    finalized_data = []
    vetted = []
    unvetted = []
    rejected = []
    approved = []
    gmpower = []
    sanction = []
    drmpower = []
    rbpower = []

    all_id = [i['ID'] for i in obj]
    all_id_current_status = list(workflow_activity_request.objects.filter(mod_id__in = all_id, type_id__in = workflow_type.objects.filter(module_name = 'MNP').values('type_id') ).values('status_id__status_name','pending_with_id__MAV_userdesig','workflow_id','mod_id'))
    workflow_dict = {}
    transactions = workflow_transaction.objects.filter(workflow_id__in = [i['workflow_id'] for i in all_id_current_status],pull_back = False).values('workflow_id','status','by_user','by_user__MAV_rlycode','to_user','to_user__MAV_rlycode','reply').order_by('-trans_id')
    
    for transaction in transactions:
        w_id = transaction['workflow_id']
        get_data = list(custom_filter(lambda x: x['workflow_id'] == w_id, all_id_current_status))
        if get_data:
            i = get_data[0]
            mod_id = i['mod_id']
            if mod_id not in workflow_dict:
                workflow_dict[mod_id] = {'status':i['status_id__status_name'],
                'pending_with':i['pending_with_id__MAV_userdesig'],
                'workflow_id':w_id,
                'all_status':[]}
            
            workflow_dict[mod_id]['all_status'].append({
                'status': transaction['status'],
                'by_user': transaction['by_user'],
                'rly_id': transaction['by_user__MAV_rlycode'],
                'to_user': transaction['to_user'],
                'reply': transaction['reply']
            })
            
    for i in obj:
        form_status  = i['form_status']
        id = i['ID']
        get_data = workflow_dict.get(id, None)
        if get_data == None:
            i.update({'update_status': ' - ', 'update_pending': None, 'workflow_id' : None})
        else:
            i.update({'update_status': get_data['status'], 'update_pending': get_data['pending_with'], 'workflow_id': get_data['workflow_id']})
        if form_status == 0 and i['created_by_user_id__MAV_userdesig'] == cuser.MAV_userdesig and i['workflow_status'] != 2:
            i.update({'draft_type':'W'})
            draft_data.append(i)
        
        if form_status == 1:
            if get_data != None:
                data = get_data['all_status']
                status14 = list(custom_filter(lambda x: x['status'] == 14, data))
                # if len(status14) == 0:
                #     status10 = list(custom_filter(lambda x: x['status'] == 10, data))
                #     if len(status10) > 0:
                #         pass
                #     else:
                #         i.update({'hf':'N', 'df':'N'})
                #         unvetted.append(i)
                # else:
                df = 'N'
                hf = 'N' 
                railway_user = None
                div_user = None
                for ii in status14:
                    rly_id = ii['rly_id']
                    if hf == 'N':
                        railway_of_user = find_railway(rly_id)
                        if railway_of_user == rly_id:
                            hf = 'Y'
                            railway_user = ii['by_user']
                    if df == 'N':
                        division_of_user = find_div(rly_id)
                        if division_of_user == rly_id:
                            df = 'Y'
                            div_user = ii['by_user']

                if railway_user == None or div_user == None:
                    status10 = list(custom_filter(lambda x: x['status'] == 10, data))
                    
                    for ii in status10:
                        rly_id = ii['rly_id']
                        reply = ii['reply']
                        
                        if railway_user == None:
                            railway_of_user = find_railway(rly_id)
                            if railway_of_user == rly_id and reply == False:
                                hf = 'P'
                                railway_user = ii['by_user']
                            elif railway_of_user == rly_id and reply == True:
                                hf = 'R'
                                railway_user = ii['by_user']

                        if div_user == None:
                            division_of_user = find_div(rly_id)
                            if division_of_user == rly_id and reply == False:
                                df = 'P'
                                div_user = ii['by_user']
                            if division_of_user == rly_id and reply == True:
                                df = 'R'
                                div_user = ii['by_user']
                i.update({'hf': hf, 'df': df})
                if hf == 'Y' or df == 'Y' or hf == 'P' or df == 'P' or hf == 'R' or df == 'R':
                    vetted.append(i)
                else:
                    unvetted.append(i)
                
            else:
                unvetted.append(i)
                i.update({'hf':'N', 'df':'N'})

             
            finalized_data.append(i)

        if i['workflow_status'] == 2:
            rejected.append(i)
        elif i['workflow_status'] == 9:
            sanction.append(i)
        
        if i['MAVGMSANC'] == 'Y':
            gmpower.append(i)
        
        elif i['MAVDRMSANC'] == 'Y':
            drmpower.append(i)
        else:
            rbpower.append(i)

        if get_data != None:
            data = get_data['all_status']
            status5 = list(custom_filter(lambda x: x['status'] == 5, data))
            if len(status5):
                approved.append(i)

    obj13 = MEM_PRSLN_DRAFT.objects.exclude(MAVPRSLNO__in = [i['MAVDRFTPRSLNO'] for i in obj]).filter(delete_flag=False, created_by_user_id__MAV_userdesig = cuser.MAV_userdesig).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE_id__location_code','MAVDESC','MAVCATCODE','MAVALCNCODE_id__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVACTV','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1','MAVUSERCODE','MAVLOCN','created_by_user_id__MAV_userdesig')
    for i in obj13:
        i.update({'draft_type':'D'})
    draft_data.extend(obj13)

    draft_data = sorted(draft_data, key = lambda x: (x['MADVRSNDATETIME'],x['draft_type']), reverse = True)
    finalized_data = sorted(finalized_data, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    vetted = sorted(vetted, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    unvetted = sorted(unvetted, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)

    rejected = sorted(rejected, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    approved = sorted(approved, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    gmpower = sorted(gmpower, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    sanction = sorted(sanction, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)

    drmpower = sorted(drmpower, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    rbpower = sorted(rbpower, key = lambda x: (x['MADVRSNDATETIME']), reverse = True)
    context = {
        'username':cuser.MAV_userdesig,
        'obj': obj,
        'selected_year': selected_year,
        'selected_type': selected_type,
   
        'obj_all': len(obj),
        'draft_data':draft_data,
        'draft_data_len':len(draft_data),
        'finalized_data':finalized_data,
        'finalized_data_len':len(finalized_data),
        'vetted':vetted,
        'vetted_len':len(vetted),
        'unvetted':unvetted,
        'unvetted_len':len(unvetted), 
        'rejected':rejected,
        'rejected_len':len(rejected),

        'approved':approved,
        'approved_len':len(approved),
        'gmpower':gmpower,
        'gmpower_len':len(gmpower),
        'sanction':sanction,
        'sanction_len':len(sanction), 
        'drmpower':drmpower,
        'drmpower_len':len(drmpower),
        'rbpower':rbpower,
        'rbpower_len':len(rbpower),

        'cuser':cuser,
        'current_user_level_code': current_user_level_code,
    }
    
    return render(request, 'list_of_proposal.html', context)

def fetch_hist_data(request):
    proposal_number = request.GET.get("proposalNumber")
    apprs = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_number,MAVVTEDRMRK__isnull=False).values('MAVPRSLNO', 'MAVVTEDRMRK','MADVTEDDATE','MAVSMTDBY','MAVVTEDBY','MAVVTEDSTTS','MAVRPLY'))
    for appr in apprs:
        date_obj = appr['MADVTEDDATE']
        if date_obj:  # Ensure the date is not None
            appr['MADVTEDDATE'] = date_obj.strftime('%d-%m-%Y')

    return JsonResponse({"apprs": apprs})

def get_appr_data(request):
    proposal_number = request.GET.get("proposalNumber")
    appr = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_number).values('MADVTEDDATE').order_by("-MADVTEDDATE"))
    date = appr[0]['MADVTEDDATE']
    # appr = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_number,MADVTEDDATE=date).values('MAVPRSLNO', 'MAVVTEDRMRK','MADVTEDDATE','MAVSMTDBY','MAVVTEDBY','MAVVTEDSTTS','MAVRPLY').order_by("-MADVTEDDATE"))
    appr = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_number,MAVRPLY__isnull=True,MAVVTEDRMRK__isnull=False).values('MAVPRSLNO', 'MAVVTEDRMRK','MADVTEDDATE','MAVSMTDBY','MAVVTEDBY','MAVVTEDSTTS','MAVRPLY').order_by("-MADVTEDDATE"))
    return JsonResponse({'user':appr}, safe=False)


def hfsave(request):
    if request.method == 'POST' and request.is_ajax():
        reply = request.POST.get('reply')
        cdate = request.POST.get('cdate')
        submittedby = request.POST.get('submittedby')
        proposalNumber = request.POST.get('proposalNumber')
        mavvtedrmrk = request.POST.get('mavvtedrmrk')
        # Check if a record with the given proposal number exists
        id1 = list(MEM_usersn.objects.filter(MAV_userid=submittedby).values_list('MAV_userlvlcode_id', flat=True))
        print('jjjjjjjjjjjjjjj', id1)
        if id1:
            id1 = id1[0]
        existing_record = MED_PRSLVTED.objects.filter(MAVPRSLNO=proposalNumber, MAVVTEDRMRK=mavvtedrmrk).first()
        print("existing_recordexisting_recordexisting_recordexisting_record", existing_record)
        if existing_record:
            # If a record exists, update it
            existing_record.MAVRPLY = reply
            existing_record.MADSMTDDATE = cdate
            existing_record.MAVSMTDBY = submittedby
            if id1:
                user_level = MED_userlvls.objects.get(pk=id1)  # Retrieve the instance of MED_userlvls
                existing_record.MAVUSERLVLCODE = user_level

            existing_record.save()
        else:
            # If no record exists, create a new one
            if id1:
                user_level = MED_userlvls.objects.get(pk=id1)  # Retrieve the instance of MED_userlvls
                MED_PRSLVTED.objects.create(MAVPRSLNO=proposalNumber, MAVRPLY=reply, MADSMTDDATE=cdate, MAVSMTDBY=submittedby, MAVUSERLVLCODE=user_level)
        return JsonResponse({'success': 'Data saved successfully'}, safe=False)



def otherremarks(request):
    if request.method == 'POST' and request.is_ajax():
        reply = request.POST.get('reply')
        cdate = request.POST.get('cdate')
        submittedby = request.POST.get('submittedby')
        proposalNumber = request.POST.get('proposalNumber')
        MED_PRSLVTED.objects.create(MAVPRSLNO=proposalNumber, MAVOTHRRMRK=reply, MADSMTDDATE=cdate, MAVSMTDBY=submittedby)
        return JsonResponse({'success': 'Data saved successfully'}, safe=False)



        
def fetch_vetted_by(request):
    proposal_number = request.GET.get("proposalNumber")
    try:
        vetted_by = MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_number).values("id").exclude(MAVVTEDBY__isnull=True,MADVTEDDATE__isnull=True)

        # vetted_by = MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_number).values("id").order_by("-MADVTEDDATE")
        id = vetted_by[0]["id"]
        vetted_by = MED_PRSLVTED.objects.get(id=id)
        print('aaaaaaaaaaaaaaaaaa',vetted_by)
        data = {
            "MAVVTEDBY": vetted_by.MAVVTEDBY,
            "MADVTEDDATE": vetted_by.MADVTEDDATE
           
            # "MADVTEDDATE": vetted_by.MADVTEDDATE.strftime("%Y-%m-%d %H:%M:%S") 
        }
        return JsonResponse(data)
    except MED_PRSLVTED.DoesNotExist:
        return JsonResponse({"MAVVTEDBY": "","MADVTEDDATE":""})


def list_of_proposal_divi_pdf(request):
    current_year = datetime.datetime.now().year
    years = list(range(2011, current_year + 1))
    years.reverse()  
    if request.method == 'POST':
        selected_status = request.POST.get('current_status')
    statuses = MEM_PRSLTHRWFRWDEVNT.objects.values_list('MAVEVNTDESC', flat=True)
    purchases = MED_PRSLTHRWFRWD.objects.values_list('MAVPRCHFROM', flat=True).distinct()
    allocations = MED_ALCNN.objects.values_list('MAVALCN', flat=True).distinct()
    progs =  MEM_PRSLPRGS.objects.values_list('MAVDESC', flat=True).distinct()

    data = MED_PRSLTHRWFRWD.objects.values('MAVFINYEAR','MAVDESC', 'MAVCNSE', 'MAVQTY', 'MAVPRCHFROM', 'MAVSCNDCOST', 'MAVABOV', 'MAVLTSTATPDCOST', 'MAVBLNCTOCOMPWORK','MAVRMRK','MAVSTTS','MAVCURRSTTS','MAVTOTLEXPDINCR','MAVALCN').all()
    context = {
    'years': years,
    'statuses': statuses,
    'purchases': purchases,
    'allocations': allocations,
    'obj':data,
    'progs':progs,
    }
    template_src='list_of_proposal_divi_pdf.html'
    return render_to_pdf(template_src, context)


# views.py
def cpd(request):
    # Retrieve the selectedProposalNumbers from the URL parameter
    selectedProposalNumbers = request.GET.get('proposalNumbers', '')

    # Split the selectedProposalNumbers on the basis of a comma (,)
    selectedProposalNumbers = selectedProposalNumbers.split(',')
    
    # Remove empty strings from the list
    selectedProposalNumbers = [number.strip() for number in selectedProposalNumbers if number.strip()]
    
    print("Selected Proposal Numbers:", selectedProposalNumbers)  # Debugging

    if selectedProposalNumbers:
        # Initialize empty lists to store results
        obj10_list = []
        obj11_list = []
        obj3_list = []
        obj12_list = []

        # Loop through each proposal number
        for proposal_number in selectedProposalNumbers:
            # If proposal_number is not empty
            if proposal_number:
                # Debugging
                print(f"Processing Proposal Number: {proposal_number}")

                # Filter your queryset based on the current proposal_number
                obj10 = MED_ASSTRGNN.objects.filter(MAVPRSLNO=proposal_number).values('MAVPRSLNO', 'MAV_ITEMNAME', 'MAVITEMCODE', 'MAVDESC', 'MAIEXPLIFE', 'MAICOST', 'MAVHIDESC').distinct()
                print("honeyyyyyyyyy", obj10)  # Debugging

                # Append data from MEM_PRSLN to obj10
                mem_prsln_data = MEM_PRSLN.objects.filter(MAVPRSLNO=proposal_number).values('MANQTY', 'MANCOST', 'MAVALCNCODE__MAVALCN')
                print("MEM_PRSLN Data:", mem_prsln_data)  # Debugging

                for item in obj10:
                    item['MANQTY'] = mem_prsln_data[0]['MANQTY']
                    item['MANCOST'] = mem_prsln_data[0]['MANCOST']
                    item['MAVALCNCODE__MAVALCN'] = mem_prsln_data[0]['MAVALCNCODE__MAVALCN']

                obj11 = MEM_PRSLN.objects.filter(MAVPRSLNO=proposal_number).values('MAVPRSLNO', 'MANVRSNNO', 'MAVDESC', 'MAVPRCHFROM').all()
                print("sharmaaaaa", obj11)  # Debugging

                # Fetch MARRORPER data from MED_PRSLRORN table
                marrorper_data = MED_PRSLRORN.objects.filter(MAVPRSLNO=proposal_number).values('MARRORPER')
                print("MARRORPER Data:", marrorper_data)  # Debugging

                obj12= MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=proposal_number).values('MANSIFTNO', 'MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL','MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB').distinct()
                print("hooooooooooooooooooo", obj12)  # Debugging

                obj3 = MED_PRSLJSTN.objects.filter(MAVPRSLNO=proposal_number).values('MATJSFN', 'MAVPRSLNO').distinct()
                print("hiiiiiiiiiiiii", obj3)  # Debugging

                # Create a dictionary to map MAVPRSLNO to MATJSFN
                mavprslno_to_matjsfn = {item['MAVPRSLNO']: item['MATJSFN'] for item in obj3}

                # Update obj11 with MATJSFN values
                for item in obj11:
                    mavprslno = item['MAVPRSLNO']
                    if mavprslno in mavprslno_to_matjsfn:
                        item['MATJSFN'] = mavprslno_to_matjsfn[mavprslno]

                # Append the results to the respective lists
                obj10_list.extend(obj10)
                obj11_list.extend(obj11)
                obj3_list.extend(obj3)
                obj12_list.extend(obj12)

                # Append the MARRORPER data to obj11_list
                if marrorper_data:
                    for item in obj11:
                        item['MARRORPER'] = marrorper_data[0]['MARRORPER']

        # Debugging: Print the final context before rendering
        print("Final Context:")
        print("obj10_list:", obj10_list)
        print("obj11_list:", obj11_list) 
        print("obj12_list:", obj12_list)

        context = {
            'obj10': obj10_list,
            'obj11': obj11_list,
            'obj12': obj12_list,
        }
        return render(request, 'cpd.html', context)
    else:
        # If selectedProposalNumbers is not provided, handle the case accordingly
        return render(request, 'error.html', {'error_message': 'No proposal numbers provided in the URL.'})

    # template_src='cpd.html'
    # return render_to_pdf(template_src, context)
# def cpd(request):
#     obj10 = MED_ASSTRGNN.objects.filter(delete_flag=False).values('MAVPRSLNO_id','MAV_ITEMNAME','MAVITEMCODE','MAVDESC','MAIEXPLIFE','MAICOST','MAVHIDESC').all() 
#     print(obj10,'idffdd')
#     obj11=prsl_list.objects.values('prsl_no','vrsn_no').all()
#     print(obj11,'id')
#     obj1=MED_ASSTRGNN.objects.values('MAVDESC').all()
#     print(obj1,'idf')
#     obj2=prsl_list.objects.values('prch_from').all
#     print(obj2,'idff')
#     context={
#         'obj10':obj10,
#         'obj11':obj11,
#         'obj1':obj1,
#         'obj2':obj2,
   
#     }
#     return render(request,'cpd.html',context)

def generate_pdf(request):
    # Fetch data from the MEM_PRSLN table
    proposals = MEM_PRSLN.objects.values('MAVPRSLNO', 'MANVRSNNO', 'MAVPRSLTYPE', 'MAVADDNRPLC','MADVRSNDATETIME','status_flag1')  # You can add more filtering conditions if needed
    print("llllllllllllllll", proposals)
    
    obj10 = MED_ASSTRGNN.objects.values('MAVPRSLNO','MAVITEMCODE', 'MAVHIDESC', 'MAV_ITEMNAME', 'MAVITEMCODE', 'MAVDESC', 'MAIEXPLIFE', 'MAICOST').distinct()
    print("honeyyyyyyyyy", obj10)  # Debugging
    
    mem_prsln_data = MEM_PRSLN.objects.values('MAVPRSLNO','MANQTY', 'MANCOST', 'MAVALCNCODE__MAVALCN', 'MAVCNSN','MAVLOCN', 'MAVSHRTDESC','MAVDEPTCODE_id__MAVDEPTNAME')
    print("MEM_PRSLN Data:", mem_prsln_data)  # Debugging

    # Calculate and store the absolute difference in each item in obj10
    for item in obj10:
        
        item['MAVPRSLNO'] = mem_prsln_data[0]['MAVPRSLNO']
        item['MANQTY'] = mem_prsln_data[0]['MANQTY']
        item['MANCOST'] = mem_prsln_data[0]['MANCOST']
        item['MAVALCNCODE__MAVALCN'] = mem_prsln_data[0]['MAVALCNCODE__MAVALCN']
        item['MAVCNSN'] = mem_prsln_data[0]['MAVCNSN']
        item['MAVLOCN'] = mem_prsln_data[0]['MAVLOCN']
        item['MAVSHRTDESC'] = mem_prsln_data[0]['MAVSHRTDESC']
        item['MAVDEPTCODE_id__MAVDEPTNAME'] = mem_prsln_data[0]['MAVDEPTCODE_id__MAVDEPTNAME']

        # Calculate the absolute difference
        maicost = float(item['MAICOST'])
        mancost = float(item['MANCOST'])
        item['DIFFERENCE'] = abs(maicost - mancost)

    cost_data = MED_PRSLCOST.objects.values('MANPRSNNO','MANCPAMNT')
    print("hhhhhhhhhhhhhhhhhhhhhh", cost_data)

    mem_prsln_costs = MEM_PRSLN.objects.values('MANBASCCOST', 'MANTTLCOST')

    # Extract MANCPAMNT values from cost_data
    existing_cost_data = [item['MANCPAMNT'] for item in cost_data]

    # Append MANBASCCOST and MANTTLCOST values to cost_data
    for index, cost_item in enumerate(cost_data):
        if index < len(mem_prsln_costs):
            # cost_item['MAVPRSLNO'] = mem_prsln_costs[index]['MAVPRSLNO']
            cost_item['MANBASCCOST'] = mem_prsln_costs[index]['MANBASCCOST']
            cost_item['MANTTLCOST'] = mem_prsln_costs[index]['MANTTLCOST']
        else:
            # cost_item['MAVPRSLNO'] = mem_prsln_costs[index]['MAVPRSLNO']
            cost_item['MANBASCCOST'] = None  # Handle the case where data is missing
            cost_item['MANTTLCOST'] = None

    obj = MED_PRSLJSTN.objects.values('MAVPRSLNO','MATJSFN')

    # Enumerate the obj data to add a serial number
    obj_with_serial = [{'serial_number': index + 1, 'MATJSFN': item['MATJSFN']} for index, item in enumerate(obj)]

    # Assuming obj1 and obj2 are lists of dictionaries
    obj1 = MED_PRSLRORN.objects.values('MAVPRSLNO','MARRORPER', 'MATRORDETL')
    obj2 = MED_PRSLRPLCDTLS.objects.values('MAVPRSLNO','MAVJOBLOAD', 'MAVWORKLOAD', 'MAVTOTLSMLRMACN', 'MAVCAPSHRTFALL')

    combined_data = []

    # Determine the minimum length of obj1 and obj2
    min_length = min(len(obj1), len(obj2))

    # Combine the data up to the length of the shorter list
    for i in range(min_length):
        combined_data.append({
            'obj1': obj1[i],
            'obj2': obj2[i],
        })

    # Append any remaining elements from obj1
    for i in range(min_length, len(obj1)):
        combined_data.append({
            'obj1': obj1[i],
            'obj2': None,  # Placeholder for obj2 when obj1 is longer
        })

    # Append any remaining elements from obj2
    for i in range(min_length, len(obj2)):
        combined_data.append({
            'obj1': None,  # Placeholder for obj1 when obj2 is longer
            'obj2': obj2[i],
        })
    obj12= MED_PRSLRPLCDTLS.objects.values('MAVPRSLNO','MANSIFTNO', 'MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL','MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB').distinct()
    print("hooooooooooooooooooo", obj12)  # Debugging
    obj3= MED_PRSLUPLDFILE.objects.values('MAVPRSLNO','MAVPDFNAME','MAVORGPDFNAME')



    # Provide the combined data to the template
    context = {
        'proposals': proposals,
        'obj10': obj10,
        'cost_data': cost_data,
        'obj': obj_with_serial,
        'combined_data': combined_data,
        'obj12':obj12,
        'obj3':obj3,
    }

    return render(request, 'generatepdf.html', context)
    

def itemcostdetails(request):
    # Retrieve the selectedProposalNumbers from the URL parameter
    selectedProposalNumbers = request.GET.get('proposalNumbers', '')

    # Split the selectedProposalNumbers on the basis of a comma (,)
    selectedProposalNumbers = selectedProposalNumbers.split(',')
    
    # Remove empty strings from the list
    selectedProposalNumbers = [number.strip() for number in selectedProposalNumbers if number.strip()]
    
    print("Selected Proposal Numbers:", selectedProposalNumbers)  # Debugging

    if selectedProposalNumbers:
        # Initialize empty lists to store results
        obj10_list = []
        obj11_list = []
        obj3_list = []
        obj12_list = []

        # Loop through each proposal number
        for proposal_number in selectedProposalNumbers:
            # If proposal_number is not empty
            if proposal_number:
                # Debugging
                print(f"Processing Proposal Number: {proposal_number}")

                # Filter your queryset based on the current proposal_number
                obj10 = MED_ASSTRGNN.objects.filter(MAVPRSLNO=proposal_number).values('MAVPRSLNO', 'MAV_ITEMNAME', 'MAVITEMCODE', 'MAVDESC', 'MAIEXPLIFE', 'MAICOST', 'MAVHIDESC').distinct()
                print("honeyyyyyyyyy", obj10)  # Debugging

                # Append data from MEM_PRSLN to obj10
                mem_prsln_data = MEM_PRSLN.objects.filter(MAVPRSLNO=proposal_number).values('MANQTY', 'MANCOST', 'MAVALCNCODE__MAVALCN')
                print("MEM_PRSLN Data:", mem_prsln_data)  # Debugging

                for item in obj10:
                    item['MANQTY'] = mem_prsln_data[0]['MANQTY']
                    item['MANCOST'] = mem_prsln_data[0]['MANCOST']
                    item['MAVALCNCODE__MAVALCN'] = mem_prsln_data[0]['MAVALCNCODE__MAVALCN']

                obj11 = MEM_PRSLN.objects.filter(MAVPRSLNO=proposal_number).values('MAVPRSLNO', 'MANVRSNNO', 'MAVDESC', 'MAVPRCHFROM').all()
                print("sharmaaaaa", obj11)  # Debugging

                # Fetch MARRORPER data from MED_PRSLRORN table
                marrorper_data = MED_PRSLRORN.objects.filter(MAVPRSLNO=proposal_number).values('MARRORPER')
                print("MARRORPER Data:", marrorper_data)  # Debugging

                obj12= MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO=proposal_number).values('MANSIFTNO', 'MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL','MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB').distinct()
                print("hooooooooooooooooooo", obj12)  # Debugging

                obj3 = MED_PRSLJSTN.objects.filter(MAVPRSLNO=proposal_number).values('MATJSFN', 'MAVPRSLNO').distinct()
                print("hiiiiiiiiiiiii", obj3)  # Debugging

                # Create a dictionary to map MAVPRSLNO to MATJSFN
                mavprslno_to_matjsfn = {item['MAVPRSLNO']: item['MATJSFN'] for item in obj3}

                # Update obj11 with MATJSFN values
                for item in obj11:
                    mavprslno = item['MAVPRSLNO']
                    if mavprslno in mavprslno_to_matjsfn:
                        item['MATJSFN'] = mavprslno_to_matjsfn[mavprslno]

                # Append the results to the respective lists
                obj10_list.extend(obj10)
                obj11_list.extend(obj11)
                obj3_list.extend(obj3)
                obj12_list.extend(obj12)

                # Append the MARRORPER data to obj11_list
                if marrorper_data:
                    for item in obj11:
                        item['MARRORPER'] = marrorper_data[0]['MARRORPER']

        # Debugging: Print the final context before rendering
        print("Final Context:")
        print("obj10_list:", obj10_list)
        print("obj11_list:", obj11_list) 
        print("obj12_list:", obj12_list)

        context = {
            'obj10': obj10_list,
            'obj11': obj11_list,
            'obj12': obj12_list,
        }
        return render(request, 'itemcostdetails.html', context)
    else:
        # If selectedProposalNumbers is not provided, handle the case accordingly
        return render(request, 'error.html', {'error_message': 'No proposal numbers provided in the URL.'})


def Quantitydetails(request):
    # Retrieve the selectedProposalNumbers from the URL parameter
    selectedProposalNumbers = request.GET.get('proposalNumbers', '')

    # Split the selectedProposalNumbers on the basis of a comma (,)
    selectedProposalNumbers = selectedProposalNumbers.split(',')

    # Remove empty strings from the list
    selectedProposalNumbers = [number.strip() for number in selectedProposalNumbers if number.strip()]
    
    print("Selected Proposal Numbers:", selectedProposalNumbers)  # Debugging

    if selectedProposalNumbers:
        manqty_data = MEM_PRSLN.objects.filter(MAVPRSLNO__in=selectedProposalNumbers, delete_flag=False).values('MAVPRSLNO','MANBASCCOST', 'MANQTY', 'MANCOST', 'MANTTLCOST')
        print(manqty_data, 'sharma')
        
        obj = MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO__in=selectedProposalNumbers).values('MAVPRSLNO','MAVORGPDFNAME', 'MAVPDFNAME')
        print(obj, 'sharmaaaaaaaaaaaaa')
        
        context = {
            'manqty_data': manqty_data,
            'obj': obj,
        }
        return render(request, 'Quantitydetails.html', context)
    else:
        # If selectedProposalNumbers is not provided, handle the case accordingly
        return render(request, 'error.html', {'error_message': 'No proposal numbers provided in the URL.'})

def listofcp(request):
     # Retrieve the selectedProposalNumbers from the URL parameter
    selectedProposalNumbers = request.GET.get('proposalNumbers', '')

    # Split the selectedProposalNumbers on the basis of a comma (,)
    selectedProposalNumbers = selectedProposalNumbers.split(',')

    # Remove empty strings from the list
    selectedProposalNumbers = [number.strip() for number in selectedProposalNumbers if number.strip()]
    
    print("Selected Proposal Numbers:", selectedProposalNumbers)  # Debugging

    if selectedProposalNumbers:
        manqty_data = MEM_PRSLN.objects.filter(MAVPRSLNO__in=selectedProposalNumbers, delete_flag=False).values('MAVPRSLNO','MANBASCCOST', 'MANQTY', 'MANCOST', 'MANTTLCOST')
        print(manqty_data, 'sharma')
        
        context = {
            'manqty_data': manqty_data,
        }
        return render(request, 'listofcp.html', context)
    else:
        # If selectedProposalNumbers is not provided, handle the case accordingly
        return render(request, 'error.html', {'error_message': 'No proposal numbers provided in the URL.'})

def RORR(request):
    # Retrieve the selectedProposalNumbers from the URL parameter
    selectedProposalNumbers = request.GET.get('proposalNumbers', '')

    # Split the selectedProposalNumbers on the basis of a comma (,)
    selectedProposalNumbers = selectedProposalNumbers.split(',')

    # Remove empty strings from the list
    selectedProposalNumbers = [number.strip() for number in selectedProposalNumbers if number.strip()]
    
    print("Selected Proposal Numbers:", selectedProposalNumbers)  # Debugging

    if selectedProposalNumbers:
        # Filter your queryset based on the selectedProposalNumbers
        cost_data = MED_PRSLCOST.objects.filter(MANPRSNNO__in=selectedProposalNumbers).values('MANPRSNNO','MANCPAMNT')
        print("hhhhhhhhhhhhhhhhhhhhhh", cost_data)
        
        context = {
            'cost_data': cost_data,
        }
        return render(request, 'RORR.html', context)
    else:
        # If selectedProposalNumbers is not provided, handle the case accordingly
        return render(request, 'error.html', {'error_message': 'No proposal numbers provided in the URL.'})


    
def proposaljustification(request):
    return render(request,'proposaljustification.html')

def deleteview1(request):
    if request.method == "GET" and request.is_ajax():
        print("hii")
        id3 = request.GET.get('ID')
        print(id3,"hlo")
        MEM_PRSLN.objects.filter(ID=id3).update(delete_flag=True)
        print("ofgt")
        return JsonResponse({"success":"deleted successfully"}, safe=False)

def deleteview3(request):
    if request.method == "GET" and request.is_ajax():
        id4= request.GET.get('ID')
        MEM_PRSLN_DRAFT.objects.filter(ID=id4).update(delete_flag=True)
        try:
            pk = list(MEM_PRSLN_DRAFT.objects.filter(ID=id4).values('MAVPRSLNO'))[0]['MAVPRSLNO']
        except:
            pk = 0
        MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = pk).delete()
        MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
        MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
        MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
        MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO=pk).delete()
        return JsonResponse({"success":"deleted successfully"}, safe=False)

def add_newitem(request):
    if request.method == "GET" and request.is_ajax():
        ids = request.GET.get('ID')
        print(ids,"thisis my ids")
        obj = list(MEM_PRSLN.objects.filter(ID=ids).values_list('MAVPRSLNO','MAVPRCHFROM','MAVALCNCODE_id__MAVALCN','MAIFINYEAR','MAVCNSN', 'MANTTLCOST', 'MANQTY', 'MAVDESC', 'MAVRLYCODE'))
        # obj = list(MEM_PRSLN.objects.filter(ID=ids).values_list('MAVPRSLNO_id','MAVPRCHFROM','MAVALCNCODE_id__MAVALCN','MAVPRSLNO__f_year','MAVPRSLNO__consinee','MAVPRSLNO__sanc_cost','MAVPRSLNO__above','MAVPRSLNO__quantity','MAVPRSLNO__Des','MAVPRSLNO__railcode'))
        print(obj,"This is object")
        return JsonResponse({'obj':obj}, safe=False)

def mysave1(request):
    if request.method == 'GET' and request.is_ajax():
        financialyear = request.GET.get('financialyear')
        rail= request.GET.get('rail')
        proposal_n=request.GET.get('proposal_n')
        desc = request.GET.get('desc')
        consignee = request.GET.get('consignee')
        quantity = request.GET.get('quantity')
        processed = request.GET.get('processed')
        current_status = request.GET.get('current_status')
        Sanctioned = request.GET.get('Sanctioned')
        above25 = request.GET.get('above25')
        latestAnticipated = request.GET.get('latestAnticipated')
        balance = request.GET.get('balance')
        remark = request.GET.get('remark')
        status = request.GET.get('status')
        totalExpenditure = request.GET.get('totalExpenditure')
        allocation = request.GET.get('allocation')

        MED_PRSLTHRWFRWD.objects.create(MAVFINYEAR=financialyear,MAVRAILCODE=rail,MAVPRSLNUM=proposal_n,MAVDESC=desc,MAVCNSE=consignee,MAVQTY=quantity, MAVPRCHFROM= processed,MAVCURRSTTS=current_status,MAVSCNDCOST=Sanctioned,MAVABOV=above25,MAVLTSTATPDCOST=latestAnticipated, MAVBLNCTOCOMPWORK=balance,MAVRMRK=remark,MAVSTTS=status,MAVTOTLEXPDINCR=totalExpenditure,MAVALCN =allocation)
        return JsonResponse({'success':'my data is saved'},safe=False)

def submit_proposal(request):
    if request.method == 'GET' and request.is_ajax():
        proposal_id = request.GET.get('IDS')
        
        # Assuming the 'status_flag1' field is an IntegerField in the model
        # Retrieve the proposal object and update the status_flag1
        try:
            proposal = MEM_PRSLN.objects.get(ID=proposal_id)
            if proposal.status_flag1 == 0:
                # Update status_flag1 to 1 if it is 0
                proposal.status_flag1 = 1
                proposal.save()
                return JsonResponse({"success": "Status updated successfully"}, safe=False)
            else:
                # Status is not changed since it is not 0
                return JsonResponse({"message": "Status remains unchanged"}, status=400)
        except MEM_PRSLN.DoesNotExist:
            # Proposal not found
            return JsonResponse({"message": "Proposal not found"}, status=404)

    # Handle other HTTP methods or non-AJAX requests
    return JsonResponse({"message": "Invalid request"}, status=400)


def submitt_proposal1(request):
    if request.method == 'GET' and request.is_ajax():
        cuser = request.user
        current_user_level_code = list(MEM_usersn.objects.filter(MAV_userid=cuser).values_list('MAV_userlvlcode_id', flat=True))[0]
        print("tttttttttttttt", current_user_level_code)
        ids = request.GET.get('ids')
        print('IDS iDS', ids)
        
        if ids:
            try:
                # Convert the comma-separated IDs to a list of integers
                proposal_ids = [int(id) for id in ids.split(',')]

                # Define the default status_flag value
                new_status_flag = 6

                # Check the current_user_level_code and update new_status_flag accordingly
                if current_user_level_code == '21':
                    new_status_flag = 11
                    MEM_PRSLN.objects.filter(ID__in=proposal_ids, status_flag1=3).update(status_flag1=new_status_flag)


                # Update the status_flag1 for the selected proposals
                MEM_PRSLN.objects.filter(ID__in=proposal_ids, status_flag1=4).update(status_flag1=new_status_flag)
                MEM_PRSLN.objects.filter(ID__in=proposal_ids, status_flag1=1).update(status_flag1=new_status_flag)

                return JsonResponse({"success": f"Selected proposals updated successfully to status_flag1={new_status_flag}"}, safe=False)
            except ValueError:
                return JsonResponse({"error": "Invalid Proposal IDs"}, status=400)
        else:
            return JsonResponse({"error": "Invalid request method or not an AJAX request"}, status=400)
    else:
        return JsonResponse({"error": "Invalid request method or not an AJAX request"}, status=400)


def list_of_proposal_for_edting(request):
    return render(request, 'list_of_proposal_for_edting.html')



def covernote(request):
    return render(request,'covernote.html')
    
def covernote_pdf(request):
    abs_path=os.path.abspath('static/images/picture.png')
    context = {
    'abs_path':abs_path,
    }
    template_src='covernotepdf.html'
    return render_to_pdf(template_src, context)

def printtdocuments(request):
    return render(request,'printtdocuments.html')
def print1(request):
    return render(request,'print1.html')

import datetime
def get_current_financial_year():
    today = datetime.date.today()
    if today.month >= 4:  # Assuming the financial year starts from April
        start_year = today.year
    else:
        start_year = today.year - 1
    return start_year

def monthly_progress(request):
    current_year = get_current_financial_year()
    years = range(2011, current_year + 1)[::-1]  # Reversed list of years

    selected_year = request.GET.get('year-dropdown')  # Assuming the year dropdown has name="year-dropdown"

    if selected_year:
        data = MED_MNTYPRGS.objects.filter(MAVFINYEAR__startswith=selected_year)
    else:
        data = MED_MNTYPRGS.objects.none()
    data = MED_MNTYPRGS.objects.values('MAVFINYEAR','MAIMACCFMW', 'MAIMACCFMWEXPD', 'MAISUPPCFMW', 'MAIMACSUPPCOFEXPD', 'MAIMACCOS', 'MAIMACCOSEXPD', 'MAIMACSUPPCOS', 'MAIMACSUPPCOSEXPD').all()
    cursor = connection.cursor()
    cursor.execute(
    '''SELECT "MAVFINYEAR", COUNT(*) FROM mnprsp."mnpapp_med_mntyprgs" GROUP BY "MAVFINYEAR" ;''')
    d = cursor.fetchall()
    list1 = []
    list2 = []
    for i in d:
        list1.append(i[0])
        list2.append(i[1])
    context = {
        'years': years,
        'obj': data,
        'list1': list1,
        'list2': list2,
    }
    return render(request, 'monthly_progress.html', context)


def monthly_progress_pdf(request):
    abs_path=os.path.abspath('static/images/picture.png')

    current_year = get_current_financial_year()
    years = range(2011, current_year + 1)[::-1]  # Reversed list of years

    selected_year = request.GET.get('year-dropdown')  # Assuming the year dropdown has name="year-dropdown"

    if selected_year:
        data = MED_MNTYPRGS.objects.filter(MAVFINYEAR__startswith=selected_year)
    else:
        data = MED_MNTYPRGS.objects.none()
    data = MED_MNTYPRGS.objects.values('MAVFINYEAR','MAIMACCFMW', 'MAIMACCFMWEXPD', 'MAISUPPCFMW', 'MAIMACSUPPCOFEXPD', 'MAIMACCOS', 'MAIMACCOSEXPD', 'MAIMACSUPPCOS', 'MAIMACSUPPCOSEXPD').all()
    cursor = connection.cursor()
    cursor.execute(
    '''SELECT "MAVFINYEAR", COUNT(*) FROM mnprsp."mnpapp_med_mntyprgs" GROUP BY "MAVFINYEAR" ;''')
    d = cursor.fetchall()
    list1 = []
    list2 = []
    for i in d:
        list1.append(i[0])
        list2.append(i[1])
    context = {
        'abs_path':abs_path,
        'years': years,
        'obj': data,
        'list1': list1,
        'list2': list2,
    }
    template_src='monthly_progress_pdf.html'
    return render_to_pdf(template_src, context)

    # return render(request,'monthly_progress_pdf.html',context)

def monthly_progress_excel(request):
    current_year = get_current_financial_year()
    years = range(2011, current_year + 1)[::-1]  # Reversed list of years

    selected_year = request.GET.get('year-dropdown')  # Assuming the year dropdown has name="year-dropdown"

    if selected_year:
        data = MED_MNTYPRGS.objects.filter(MAVFINYEAR__startswith=selected_year)
    else:
        data = MED_MNTYPRGS.objects.none()
    data = MED_MNTYPRGS.objects.values('MAVFINYEAR','MAIMACCFMW', 'MAIMACCFMWEXPD', 'MAISUPPCFMW', 'MAIMACSUPPCOFEXPD', 'MAIMACCOS', 'MAIMACCOSEXPD', 'MAIMACSUPPCOS', 'MAIMACSUPPCOSEXPD').all()
    cursor = connection.cursor()
    cursor.execute(
    '''SELECT "MAVFINYEAR", COUNT(*) FROM mnprsp."mnpapp_med_mntyprgs" GROUP BY "MAVFINYEAR" ;''')
    d = cursor.fetchall()
    list1 = []
    list2 = []
    for i in d:
        list1.append(i[0])
        list2.append(i[1])
    context = {
        'years': years,
        'obj': data,
        'list1': list1,
        'list2': list2,
    }
    import xlwt
    from xlwt import Workbook
    from django.http import HttpResponse
    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename="MonthlyProgressReport.xls"'
    wb = Workbook()
    sheet1 = wb.add_sheet('Sheet 1')
    style = xlwt.easyxf("alignment: wrap off;font: bold on;borders: top_color black, bottom_color black, right_color black, left_color black;")
    style1 = xlwt.easyxf("alignment: wrap off;borders: top_color black, bottom_color black, right_color black, left_color black;")
    style2 = xlwt.easyxf("alignment: wrap off;font: bold on;")
    heading1 = "Machinery and Plant Portal"
    row = 1
    col =4
    sheet1.write_merge(row, row , col, col + 1, heading1, style=style2)
    row = 4
    col = 4
    sheet1.write(row, col, 'Monthly Progress Report', style=style2)
    row = 6
    col = 0
    attributes = ["S.no","Financial year","No.of machines to be supplied by COFMOW", "Expendt. on COFMOW M/cs. (Rs. in lakhs)", "No.of machines supplied by COFMOW", "Expendt. on COFMOW M/cs. (Rs. in lakhs)", "No.of machines to be supplied by COS", "Expendt. on COS M/cs. (Rs. in lakhs)", "No.of machines supplied by COFMOW","Expendt. on COFMOW M/cs. (Rs. in lakhs)","Total No. of machines received (3+7)","Total Expendt. booked (Rs. in lakhs) (4+8)"]
    col_width = {col:len(attr)for col, attr in enumerate(attributes)}
    for idx, attribute in enumerate(attributes):
        sheet1.write_merge(row, row + 0, col, col, attribute, style=style)
        col_width[col] = max(col_width[col],len(attribute))
        col += 1

    data = context['obj']
    row = 7

    for index, item in enumerate(data, start=1):
        sheet1.write(row, 0, index, style=style1)
        sheet1.write(row, 1, item['MAVFINYEAR'], style=style1)
        sheet1.write(row, 2, item['MAIMACCFMW'], style=style1)
        sheet1.write(row, 3, item['MAIMACCFMWEXPD'], style=style1)
        sheet1.write(row, 4, item['MAISUPPCFMW'], style=style1)
        sheet1.write(row, 5, item['MAIMACSUPPCOFEXPD'], style=style1)
        sheet1.write(row, 6, item['MAIMACCOS'], style=style1)
        sheet1.write(row, 7, item['MAIMACCOSEXPD'], style=style1)
        sheet1.write(row, 8, item['MAIMACSUPPCOS'], style=style1)
        sheet1.write(row, 9, item['MAIMACSUPPCOSEXPD'], style=style1)
        mac_supp_sum = item['MAISUPPCFMW'] + item['MAIMACSUPPCOS']
        sheet1.write(row, 10, mac_supp_sum, style=style1)
    
        # Calculate the sum of MacSuppCofExp and MacSuppCosExp
        mac_supp_exp_sum = item['MAIMACSUPPCOFEXPD'] + item['MAIMACSUPPCOSEXPD']
        sheet1.write(row, 11, mac_supp_exp_sum, style=style1)
        row += 1
        content_list = [
        index, item['MAVFINYEAR'], item['MAIMACCFMW'], item['MAIMACCFMWEXPD'],
        item['MAISUPPCFMW'], item['MAIMACSUPPCOFEXPD'],
        item['MAIMACCOS'], item['MAIMACCOSEXPD'],
        item['MAIMACSUPPCOS'], item['MAIMACSUPPCOSEXPD'],
        mac_supp_sum, mac_supp_exp_sum
    ]

    for col, content in enumerate(content_list):
        sheet1.write(row, col, content, style=style1)

    row += 1
    for col,width in col_width.items():
        sheet1.col(col).width=(width + 4)* 256        
    wb.save(response)
    return response



#nandini
# def add_asset(request):
#     item =MEM_ITEMMSTN.objects.filter().values('MAV_ITEM_NAME')
#     obj = MED_ASSTRGNN.objects.filter().values('MAVASSTCODE','MAV_ITEMNAME','MAVITEMCODE','MAIYEARPURC','MAVHIDESC','MAICOST','MAIEXPLIFE','MAVDVSNCODE','MAVDEPTCODE_id__MAVDEPTNAME','STATUS')
#     print(item,"itemmm")
#     context = {
#     'item':item,
#     'obj':obj,
#     }
#     return render(request,'add_asset.html',context)
# def add_asset_excel(request):
#     item =MEM_ITEMMSTN.objects.filter().values('MAV_ITEM_NAME')
#     obj = MED_ASSTRGNN.objects.filter().values('MAVASSTCODE','MAV_ITEMNAME','MAVITEMCODE','MAIYEARPURC','MAVHIDESC','MAICOST','MAIEXPLIFE','MAVDVSNCODE','MAVDEPTCODE','STATUS')
#     print(item,"itemmm")
#     context = {
#     'item':item,
#     'obj':obj,
#     }
#     # return render(request,'add_asset.html',context)

#     import xlwt
#     from xlwt import Workbook
#     from django.http import HttpResponse
#     response = HttpResponse(content_type='application/ms-excel')
#     response['Content-Disposition'] = 'attachment; filename="AddAssetReport.xls"'
#     wb = Workbook()
#     sheet1 = wb.add_sheet('Sheet 1')
#     style = xlwt.easyxf("alignment: wrap off;font: bold on;borders: top_color black, bottom_color black, right_color black, left_color black;")
#     style1 = xlwt.easyxf("alignment: wrap off;borders: top_color black, bottom_color black, right_color black, left_color black;")
#     style2 = xlwt.easyxf("alignment: wrap off;font: bold on;")
#     heading1 = "Machinery and Plant Portal"
#     row = 1
#     col =4
#     sheet1.write_merge(row, row , col, col + 1, heading1, style=style2)
#     row = 4
#     col = 4
#     sheet1.write(row, col, 'Add Asset Report', style=style2)
    
#     row = 6
#     col = 0
#     attributes = ["S.no","Category", "Local Plant No.", "Year of Purchase", "Cost", "Expected Life", "Division", "Department","Status"]
#     col_width = {col:len(attr)for col, attr in enumerate(attributes)}
#     for idx, attribute in enumerate(attributes):
#         sheet1.write_merge(row, row + 0, col, col, attribute, style=style)
#         col_width[col] = max(col_width[col],len(attribute))
#         col += 1

#     data = context['obj']
#     row = 7
#     for index, item in enumerate(data, start=1):
#         sheet1.write(row, 0, index, style=style1)
#         sheet1.write(row, 1, item['MAV_ITEMNAME'], style=style1)
#         sheet1.write(row, 2, item['MAVITEMCODE'], style=style1)
#         sheet1.write(row, 3, item['MAIYEARPURC'], style=style1)
#         sheet1.write(row, 4, item['MAICOST'], style=style1)
#         sheet1.write(row, 5, item['MAIEXPLIFE'], style=style1)
#         sheet1.write(row, 6, item['MAVDVSNCODE'], style=style1)
#         sheet1.write(row, 7, item['MAVDEPTCODE'], style=style1)
#         sheet1.write(row, 8, item['STATUS'], style=style1)
        
#         for col, content in enumerate([index,item['MAV_ITEMNAME'],item['MAVITEMCODE'], item['MAIYEARPURC'],item['MAICOST'],item['MAIEXPLIFE'],item['MAVDVSNCODE'],item['MAVDEPTCODE'],item['STATUS']]):
#             col_width[col]=max (col_width[col],len(str(content)))
#         row += 1

#     for col,width in col_width.items():
#         sheet1.col(col).width=(width + 4)* 256        

#     wb.save(response)
#     return response

# def selectPeriod123(request):
#     if request.method == "GET" and request.is_ajax():
#         catg = request.GET.get('catg')
#         lplant = request.GET.get('lplant')
#         asst = request.GET.get('asst')
#         yop = request.GET.get('yop')
#         desc = request.GET.get('desc')
#         cost = request.GET.get('cost')
#         exlife = request.GET.get('exlife')
#         div = request.GET.get('div')
#         dept = request.GET.get('dept')
#         status = request.GET.get('status')
#         replc = request.GET.get('replc')
#         print(catg,"catg",lplant,"lplant",asst,"asst",yop,"yop",desc,"desc",cost,"cost",exlife,"exlife",div,"div",dept,"dept",status,"status","replc",replc)
#         replccode = None
#         if replc =='N':
#             replccode = 1
#         elif replc == 'Y':
#             replccode = 0
#         statuscode = None
#         if status == 'Condemn':
#             statuscode = 0
#         elif status == 'Working':
#             statuscode = 1
#         elif status == 'Not Working':
#             statuscode = 2
#         elif status == 'Replacement Required':
#             statuscode = 3
#         elif status == 'Under Commission':
#             statuscode = 4
#         MED_ASSTRGNN.objects.create(CNDT_flag=statuscode,RPLC_flag=replccode,MAV_ITEMNAME = catg, MAVITEMCODE  = lplant,MAVASSTCODE=asst ,MAIYEARPURC = yop, MAVHIDESC = desc, MAICOST = cost, MAIEXPLIFE = exlife, MAVDVSNCODE = div, MAVDEPTCODE_id= dept, STATUS = status, MAVRLCT = replc)
#         print(catg)
#         return JsonResponse({'success':'my data is saved'}, safe=False)

def add_asset(request):
    item =MEM_ITEMMSTN.objects.filter().values('MAV_ITEM_NAME')
    cofcodes=list(MEM_ITEMDTLN.objects.all().exclude(MAV_ITEMDETWDE = None).values('MAV_ITEMDETWDE').distinct('MAV_ITEMDETWDE'))
            
    obj = MED_ASSTRGNN.objects.filter().values('MAVASSTCODE','MAV_ITEMNAME','MAVITEMCODE','MAIYEARPURC','MAVHIDESC','MAICOST','MAIEXPLIFE','MAVDVSNCODE','MAVDEPTCODE_id__MAVDEPTNAME','STATUS','MAV_COFCODE')
    dept=list(MEM_DEPTMSTN.objects.all().values('MACDEPTCODE','MAVDEPTNAME'))
    div=railwayLocationMaster.objects.filter(location_type='DIV').values('location_code').distinct('location_code')
    print(dept,"itemmm")
    context = {
        'dept':dept,
        'div':div,
        'item':item,
        'obj':obj,
        'cof':cofcodes,
    }
    return render(request,'add_asset.html',context)
def add_asset_excel(request):
    item =MEM_ITEMMSTN.objects.filter().values('MAV_ITEM_NAME')
    obj = MED_ASSTRGNN.objects.filter().values('MAVASSTCODE','MAV_ITEMNAME','MAVITEMCODE','MAIYEARPURC','MAVHIDESC','MAICOST','MAIEXPLIFE','MAVDVSNCODE','MAVDEPTCODE','STATUS')
    print(item,"itemmm")
    context = {
    'item':item,
    'obj':obj,
    }
    # return render(request,'add_asset.html',context)

    import xlwt
    from xlwt import Workbook
    from django.http import HttpResponse
    response = HttpResponse(content_type='application/ms-excel')
    response['Content-Disposition'] = 'attachment; filename="AddAssetReport.xls"'
    wb = Workbook()
    sheet1 = wb.add_sheet('Sheet 1')
    style = xlwt.easyxf("alignment: wrap off;font: bold on;borders: top_color black, bottom_color black, right_color black, left_color black;")
    style1 = xlwt.easyxf("alignment: wrap off;borders: top_color black, bottom_color black, right_color black, left_color black;")
    style2 = xlwt.easyxf("alignment: wrap off;font: bold on;")
    heading1 = "Machinery and Plant Portal"
    row = 1
    col =4
    sheet1.write_merge(row, row , col, col + 1, heading1, style=style2)
    row = 4
    col = 4
    sheet1.write(row, col, 'Add Asset Report', style=style2)
    
    row = 6
    col = 0
    attributes = ["S.no","Category", "Local Plant No.", "Year of Purchase", "Cost", "Expected Life", "Division", "Department","Status"]
    col_width = {col:len(attr)for col, attr in enumerate(attributes)}
    for idx, attribute in enumerate(attributes):
        sheet1.write_merge(row, row + 0, col, col, attribute, style=style)
        col_width[col] = max(col_width[col],len(attribute))
        col += 1

    data = context['obj']
    row = 7
    for index, item in enumerate(data, start=1):
        sheet1.write(row, 0, index, style=style1)
        sheet1.write(row, 1, item['MAV_ITEMNAME'], style=style1)
        sheet1.write(row, 2, item['MAVITEMCODE'], style=style1)
        sheet1.write(row, 3, item['MAIYEARPURC'], style=style1)
        sheet1.write(row, 4, item['MAICOST'], style=style1)
        sheet1.write(row, 5, item['MAIEXPLIFE'], style=style1)
        sheet1.write(row, 6, item['MAVDVSNCODE'], style=style1)
        sheet1.write(row, 7, item['MAVDEPTCODE'], style=style1)
        sheet1.write(row, 8, item['STATUS'], style=style1)
        
        for col, content in enumerate([index,item['MAV_ITEMNAME'],item['MAVITEMCODE'], item['MAIYEARPURC'],item['MAICOST'],item['MAIEXPLIFE'],item['MAVDVSNCODE'],item['MAVDEPTCODE'],item['STATUS']]):
            col_width[col]=max (col_width[col],len(str(content)))
        row += 1

    for col,width in col_width.items():
        sheet1.col(col).width=(width + 4)* 256        

    wb.save(response)
    return response

def selectPeriod123(request):
    if request.method == "GET" and request.is_ajax():
        catg = request.GET.get('catg')
        lplant = request.GET.get('lplant')
        asst = request.GET.get('asst')
        yop = request.GET.get('yop')
        desc = request.GET.get('desc')
        cost = request.GET.get('cost')
        exlife = request.GET.get('exlife')
        div = request.GET.get('div')
        dept = request.GET.get('dept')
        status = request.GET.get('status')
        replc = request.GET.get('replc')
        cofcode = request.GET.get('cofcode')
        print(catg,"catg",lplant,"lplant",asst,"asst",yop,"yop",desc,"desc",cost,"cost",exlife,"exlife",div,"div",dept,"dept",status,"status","replc",replc)
        replccode = None
        if replc =='N':
            replccode = 1
        elif replc == 'Y':
            replccode = 0
        statuscode = None
        if status == 'Condemn':
            statuscode = 0
        elif status == 'Working':
            statuscode = 1
        elif status == 'Not Working':
            statuscode = 2
        elif status == 'Replacement Required':
            statuscode = 3
        elif status == 'Under Commission':
            statuscode = 4
        a=MEM_DEPTMSTN.objects.get(MACDEPTCODE=dept)
        MED_ASSTRGNN.objects.create(CNDT_flag=statuscode,RPLC_flag=replccode,MAV_ITEMNAME = catg, MAVITEMCODE  = lplant,MAVASSTCODE=asst ,MAIYEARPURC = yop, MAVHIDESC = desc, MAICOST = cost, MAIEXPLIFE = exlife, MAVDVSNCODE = div, MAVDEPTCODE_id= dept, STATUS = status, MAVRLCT = replc, MAV_COFCODE = cofcode)
        print(catg)
        return JsonResponse({'success':'my data is saved'}, safe=False)

def editview1(request):
    if request.method == "GET" and request.is_ajax():
        print("inside fnnnn")
        MAVASSTCODE = request.GET.get('MAVASSTCODE')
        print(MAVASSTCODE,"idddd")
        obj = MED_ASSTRGNN.objects.filter(MAVASSTCODE=MAVASSTCODE).values_list()
        obj = [entry for entry in obj]
        print(obj,"objjj")
        #lst=list(obj)
        return JsonResponse({'obj':obj}, safe=False)

def updateview1(request):
    if request.method == "GET" and request.is_ajax():
        ids = request.GET.get('ids')
        catg = request.GET.get('catg')
        lplant = request.GET.get('lplant')
        yop = request.GET.get('yop')
        cost = request.GET.get('cost')
        exlife = request.GET.get('exlife')
        dept = request.GET.get('dept')
        div = request.GET.get('div')
        status = request.GET.get('status')
        print(ids,"ids",catg,"catg",lplant,"lplant",yop,"yop",cost,"cost",exlife,"exlife",dept,"dept",div,"div",status,"status")
        MED_ASSTRGNN.objects.filter(MAVASSTCODE = ids).update(MAV_ITEMNAME = catg, MAVITEMCODE = lplant, MAIYEARPURC = yop, MAICOST = cost, MAIEXPLIFE =exlife, MAVDEPTCODE_id = dept,MAVDVSNCODE = div, STATUS = status)
        return JsonResponse({'success':'my data is saved'}, safe=False)

def add_asset_pdf(request):
    abs_path=os.path.abspath('static/images/picture.png')
    # abs_path1=os.path.abspath('static/images/crislogo1.png')
    item =MEM_ITEMMSTN.objects.filter().values('MAV_ITEM_NAME')
    obj = MED_ASSTRGNN.objects.filter().values('MAVASSTCODE','MAV_ITEMNAME','MAVITEMCODE','MAIYEARPURC','MAVHIDESC','MAICOST','MAIEXPLIFE','MAVDVSNCODE','MAVDEPTCODE','STATUS')
    print(item,"itemmm")
    context = {
    'abs_path':abs_path,
    # 'abs_path1':abs_path1,
    'item':item,
    'obj':obj,
    }
    template_src='add_asset_pdf.html'
    return render_to_pdf(template_src, context)

def list_of_proposal_HQ(request):
    cuser=request.user 
    print("CUSER-----------",cuser,request.user)
    selected_year = None
    selected_user = None
    selected_forwarded = None
  
    if request.method == 'POST':
        selected_year = request.POST.get('selected_year')
        selected_forwarded = request.POST.get('selected_forwarded')
   
    if not selected_year or request.POST.get('show_all'):
        obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1','status_flag1')    

        # obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID', 'MAVPRSLNO', 'MADVRSNDATETIME', 'MAVRLYCODE_id__MAV_shrtraildesc', 'MAVDESC', 'MAVPRCHFROM', 'MAVALCNCODE_id__MAVALCN', 'MANTTLCOST', 'MAVCRTRC', 'MAVACTV', 'MAVDEPTCODE', 'status_flag1')
        
    else:
        selected_year = int(selected_year)
        obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1','status_flag1')    

        # obj = MEM_PRSLN.objects.filter(MADVRSNDATETIME__year=selected_year, delete_flag=False).values('ID', 'MAVPRSLNO', 'MADVRSNDATETIME', 'MAVRLYCODE_id__MAV_shrtraildesc', 'MAVDESC', 'MAVPRCHFROM', 'MAVALCNCODE_id__MAVALCN', 'MANTTLCOST', 'MAVCRTRC', 'MAVACTV', 'MAVDEPTCODE', 'status_flag1').all()
   
    if request.is_ajax():
        if selected_forwarded == 'Railway Board':
            employees = MEM_usersn.objects.filter(user_level_code=39).values('MAV_username', 'MAV_userdesig')
            combined_data = [f"{emp['MAV_username']} - {emp['MAV_userdesig']}" for emp in employees]
            return JsonResponse(list(combined_data), safe=False)
            print(combined_data,"^^^^^^^^^^^^^^^")

        elif selected_forwarded == 'CME Planning':
            cmes = MEM_usersn.objects.filter(user_level_code=20).values('MAV_username', 'MAV_userdesig')
            combined_data = [f"{cme['MAV_username']} - {cme['MAV_userdesig']}" for cme in cmes]
            return JsonResponse(list(combined_data), safe=False)
        elif selected_forwarded == 'HQF':
            is_hqf = request.POST.get('is_hqf') == 'true'
            if is_hqf:
                hqfs = MEM_usersn.objects.filter(user_level_code=29).values('MAV_username')
                return JsonResponse(list(hqfs), safe=False)
    obj10 = MEM_usersn.objects.filter(MAV_userlvlcode=39).values('MAV_username','MAV_userdesig')
    print(obj10,"+++++++++++++++++++")
    obj11 = MEM_usersn.objects.filter(MAV_userlvlcode=20).values('MAV_username','MAV_userdesig')
    obj13 = MEM_usersn.objects.filter(MAV_userlvlcode=29).values('MAV_username')
    obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1','status_flag1')    


    # selected_year = None  # Initialize selected_year variable
    # if request.method == 'POST':
    #     selected_year = request.POST.get('selected_year')  # Get selected year from POST data
    # # Filter the data based on the selected year
    # if selected_year:
    #     # Convert selected_year to integer since it's coming as a string
    #     selected_year = int(selected_year)
    #     obj = MEM_PRSLN.objects.filter(MAIFINYEAR=selected_year, delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE','status_flag1','status_flag1')
    # else:
    #     # If no year is selected, fetch all data
    #     obj10 = MEM_usersn.objects.filter(MAV_userlvlcode=39).values('MAV_username','MAV_userdesig')
    #     obj11 = MEM_usersn.objects.filter(MAV_userlvlcode=20).values('MAV_username','MAV_userdesig')
    #     obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE','status_flag1','status_flag1')    
    # print(obj10,"---------")

    # obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALLOC','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE','status_flag1','status_flag1')
    obj1 = MEM_PRSLN.objects.filter(Q(status_flag1=4) | Q(status_flag1=8),delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj2 = MEM_PRSLN.objects.filter(status_flag1=7,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj3 = MEM_PRSLN.objects.filter(status_flag1=5,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVSHRTDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj4 = MEM_PRSLN.objects.filter(status_flag1=3,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj5 = MEM_PRSLN.objects.filter(status_flag1=6,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj6 = MEM_PRSLN.objects.filter(MAVGMSANC='Y',delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME')
    obj7 = MEM_PRSLN.objects.filter(status_flag1=8,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj8 = MEM_PRSLN.objects.filter(status_flag1=2,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj9 = MEM_PRSLN.objects.filter(status_flag1=3,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    obj12 = MEM_PRSLN_DRAFT.objects.filter(MAVUSERID=cuser,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1')
    print("-------------------------",obj12)
    for item in obj:
        if item['status_flag1'] == 4:
            item['status_class'] = 'C'
            item['button_text'] = 'C'
        elif item['status_flag1'] == 2:
            item['status_class'] = 'A'
            item['button_text'] = 'A'
        elif item['status_flag1'] == 5:
            item['status_class'] = 'U'
            item['button_text'] = 'U'
        elif item['status_flag1'] ==7:
            item['status_class'] = 'V'
            item['button_text'] = 'V'
        elif item['status_flag1'] ==3:
            item['status_class'] = 'R'
            item['button_text'] = 'R'
        elif item['status_flag1'] ==1:
            item['status_class'] = 'P'
            item['button_text'] = 'P'
        elif item['status_flag1'] ==8:
            item['status_class'] = 'SU'
            item['button_text'] = 'SU'
        
        else:
            item['status_class'] = 'status'
            item['button_text'] = 'D'
    context = {
    'obj':obj,
    'obj1':obj1,
    'obj2':obj2,
    'obj3':obj3,
    'obj4':obj4,
    'obj5':obj5,
    'obj6':obj6,
    'obj7':obj7,
    'obj8':obj8,
    'obj9':obj9,
    'obj10':obj10,
    'obj11':obj11,
    'obj12':obj12,
    'selected_year': selected_year,
    }
    return render(request,'list_of_proposal_HQ.html',context)

def submit_proposal3(request):
    if request.method=='GET' and request.is_ajax():
        ids= request.GET.get('IDS')
        print('IDS iDS',ids)
        MEM_PRSLN.objects.filter(ID=ids).update(status_flag1=3)
        return JsonResponse({"success":"updated successfully"}, safe=False)

def submitt_proposal(request):
    if request.method=='GET' and request.is_ajax():
        ids= request.GET.get('IDS')
        print('IDS iDS',ids)
        MEM_PRSLN.objects.filter(ID=ids).update(status_flag1=2)
        return JsonResponse({"success":"updated successfully"}, safe=False)

def submitt_proposal2(request):
    if request.method=='GET' and request.is_ajax():
        
        ids= request.GET.get('ids')
        print('IDS iDS',ids)
        if ids:
            try:
                # Convert the comma-separated IDs to a list of integers
                proposal_ids = [int(id) for id in ids.split(',')]

                # Update the status_flag1 for the selected proposals to 6
                MEM_PRSLN.objects.filter(ID__in=proposal_ids, status_flag1=4).update(status_flag1=8)

                return JsonResponse({"success": "Selected proposals updated successfully"}, safe=False)
            except ValueError:
                return JsonResponse({"error": "Invalid Proposal IDs"}, status=400)

                return JsonResponse({"error": "Invalid request method or not an AJAX request"}, status=400)



def list_of_proposal_finance(request):
    cuser=request.user 
    print("CUSER-----------",cuser,request.user)
    selected_year = None
    selected_user = None
    selected_forwarded = None
    mavusercode_filter = None
    user_level_code=list(MEM_usersn.objects.filter(MAV_userid=cuser).values_list('MAV_userlvlcode_id',flat = True))[0]
    print("ggggggggggggg",type(user_level_code))
    if user_level_code == '29' :  
        mavusercode_filter = 21
        print("///////////",mavusercode_filter)
    elif user_level_code == '19' : 
        mavusercode_filter = 11
        print(":;;;;;;;;;;;;;",mavusercode_filter)
    else:
        print("############")

  
    if request.method == 'POST':
        selected_year = request.POST.get('selected_year')
        selected_forwarded = request.POST.get('selected_forwarded')
        selected_type = request.POST.get('selected_type')
        print("Selected Type:", selected_type)
  
   
        filters = {'delete_flag': False}

        if mavusercode_filter:
            filters['MAVUSERCODE'] = mavusercode_filter

        if selected_year :
            filters['MADVRSNDATETIME__year'] = selected_year

        if selected_type :
            filters['MAVPRSLTYPE'] = selected_type

        obj = MEM_PRSLN.objects.filter(**filters).values(
            'ID', 'MAVPRSLNO', 'MADVRSNDATETIME', 'MAVRLYCODE__MAV_shrtraildesc',
            'MAVDESC', 'MAVCATCODE', 'MAVALCNCODE__MAVALCN', 'MANTTLCOST',
            'MAVCRTRC', 'MAVPRCHFROM', 'MAVDEPTCODE_id__MAVDEPTNAME',
            'status_flag1', 'MAVUSERID', 'MAVUSERCODE'
        )

        if request.method != 'POST' or (not selected_type and not selected_year):
            obj = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter, delete_flag=False).values(
                'ID', 'MAVPRSLNO', 'MADVRSNDATETIME', 'MAVRLYCODE__MAV_shrtraildesc',
                'MAVDESC', 'MAVCATCODE', 'MAVALCNCODE__MAVALCN', 'MANTTLCOST',
                'MAVCRTRC', 'MAVPRCHFROM', 'MAVDEPTCODE_id__MAVDEPTNAME',
                'status_flag1', 'MAVUSERID', 'MAVUSERCODE'
            )


    if request.is_ajax():
        if selected_forwarded == 'Railway Board':
            employees = MEM_usersn.objects.filter(user_level_code=39).values('MAV_username', 'MAV_userdesig')
            combined_data = [f"{emp['MAV_username']} - {emp['MAV_userdesig']}" for emp in employees]
            return JsonResponse(list(combined_data), safe=False)
            print(combined_data,"^^^^^^^^^^^^^^^")

        elif selected_forwarded == 'CME Planning':
            cmes = MEM_usersn.objects.filter(user_level_code=20).values('MAV_username', 'MAV_userdesig')
            combined_data = [f"{cme['MAV_username']} - {cme['MAV_userdesig']}" for cme in cmes]
            return JsonResponse(list(combined_data), safe=False)
        elif selected_forwarded == 'HQF':
            is_hqf = request.POST.get('is_hqf') == 'true'
            if is_hqf:
                hqfs = MEM_usersn.objects.filter(user_level_code=29).values('MAV_username')
                return JsonResponse(list(hqfs), safe=False)
    obj10 = MEM_usersn.objects.filter(MAV_userlvlcode=39).values('MAV_username','MAV_userdesig')
    print(obj10,"+++++++++++++++++++")
    obj11 = MEM_usersn.objects.filter(MAV_userlvlcode=20).values('MAV_username','MAV_userdesig')
    obj13 = MEM_usersn.objects.filter(MAV_userlvlcode=29).values('MAV_username')
   # obj = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','status_flag1','MAVUSERID','MAVUSERCODE','status_flag1')    
    print("**********",obj)




    # selected_year = None  # Initialize selected_year variable
    # if request.method == 'POST':
    #     selected_year = request.POST.get('selected_year')  # Get selected year from POST data
    # # Filter the data based on the selected year
    # if selected_year:
    #     # Convert selected_year to integer since it's coming as a string
    #     selected_year = int(selected_year)
    #     obj = MEM_PRSLN.objects.filter(MAIFINYEAR=selected_year, delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE','status_flag1','status_flag1')
    # else:
    #     # If no year is selected, fetch all data
    #     obj10 = MEM_usersn.objects.filter(MAV_userlvlcode=39).values('MAV_username','MAV_userdesig')
    #     obj11 = MEM_usersn.objects.filter(MAV_userlvlcode=20).values('MAV_username','MAV_userdesig')
    #     obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE','status_flag1','status_flag1')    
    # print(obj10,"---------")

    # obj = MEM_PRSLN.objects.filter(delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALLOC','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE','status_flag1','status_flag1')
    obj1 = MEM_PRSLN.objects.filter(Q(status_flag1=5) | Q(status_flag1=12),delete_flag=False,MAVUSERCODE=mavusercode_filter).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj2 = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter,status_flag1=7,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj3 = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter,status_flag1=8,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVSHRTDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj4 = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter,status_flag1=9,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj5 = MEM_PRSLN.objects.filter(Q(status_flag1=6) | Q(status_flag1=11),MAVUSERCODE=mavusercode_filter,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj6 = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter,MAVGMSANC='Y',delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERCODE','MAVUSERID')
    obj7 = MEM_PRSLN.objects.filter(MAVUSERCODE=mavusercode_filter,status_flag1=9,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj8 = MEM_PRSLN.objects.filter(Q(status_flag1=2)|Q(status_flag1=10),delete_flag=False,MAVUSERCODE=mavusercode_filter).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj9 = MEM_PRSLN.objects.filter(Q(status_flag1=1)|Q(status_flag1=3),MAVUSERCODE=mavusercode_filter,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')
    obj12 = MEM_PRSLN_DRAFT.objects.filter(MAVUSERID=cuser,delete_flag=False).values('ID','MAVPRSLNO','MADVRSNDATETIME','MAVRLYCODE__MAV_shrtraildesc','MAVDESC','MAVCATCODE','MAVALCNCODE__MAVALCN','MANTTLCOST','MAVCRTRC','MAVPRCHFROM','MAVDEPTCODE_id__MAVDEPTNAME','MAVUSERID','MAVUSERCODE','status_flag1')

    appr = MED_PRSLVTED.objects.order_by('-MADVTEDDATE').values('MAVPRSLNO','MAVVTEDRMRK','MADVTEDDATE','MAVSMTDBY','MAVVTEDBY','MAVVTEDSTTS')
    quer = MED_PRSLVTED.objects.order_by('-MADVTEDDATE').values('MAVPRSLNO','MAVVTEDRMRK','MADVTEDDATE','MAVSMTDBY','MAVVTEDBY','MAVVTEDSTTS')
    

    current_user = request.user
    desg = MEM_usersn.objects.filter(MAV_userid=current_user).values("MAV_userdesig")[0]

    print("-------------------------",obj12)
    for item in obj:
        if item['status_flag1'] == 5:
            item['status_class'] = 'C'
            item['button_text'] = 'C'
        elif item['status_flag1'] == 2:
            item['status_class'] = 'AH'
            item['button_text'] = 'AH'
        elif item['status_flag1'] == 8:
            item['status_class'] = 'U'
            item['button_text'] = 'U'
        elif item['status_flag1'] ==7:
            item['status_class'] = 'V'
            item['button_text'] = 'V'
        elif item['status_flag1'] ==3:
            item['status_class'] = 'RH'
            item['button_text'] = 'RH'
        elif item['status_flag1'] ==6:
            item['status_class'] = 'P'
            item['button_text'] = 'P'
        elif item['status_flag1'] ==9:
            item['status_class'] = 'SU'
            item['button_text'] = 'SU'
        elif item['status_flag1'] ==1:
            item['status_class'] = 'RD'
            item['button_text'] = 'RD'
        elif item['status_flag1'] ==10:
            item['status_class'] = 'AD'
            item['button_text'] = 'AD'
        elif item['status_flag1'] ==11:
            item['status_class'] = 'PH'
            item['button_text'] = 'PH'
        else:
            item['status_class'] = 'status'
            item['button_text'] = 'D'
    context = {
    'obj':obj,
    'obj1':obj1,
    'obj2':obj2,
    'obj3':obj3,
    'obj4':obj4,
    'obj5':obj5,
    'obj6':obj6,
    'obj7':obj7,
    'obj8':obj8,
    'obj9':obj9,
    'obj10':obj10,
    'obj11':obj11,
    'obj12':obj12,
    'appr': appr,
    'cuser':cuser,
    'quer':quer,
    'desg':desg,
    
    'selected_type': selected_type,
    'selected_year': selected_year,
    }
    return render(request,'list_of_proposalHQF.html',context)

def fetch_forwd(request):
    if request.method == 'GET':
        proposal_no = request.GET.get('proposalNo')

        # Fetch the data from the MEM_PRSLN table based on the proposal number
        prsln_data = get_object_or_404(MEM_PRSLN, MAVPRSLNO=proposal_no)

        # Prepare the data to be sent back to the client
        data = {'MAVUSERID': prsln_data.MAVUSERID}

        return JsonResponse(data)
    else:
        # Handle other HTTP methods if necessary
        return JsonResponse({'error': 'Invalid request method'}, status=400)

def div_reply2(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        print('MAVPRSLNO',MAVPRSLNO)
        rpl = MED_PRSLVTED.objects.filter(MAVPRSLNO = MAVPRSLNO).values('id','MAVPRSLNO','MAVVTEDRMRK','MAVRPLY','MAVSMTDBY','MADSMTDDATE','MAVVTEDSTTS','MAVVTEDBY')
        return JsonResponse(list(rpl), safe=False)
    else:
        return JsonResponse({'error': 'Invalid request method'},status = 404)



def fetch_remark1(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        try:
            remark = MED_PRSLVTED.objects.filter(id=MAVPRSLNO, MAVVTEDRMRK__isnull=False).values('MAVPRSLNO','MAVVTEDRMRK').first()
            if remark:
                return JsonResponse({'MAVVTEDRMRK': remark['MAVVTEDRMRK']})
            else:
                return JsonResponse({'error': 'Remark not found for the given proposalNo'}, status=404)
        except MED_PRSLVTED.DoesNotExist:
            return JsonResponse({'error': 'Proposal not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=404)




def fetch_reply1(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        try:
            reply = MED_PRSLVTED.objects.filter(id=MAVPRSLNO, MAVRPLY__isnull=False).values('MAVRPLY').first()
            if reply:
                return JsonResponse({'MAVRPLY': reply['MAVRPLY']})
            else:
                return JsonResponse({'error': 'Reply not found for the given proposalNo'}, status=404)
        except MED_PRSLVTED.DoesNotExist:
            return JsonResponse({'error': 'Proposal not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=404)
        
# Add a new view to fetch remarks based on the proposal number
def get_remarks(request):
    if request.method == 'GET':
        proposal_no = request.GET.get('proposalNo')  # Get the selected proposal number
        # Fetch remarks based on the proposal number (You need to implement this logic)
        remarks = MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_no,MAVVTEDSTTS='V').values('MAVPRSLNO', 'MAVVTEDRMRK', 'MADVTEDDATE', 'MAVSMTDBY', 'MAVVTEDBY','MAVVTEDSTTS')

        return JsonResponse(list(remarks), safe=False)
    else:
        return JsonResponse({'error': 'Invalid request method'})

# Add a new view to fetch remarks based on the proposal number
def get_reject_remarks(request):
    if request.method == 'GET':
        proposal_no = request.GET.get('proposalNo')  # Get the selected proposal number
        # Fetch remarks based on the proposal number (You need to implement this logic)
        remarks = MED_PRSLVTED.objects.filter(MAVPRSLNO=proposal_no,MAVVTEDSTTS='R').values('MAVPRSLNO', 'MAVVTEDRMRK', 'MADVTEDDATE', 'MAVSMTDBY', 'MAVVTEDBY','MAVVTEDSTTS')

        return JsonResponse(list(remarks), safe=False)
    else:
        return JsonResponse({'error': 'Invalid request method'})


def submitt_proposlHQF(request):
    if request.method=='GET' and request.is_ajax():
        
        ids= request.GET.get('ids')
        print('IDS iDS',ids)
        if ids:
            try:
                # Convert the comma-separated IDs to a list of integers
                proposal_ids = [int(id) for id in ids.split(',')]

                # Update the status_flag1 for the selected proposals to 6
                MEM_PRSLN.objects.filter(ID__in=proposal_ids, status_flag1=4).update(status_flag1=12)

                return JsonResponse({"success": "Selected proposals updated successfully"}, safe=False)
            except ValueError:
                return JsonResponse({"error": "Invalid Proposal IDs"}, status=400)

                return JsonResponse({"error": "Invalid request method or not an AJAX request"}, status=400)

def rmksave(request):
    if request.method == 'GET' and request.is_ajax():
        prsl = request.GET.get('prsl')
        addrmk = request.GET.get('addrmk')
        rdate= request.GET.get('rdate')
        vetto = request.GET.get('vetto')
        current_user = request.user
        vettby = MEM_usersn.objects.filter(MAV_userid=current_user).values("MAV_userdesig")
        print('vettby',vettby)
        
     
        MED_PRSLVTED.objects.create(MAVPRSLNO=prsl,MAVVTEDRMRK=addrmk,MADVTEDDATE=rdate, MAVVTEDBY=vettby,MAVVTEDSTTS='V', MAVSMTDBY = vetto)
        return JsonResponse({'success':'my data is saved'},safe=False)

def Qsave(request):
    if request.method == 'GET' and request.is_ajax():
        prsl1 = request.GET.get('prsl1')
        addrmk1 = request.GET.get('addrmk1')
        rdate1= request.GET.get('rdate1')
        qrej1 = request.GET.get('qrej1')
        current_user = request.user
        qby = MEM_usersn.objects.filter(MAV_userid=current_user).values("MAV_userdesig")

        MED_PRSLVTED.objects.create(MAVPRSLNO=prsl1,MAVVTEDRMRK=addrmk1,MADVTEDDATE=rdate1, MAVVTEDBY=qby,MAVVTEDSTTS='R',MAVSMTDBY=qrej1)
        return JsonResponse({'success':'my data is saved'},safe=False)


def approve_HQF(request):
    if request.method == 'GET' and request.is_ajax():
        cuser = request.user
        ids = request.GET.get('MAVPRSLNO')
        print('MAVPRSLNO iDS', ids)
        mavusercode_filter = list(MEM_usersn.objects.filter(MAV_userid=cuser).values_list('MAV_userlvlcode_id', flat=True))[0]
        print("honeyyyyyyyyyyyyyyyyyyyyyyyyy", mavusercode_filter)
        # mavusercode_filter = get_mavusercode_filter(request.user)  # Assuming you have a function to get mavusercode_filter
        if mavusercode_filter == '29':
            MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=2)
        elif mavusercode_filter == '19':
            MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=10)
        # MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=2)
        return JsonResponse({'success': True})
    return JsonResponse({'success': False})




def reject_proposal3(request):
    if request.method=='GET' and request.is_ajax():
        cuser = request.user
        ids= request.GET.get('MAVPRSLNO')
        print('IDS iDS',ids)
        mavusercode_filter = list(MEM_usersn.objects.filter(MAV_userid=cuser).values_list('MAV_userlvlcode_id', flat=True))[0]
        if mavusercode_filter == '29':
            MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=3)
        elif mavusercode_filter == '19':
            MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=1)
        # MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=2)
        return JsonResponse({'success': True})
    return JsonResponse({'success': False})

        # MEM_PRSLN.objects.filter(MAVPRSLNO=ids).update(status_flag1=3)
        # return JsonResponse({"success":"updated successfully"}, safe=False)

def div_reply(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        print('MAVPRSLNO',MAVPRSLNO)
        rpl = MED_PRSLVTED.objects.filter(MAVPRSLNO = MAVPRSLNO).values('id','MAVPRSLNO','MAVVTEDRMRK','MAVRPLY','MAVSMTDBY','MADSMTDDATE','MAVVTEDSTTS','MAVVTEDBY')
        return JsonResponse(list(rpl), safe=False)
    else:
        return JsonResponse({'error': 'Invalid request method'},status = 404)



def fetch_remark(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        try:
            remark = MED_PRSLVTED.objects.filter(id=MAVPRSLNO, MAVVTEDRMRK__isnull=False).values('MAVPRSLNO','MAVVTEDRMRK').first()
            if remark:
                return JsonResponse({'MAVVTEDRMRK': remark['MAVVTEDRMRK']})
            else:
                return JsonResponse({'error': 'Remark not found for the given proposalNo'}, status=404)
        except MED_PRSLVTED.DoesNotExist:
            return JsonResponse({'error': 'Proposal not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=404)

def fetch_reply(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        try:
            reply = MED_PRSLVTED.objects.filter(id=MAVPRSLNO, MAVRPLY__isnull=False).values('MAVRPLY').first()
            if reply:
                return JsonResponse({'MAVRPLY': reply['MAVRPLY']})
            else:
                return JsonResponse({'error': 'Reply not found for the given proposalNo'}, status=404)
        except MED_PRSLVTED.DoesNotExist:
            return JsonResponse({'error': 'Proposal not found'}, status=404)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=404)

# def div_replyhis(request):
#     if request.method == 'GET':
#         MAVPRSLNO = request.GET.get('proposalNo')
#         rpl = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=MAVPRSLNO).values('MAVPRSLNO', 'MAVVTEDRMRK', 'MAVRPLY', 'MAVSMTDBY', 'MADSMTDDATE'))
#         return JsonResponse((rpl), safe=False)
#     else:
#         return JsonResponse({'error': 'Invalid request method'}, status=404)

def div_replyhis(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        rpl = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=MAVPRSLNO, MAVRPLY__isnull=False).values('MAVPRSLNO', 'MAVVTEDRMRK', 'MAVRPLY', 'MAVSMTDBY', 'MADSMTDDATE').order_by('-MADSMTDDATE'))[0]
        return JsonResponse((rpl), safe=False)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=404)

def div_replyviw(request):
    if request.method == 'GET':
        MAVPRSLNO = request.GET.get('proposalNo')
        rpl = list(MED_PRSLVTED.objects.filter(MAVPRSLNO=MAVPRSLNO, MAVRPLY__isnull=False).values('MAVPRSLNO', 'MAVVTEDRMRK', 'MAVRPLY', 'MAVSMTDBY', 'MADSMTDDATE').order_by('-MADSMTDDATE'))[0]
        return JsonResponse((rpl), safe=False)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=404)

def deleteremark(request):
    if request.method == "GET" and request.is_ajax():
        MAVVTEDRMRK = request.GET.get('MAVVTEDRMRK')
        
        try:
            # Assuming YourModel has a field named 'MAVPRSLNO'
            remark_instances = MED_PRSLVTED.objects.filter(MAVVTEDRMRK=MAVVTEDRMRK)
            # Check if there are any instances
            if remark_instances.exists():
                # Delete all instances with the given MAVPRSLNO
                remark_instances.delete()

                # Get the remaining remarks
                remarks = MED_PRSLVTED.objects.values('MAVPRSLNO', 'MAVVTEDRMRK','MAVVTEDRMRK','MAVVTEDBY').all()  # Adjust this based on your model/query

                return JsonResponse({"success": "deleted successfully", "remarks": remarks}, safe=False)
            else:
                return JsonResponse({"error": "Record not found"}, status=404)

        except Exception as e:
            return JsonResponse({"error": str(e)}, status=500)

    return JsonResponse({"error": "Invalid request"}, status=400)

def editremark(request):
   if request.method == "GET" and request.is_ajax():
      MAVVTEDRMRK = request.GET.get('MAVVTEDRMRK')
      new_remark = request.GET.get('newRemark')

      try:
         remark_instance = MED_PRSLVTED.objects.get(MAVVTEDRMRK=MAVVTEDRMRK)
         remark_instance.MAVVTEDRMRK = new_remark
         remark_instance.save()

         # Get the remaining remarks
         remarks = MED_PRSLVTED.objects.values('MAVPRSLNO', 'MAVVTEDRMRK', 'MAVVTEDBY', 'MADVTEDDATE').all()

         return JsonResponse({"success": "edited successfully", "remarks": remarks}, safe=False)

      except MED_PRSLVTED.DoesNotExist:
         return JsonResponse({"error": "Record not found"}, status=404)

   return JsonResponse({"error": "Invalid request"}, status=400)

def editremark1(request):
   if request.method == "GET" and request.is_ajax():
      MAVVTEDRMRK = request.GET.get('MAVVTEDRMRK')
      new_remark = request.GET.get('newRemark')

      try:
         remark_instance = MED_PRSLVTED.objects.get(MAVVTEDRMRK=MAVVTEDRMRK)
         remark_instance.MAVVTEDRMRK = new_remark
         remark_instance.save()

         # Get the remaining remarks
         remarks = MED_PRSLVTED.objects.values('MAVPRSLNO', 'MAVVTEDRMRK', 'MAVVTEDBY', 'MADVTEDDATE').all()

         return JsonResponse({"success": "edited successfully", "remarks": remarks}, safe=False)

      except MED_PRSLVTED.DoesNotExist:
         return JsonResponse({"error": "Record not found"}, status=404)

   return JsonResponse({"error": "Invalid request"}, status=400)
        
def Indent(request):
    return render(request,'Indent.html')

def insert_monthly_progress(request):
    return render(request,'insert_monthly_progress.html')

def vetting(request):
    return render(request,'vetting.html')

def nonvetting(request):
    return render(request,'nonvetting.html')

def vetted(request):
    return render(request,'vetted.html')

def nonvetted(request):
    return render(request,'nonvetted.html')

def wip_summary(request):
    return render(request,'wip_summary.html')

def zonal_level_proposal(request):
    return render(request,'zonal_level_proposal.html')

def viewprioritylist(request):
    return render(request,'viewprioritylist.html')

def submission(request):
    return render(request,'submission.html')

def sectionsummary(request):
    return render(request,'sectionsummary.html')

def sanctioned_proposal(request):
    return render(request,'sanctioned_proposal.html')

def reply(request):
    return render(request,'reply.html')

def proposaljustificationn(request):
    return render(request,'proposaljustification.html')

def priority_of_proposal(request):
    return render(request,'priority_of_proposal.html')

def proposalremarkss(request):
    return render(request,'proposalremarkss.html')

def proposalstatuss(request):
    return render(request,'proposalstatuss.html')

def proposalstatustable(request):
    return render(request,'proposalstatustable.html')

def pinkbookitem(request):
    return render(request,'pinkbookitem.html')

def viewprioritylist(request):
    return render(request,'viewprioritylist.html')

def financequery(request):
    return render(request,'financequery.html')

def pinkbookgeneration(request):
    return render(request,'pinkbookgeneration.html')

def pinkbookgeneration2(request):
    return render(request,'pinkbookgeneration2.html')

def workinprogress(request):
    return render(request,'workinprogress.html')

def mech(request):
    return render(request,'mech.html')

def finaljustificationform(request):
    return render(request,'finaljustificationform.html')

def listofcreatedproposal(request):
    return render(request,'listofcreatedproposal.html')


def printtdocuments(request):
    return render(request,'printtdocuments.html')

def Submitted_proposal(request):

    return render(request,'Submitted_proposal.html')

def submitted_programm(request):

    return render(request,'submitted_programm.html')

def procurement_rlyboard(request):

    return render(request,'procurement_rlyboard.html')

def procurement_gmpower(request):

    return render(request,'procurement_gmpower.html')

def sanctioned_cost(request):

    return render(request,'sanctioned_cost.html')

def summaryprop_processedRB(request):

    return render(request,'summaryprop_processedRB.html')

def board_summary(request):

    return render(request,'board_summary.html')



def detailss(request):
    if request.method == "GET":
       flag=request.GET.get('_id')
       flag=flag.split('@')
       o=[]
       if(flag[0]=='Disable'):
          changes = MEM_DEPTMSTN.objects.filter(MACDEPTCODE=flag[1]).update(MABDELTFLAG=True)
       elif(flag[0]=='Enable'):
          changes = MEM_DEPTMSTN.objects.filter(MACDEPTCODE=flag[1]).update(MABDELTFLAG=False)
    return JsonResponse(o,safe=False)
    return JsonResponse({"success":False},status=400)

# def savediv(request):
#     try:
#         if request.method == "GET":
#             #print("hello")
#             shortcode=request.GET.get('shortcode')
#             description=request.GET.get('description')
#             parentcode=request.GET.get('parentcode')
#             station=request.GET.get('station')
#             rlytype=request.GET.get('rlytype')
#             st = station.split("-")
            
#             dict1 = {"Railwayunit":"Unit","DIRECTORATE":"DIRECTORATE","DIVISION": "DIV", "OFFICE": "O","HEAD QUATER": "HQ", "PRODUCTION UNIT": "PU","PSU": "PSU","INSTITUTE": "CTI","WORKSHOP": "WS","RAILWAY BOARD": "RB"}
            
#             ltype=None
#             for key,val in dict1.items():
#                 if key == rlytype:
#                     ltype = val
            
#             pid=railwayLocationMaster.objects.filter(location_code=parentcode).values('rly_unit_code')
#             #print(pid)
#             id=railwayLocationMaster.objects.filter().order_by('-rly_unit_code')[0].rly_unit_code
#             id+=1
#             #print(id,"i am ideeyyyyyy")
#             railwayLocationMaster.objects.create(station_code=st[0],location_type=ltype,rly_unit_code=id,location_code=shortcode,location_type_desc=rlytype,location_description=description,parent_location_code=parentcode,parent_id=pid)
#             obj=[]
#             # context={
#             #     'datatable':datatable,
#             # }
#             return JsonResponse(obj, safe=False)
#         return JsonResponse({'success': False}, status=400)
#     except Exception as e:
#         # try:
#         #     rm.error_Table.objects.create(fun_name="savediv",user_id=request.user,err_details=str(e))
#         # except:
#         print("Internal Error!!!")
#         #messages.error(request, 'Error : '+str(e))
#         return render(request, "errorspage.html", {})

def savehqq(request):
    if request.method == "GET":
       flag=request.GET.get('deptc')
       print(flag)
    # department_code = '1'
    department_code= MEM_DEPTMSTN.objects.filter(MACDEPTCODE=flag).exists()
    print(department_code)
    return JsonResponse( {'deptname': department_code})
    
def able_rlyorgg(request):
    if request.method == "GET":
        rlytype=request.GET.get('rlytype')
        print(rlytype)
        parent=[]
        unit=[]
        if rlytype == "DIRECTORATE":
            # parent=list(railwayLocationMaster.objects.filter(Q(location_type_desc='RAILWAY BOARD')| Q(location_type_desc='OFFICE')).values('parent_location_code').distinct())
            parent=[{'parent_location_code': 'PSU'}, {'parent_location_code': 'RB'}]
        elif rlytype == "Railwayunit":
            # unit=list(Railwayunit.objects.values('Unit_description'))
            parent = list(MEM_DEPTMSTN.objects.filter(Q(location_type_desc='DIVISION')| Q(location_type_desc='OFFICE')| Q(location_type_desc='WORKSHOP')).values('parent_location_code').distinct())
        else:
            parent=list(MEM_DEPTMSTN.objects.filter(location_type_desc=rlytype).values('parent_location_code').distinct())
        print(parent)
        print(unit)
        context={
            'parent':parent,
            'unit':unit,
        }
        return JsonResponse(context, safe=False)
    return JsonResponse({'success': False}, status=400)



def adminuserHome(request):
    return HttpResponse("<h1>Successful<h1>")

def admin_changePassword(request):
    return HttpResponse("<h1>Successful<h1>")

def admin_logout(request):
    return HttpResponse("<h1>Successful<h1>")

def details(request):
    if request.method == "GET":
        PostCode = request.GET.get('post_id')
        key = request.GET.get('key')
        print("KEY------------",key,PostCode)
        if key =="disable":
            railwayLocationMaster.objects.filter(rly_unit_code = PostCode ).update(delete_flag = True)
            data='1'
            print(data)
        else:
            railwayLocationMaster.objects.filter(rly_unit_code = PostCode ).update(delete_flag = False)
            data='2'
            print(data)
        return JsonResponse({"success":True,'data':data},safe=False)
       
    return JsonResponse({"success":False},status=400)

def getDesigbyDepartment(request):
    try:
        if request.method == "GET" and request.is_ajax():
            department = request.GET.get('department')
            print(department)  
            
            obj=list(Level_Desig.objects.filter(department=department).values('designation').order_by('designation').distinct('designation'))
            print(obj,'____________________________________')
            return JsonResponse(obj, safe = False)
        return JsonResponse({"success":False}, status=400)
    except Exception as e: 
        try:
            rm.error_Table.objects.create(fun_name="getDesigbyDepartment",user_id=request.user,err_details=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

def division_by_rly(request):
    try:
        if request.method == "GET" and request.is_ajax():
            rly=request.GET.get('rly')
            print(rly,'_________________________aaaaaa________________')
            
            division=list(railwayLocationMaster.objects.filter(location_type='DIV',parent_location_code=rly).order_by('location_code').values('location_code').distinct('location_code'))
            l=[]
            for i in division:
                l.append(i['location_code'])
            print(l)    
            context={
                'division':l,
            } 
            return JsonResponse(context,safe = False)
        return JsonResponse({"success":False}, status = 400)
    except Exception as e: 
        try:
            rm.error_Table.objects.create(fun_name="division_by_rly",user_id=request.user,err_details=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

def filter(request):
    try:
        if request.method == "GET":
            rlycode=request.GET.get('rlycode')
            print(rlycode,'rlycode')
            rlytype=request.GET.get('rlytype')
            print(rlytype,'rlytype')
            parentrlycode=request.GET.get('parentrlycode')
            print(parentrlycode,'parentrlycode')
            station1=request.GET.get('station1')
            print(station1,'station1')
            dict2={}
            dict1 = {"location_code":rlycode,  "location_type":rlytype,"parent_location_code":parentrlycode,"station_code":station1}
            for key,val in dict1.items():
                print(key, val)
                if val!='':
                    dict2[key] =val
                    
            print(dict2,"dict2")        
            print(len(dict2))
            data = []  
            a= len(dict2)
            
            for i in dict2.items():
                for k,v in dict2.items():
                    print(k)
                    data2={k:v}
                    data1=list(railwayLocationMaster.objects.filter(**data2).values())
                    for j in data1:
                        if j not in data:
                            data.append(j)

                    print(data1)
            
            return JsonResponse({'data':data},safe=False)
        return JsonResponse({"success":False},status=400)
    except Exception as e: 
        try:
            rm.error_Table.objects.create(fun_name="filter",user_id=request.user,err_details=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})
    
def fetch_details(request):
    try:
        empno=request.GET.get('empno')
        print(empno)
        if(HRMS.objects.filter(empno=empno).exists()):
            # designation_id=m1.HRMS.objects.filter(empno=emp_id)[0].designation_id
            # designation=Designation_Master.objects.filter(designation_master_no=designation_id)[0].designation
            name=HRMS.objects.filter(empno=empno)[0].employee_first_name
            # empname=m1.HRMS.objects.filter(empno=emp_id)[0].empname
            # rly_id=m1.HRMS.objects.filter(empno=emp_id)[0].rly_id_id
            # div_id=m1.HRMS.objects.filter(empno=emp_id)[0].div_id_id
            # email_idd=m1.HRMS.objects.filter(empno=emp_id)[0].email
            # print(rly_id,'___________')
            # print(div_id,'___________')
            # print(name,'first name')
            # desigg=Level_Desig.objects.filter(designation_code=designation)[0].designation
            # rly_code=railwayLocationMaster.objects.filter(rly_unit_code=rly_id)[0].location_code
            # if div_id!=None:
            #     div_code=railwayLocationMaster.objects.filter(rly_unit_code=div_id)[0].location_code
            # else:
            #     div_code=''
            context={
                'name':str(name),
                # 'empname':str(empname),
                # 'rly_code':str(rly_code),
                # 'div_code':str(div_code),
                # 'desigg':str(desigg),
                # 'email_idd':str(email_idd),
            }
            return JsonResponse(context)
    except Exception as e: 
        try:
            rm.error_Table.objects.create(fun_name="fetch_details",user_id=request.user,err_details=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})



def masterTable(request):
    return HttpResponse("<h1>Successful<h1>")

def roster(request):
    return HttpResponse("<h1>Successful<h1>")

def user_list(request):
    # try:
        usermast=rm.MyUser.objects.filter(email=request.user).first()
        rolelist=usermast.user_role
        if str(request.user).startswith('admin'):
            actual_user = str(request.user).split('admin')[1]
        else:
            actual_user = request.user
        empnox = AdminMaster.objects.filter(Q(admin_email=actual_user), user_id__isnull=False).values('rly','user_id')
        #empnox = AdminMaster.objects.filter(Q(admin_email='admin'+str(request.user)) | Q(admin_email='admin'+str(request.user.email)), user_id__isnull=False).values('rly','user_id')
        
        rly_unit_id=None
        cuser = None
        parent_rly = []
        if empnox:
            rly_unit_id = empnox[0]['rly']
            cuser = empnox[0]['user_id']
            child_rly = list(railwayLocationMaster.objects.filter( parent_rly_unit_code  = str(rly_unit_id)).values('rly_unit_code'))
            if len(child_rly)>0:
                child_rly = list(map(lambda x: x['rly_unit_code'], child_rly))
           

        if request.method == 'POST' and request.is_ajax():
            post_type = request.POST.get('post_type') 
            if post_type == 'reject':
                reqno = request.POST.get('reqno')
                remarks = request.POST.get('remarks')
                posting_History.objects.filter(history_id=reqno).update(accepted_remarks=remarks,accepted_date=datetime.now(), forwarded_to=cuser, status = 'Rejected')
                msg = 'Successfuly Rejected'
                return JsonResponse(msg, safe = False) 
            if post_type == 'accept':
                reqno = request.POST.get('reqno')
                remarks = request.POST.get('remarks')
                posting_History.objects.filter(history_id=reqno).update(accepted_remarks=remarks,accepted_date=datetime.now(), forwarded_to=cuser, status = 'Accepted')

                data = list(posting_History.objects.filter(history_id=reqno).values())
                prev_details =list(Level_Desig.objects.filter(designation = data[0]['current_desigination']).values())

                Level_Desig.objects.filter(designation = data[0]['current_desigination']).update(modified_by=cuser,empno_id = data[0]['empno_id'], department_code_id = data[0]['current_department_code_id'],parent_desig_code = data[0]['current_parent_desig_code'],rly_unit_id=data[0]['current_rly_unit_id'],status='P',contactnumber=data[0]['current_contactnumber'],official_email_ID=data[0]['current_official_email_ID'],station_name=data[0]['current_station_name'])
                password = 'Admin@123'

                
                if rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).exists():
                    forgetuser=rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).first()
                    if forgetuser:
                        forgetuser.set_password(password)
                        forgetuser.save()
                        rm.MyUser.objects.filter(username=data[0]['current_official_email_ID']).update(username=None,is_active= False,email = None)
                        rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).update(username=data[0]['current_official_email_ID'],is_active= True,email = data[0]['current_official_email_ID'])
                else:
                    id = list(rm.MyUser.objects.values('id').order_by('-id'))
                    if len(id)>0:
                        id = id[0]['id'] + 1
                    else:
                        id = 1
                    newuser = rm.MyUser.objects.create_user(id = id,username=data[0]['current_official_email_ID'], password=password,email=data[0]['current_official_email_ID'],user_role='user')
                    newuser.is_active= True
                    newuser.is_admin=False
                    newuser.save()
                    myuser_id = list(rm.MyUser.objects.filter(email = data[0]['current_official_email_ID']).values('id'))
                    if len(myuser_id)>0:
                        Level_Desig.objects.filter(designation = data[0]['current_desigination']).update(desig_user_id = myuser_id[0]['id'])
                
                data1 = list(Level_Desig.objects.filter(empno_id = data[0]['empno_id'],designation = data[0]['prev_desigination']).values('official_email_ID'))
                if len(data1)>0:
                    Level_Desig.objects.filter(empno = data[0]['empno_id'],designation = data[0]['prev_desigination']).update(empno = None, status = 'P')
                    newuser = rm.MyUser.objects.filter(email=data1[0]['official_email_ID']).update(is_active= False)

                msg = 'Successfuly Accepted'
                return JsonResponse(msg, safe = False) 
            if post_type == 'request_to_me':
                reqno = request.POST.get('reqno')
                p_reporting_officer = ''
                c_reporting_officer = ''
                emp_details = list(posting_History.objects.filter( history_id = reqno ).values('history_id','done_by',
                    'empno_id' ,'prev_desigination','prev_parent_desig_code','prev_department_code_id__department_name','prev_rly_unit_id__location_code','prev_rly_unit_id__location_type','prev_contactnumber','prev_official_email_ID','prev_station_name',
                    'current_desigination','current_parent_desig_code','current_department_code_id__department_name','current_rly_unit_id__location_code','current_rly_unit_id__location_type','current_contactnumber','current_official_email_ID','current_station_name',
                    'empno_id__empname','empno_id__empmname','empno_id__emplname'
                ))
                if len(emp_details) > 0: 
                    reporting_officer = list(Level_Desig.objects.filter(designation_code = emp_details[0]['prev_parent_desig_code']).values('designation'))
                    if len(reporting_officer) > 0:
                        p_reporting_officer = reporting_officer[0]['designation']
                    else:
                        p_reporting_officer = ''
                    reporting_officer = list(Level_Desig.objects.filter(designation_code = emp_details[0]['current_parent_desig_code']).values('designation'))
                    if len(reporting_officer) > 0:
                        c_reporting_officer = reporting_officer[0]['designation']
                    else:
                        c_reporting_officer = ''
                
                context ={
                    'emp_details':emp_details,
                    'p_reporting_officer':p_reporting_officer,
                    'c_reporting_officer':c_reporting_officer,
                }
                
                return JsonResponse(context, safe = False) 
            if post_type == 'emp_details':
                empno = request.POST.get('empno')
                designation = request.POST.get('designation')
                reporting_officer = ''
                emp_details = list(Level_Desig.objects.filter(empno_id = empno, designation = designation).values('designation','rly_unit_id__location_code','rly_unit_id__location_type','empno_id','empno_id__empname','empno_id__empmname','empno_id__emplname','contactnumber','official_email_ID','department_code__department_name','station_name','empno_id__hrms_id_id','parent_desig_code','status').order_by('-status','designation'))
                if len(emp_details) > 0: 
                    reporting_officer = list(Level_Desig.objects.filter(designation_code = emp_details[0]['parent_desig_code']).values('designation'))
                    if len(reporting_officer) > 0:
                        reporting_officer = reporting_officer[0]['designation']
                    else:
                        reporting_officer = ''
                
                context ={
                    'emp_details':emp_details,
                    'reporting_officer':reporting_officer,
                }
                return JsonResponse(context, safe = False)  
            
            if post_type == 'emp_release':
                empno = request.POST.get('empno')
                charge_type = request.POST.get('charge_type')  
                designation = request.POST.get('designation')
                data = list(Level_Desig.objects.filter(empno_id = empno,designation = designation).values('official_email_ID'))
                msg = 'Operation Failed'
                if len(data)>0:
                    Level_Desig.objects.filter(empno = empno,designation = designation).update(empno = None, status = 'P',modified_by=cuser)
                    newuser = rm.MyUser.objects.filter(email=data[0]['official_email_ID']).update(is_active= False)
                    
                    msg = 'Successfully relinquished'
                return JsonResponse(msg, safe = False)
            if post_type == 'new_emp':
                empno = request.POST.get('empno')
                emp_no_details = list(rm.empmast.objects.filter(empno = empno).values())
                lev_desig_details = list(Level_Desig.objects.filter(empno_id = empno).values('designation','parent_desig_code','department_code__department_name','rly_unit_id__location_type','rly_unit_id__location_code','status','official_email_ID','contactnumber','station_name').order_by('-status'))
                if len(lev_desig_details) > 0: 
                    for i in range(len(lev_desig_details)):
                        reporting_officer = list(Level_Desig.objects.filter(designation_code = lev_desig_details[i]['parent_desig_code']).values('designation'))
                        if len(reporting_officer) > 0:
                            reporting_officer = reporting_officer[0]['designation']
                        else:
                            reporting_officer = ''
                        lev_desig_details[i].update({'reporting_officer':reporting_officer})
                response = {
                    'emp_no_details' : emp_no_details,
                    'lev_desig_details' : lev_desig_details,
                }
                return JsonResponse(response, safe = False)
            if post_type == 'desig_search':
                designation = request.POST.get('designation')
                lev_desig_details = list(Level_Desig.objects.filter(designation = designation).values('parent_desig_code','department_code','rly_unit_id','official_email_ID','contactnumber','station_name').order_by('status'))
                if len(lev_desig_details) > 0: 
                    for i in range(len(lev_desig_details)):
                        reporting_officer = ''
                        if lev_desig_details[i]['parent_desig_code'] is not None:
                            reporting_officer = list(Level_Desig.objects.filter(designation_code = lev_desig_details[i]['parent_desig_code']).values('designation'))
                            if len(reporting_officer) > 0:
                                reporting_officer = reporting_officer[i]['designation']
                            else:
                                reporting_officer = ''
                        lev_desig_details[i].update({'reporting_officer':reporting_officer})
                    
                    rly_unit_id = lev_desig_details[i]['rly_unit_id']
                    rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
                    rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
                    rep_officer = list(Level_Desig.objects.filter(Q(rly_unit = rly_unit_id) | Q(rly_unit__in = rly_unit_det)).values('designation'))
                    rep_officer = list(map( lambda x: x['designation'],rep_officer))
                    all_station = list(station_master.objects.filter(Q(rly_id_id = rly_unit_id) | Q(div_id_id = rly_unit_id)).values('station_name').distinct().order_by('station_name'))
                    if lev_desig_details[0]['station_name'] is not None:
                        all_station.append({'station_name':lev_desig_details[0]['station_name']})
                
                context = {
                    'lev_desig_details' : lev_desig_details,
      
              'rep_officer':rep_officer,
                    'all_station':all_station,
                }
                return JsonResponse(context, safe = False)
            
            if post_type == 'new_joining':
                empno = request.POST.get('empno')
                txt_new_joining_designation = request.POST.get('txt_new_joining_designation')
                charge_type_new_joining = request.POST.get('charge_type_new_joining')
                department_new_joining = request.POST.get('department_new_joining')
                place_new_joining = request.POST.get('place_new_joining')
                reporting_officer_new_joining = request.POST.get('reporting_officer_new_joining')
                if reporting_officer_new_joining == '':
                    reporting_officer_new_joining = None
                else:
                    dt1 = list(Level_Desig.objects.filter(designation = reporting_officer_new_joining).values('designation_code'))
                    reporting_officer_new_joining = dt1[0]['designation_code']
                contact_new_joining = request.POST.get('contact_new_joining')
                email_new_joining = request.POST.get('email_new_joining')
                station_new_joining = request.POST.get('station_new_joining')
                remarks_new_joining = request.POST.get('remarks_new_joining')
                msg = 'Not changed, please contact admin'
                password = 'Admin@123'
                if charge_type_new_joining == 'D':
                    if Level_Desig.objects.filter(~Q(designation = txt_new_joining_designation), official_email_ID=email_new_joining).exists():
                        msg = 'e-mail id is already used with another designation, Request cannot be processed'
                    elif Level_Desig.objects.filter(designation = txt_new_joining_designation, empno = empno , status = 'D').exists():
                        msg = 'Same user is already Exists as Dual charge for the same post'
                    elif Level_Desig.objects.filter(~Q( empno = empno), contactnumber = contact_new_joining).exists():
                        msg = 'Contact number already present, with some other designation, Request cannot be processed'
                    else:
                        posting_History.objects.create(empno_id = empno,done_by = cuser,current_desigination = txt_new_joining_designation,current_parent_desig_code= reporting_officer_new_joining,current_department_code_id=department_new_joining,current_rly_unit_id=place_new_joining,
                        current_contactnumber=contact_new_joining,current_official_email_ID=email_new_joining,current_station_name=station_new_joining,charge_type=charge_type_new_joining,created_date=datetime.now(),accepted_date=datetime.now(),status='Accepted',created_remarks=remarks_new_joining)
                        prev_details =list(Level_Desig.objects.filter(designation = txt_new_joining_designation).values())
                        Level_Desig.objects.filter(designation = txt_new_joining_designation).update(modified_by=cuser,empno_id = empno, department_code_id = department_new_joining,parent_desig_code = reporting_officer_new_joining,rly_unit_id=place_new_joining,status=charge_type_new_joining,contactnumber=contact_new_joining,official_email_ID=email_new_joining,station_name=station_new_joining)
                        if rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).exists():
                            forgetuser=rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).first()
                            if forgetuser:
                                forgetuser.set_password(password)
                                forgetuser.save()
                                rm.MyUser.objects.filter(username=email_new_joining).update(username=None,is_active= False,email = None)
                                rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).update(username=email_new_joining,is_active= True,email = email_new_joining)
                        else:
                            id = list(rm.MyUser.objects.values('id').order_by('-id'))
                            if len(id)>0:
                                id = id[0]['id'] + 1
                            else:
                                id = 1
                            newuser = rm.MyUser.objects.create_user(id = id,username=email_new_joining, password=password,email=email_new_joining,user_role='user')
                            newuser.is_active= True
                            newuser.is_admin=False
                            newuser.save()
                            myuser_id = list(rm.MyUser.objects.filter(email = email_new_joining).values('id'))
                            if len(myuser_id)>0:
                                Level_Desig.objects.filter(designation = txt_new_joining_designation).update(desig_user_id = myuser_id[0]['id'])
                        msg = 'Dual charge is created successfully'
                

                if charge_type_new_joining == 'P':
                    if str(request.user).startswith('admin'):
                        actual_user = str(request.user).split('admin')[1]
                    else:
                        actual_user = request.user
                    empnox_det = AdminMaster.objects.filter(Q(admin_email=actual_user), user_id__isnull=False).values('rly','user_id')
                    #empnox_det = AdminMaster.objects.filter(Q(admin_email='admin'+str(request.user)) | Q(admin_email='admin'+str(request.user.email)), user_id__isnull=False).values('rly','user_id')
                    rly_unit_id_det=None
                    cuser_det = None
                    if empnox_det:
                        rly_unit_id_det = empnox_det[0]['rly']
                        cuser_det = empnox_det[0]['user_id']
                    if Level_Desig.objects.filter(~Q(designation = txt_new_joining_designation), official_email_ID=email_new_joining).exists():
                        msg = 'e-mail id is already used with another designation, Request cannot be processed'

                    elif Level_Desig.objects.filter(designation = txt_new_joining_designation, empno = empno , status = 'P').exists():
                        msg = 'Same user is already Exists as Primary charge for the same post'
                    
                    elif Level_Desig.objects.filter(~Q(designation = txt_new_joining_designation),contactnumber=contact_new_joining,status = 'P').exists():
                        msg = 'Contact number is already used with another designation, Request cannot be processed'

                    elif Level_Desig.objects.filter(empno = empno , status = 'P', rly_unit = rly_unit_id_det).exists():
                        prev_details =list(Level_Desig.objects.filter(empno = empno , status = 'P', rly_unit = rly_unit_id_det).values())
                
                        if len(prev_details)>0:
                            Level_Desig.objects.filter(empno_id = empno,designation = prev_details[0]['designation']).update(modified_by=cuser_det,empno_id = None, status = 'P')
                            rm.MyUser.objects.filter(email=prev_details[0]['official_email_ID']).update(is_active= False)
                           
                        
                        posting_History.objects.create(empno_id = empno,done_by = cuser,current_desigination = txt_new_joining_designation,current_parent_desig_code= reporting_officer_new_joining,current_department_code_id=department_new_joining,current_rly_unit_id=place_new_joining,
                        prev_desigination=prev_details[0]['designation'],prev_parent_desig_code=prev_details[0]['parent_desig_code'],prev_department_code_id=prev_details[0]['department_code_id'],prev_rly_unit_id=prev_details[0]['rly_unit_id'],prev_contactnumber=prev_details[0]['contactnumber'],prev_official_email_ID=prev_details[0]['official_email_ID'],prev_station_name=prev_details[0]['station_name'],
                        current_contactnumber=contact_new_joining,current_official_email_ID=email_new_joining,current_station_name=station_new_joining,charge_type=charge_type_new_joining,created_date=datetime.now(),accepted_date=datetime.now(),status='Accepted',created_remarks=remarks_new_joining)
                        
                        Level_Desig.objects.filter(designation = txt_new_joining_designation).update(modified_by=cuser_det,empno_id = empno, department_code_id = department_new_joining,parent_desig_code = reporting_officer_new_joining,rly_unit_id=place_new_joining,status=charge_type_new_joining,contactnumber=contact_new_joining,official_email_ID=email_new_joining,station_name=station_new_joining)
                        if rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).exists():
                            forgetuser=rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).first()
                            if forgetuser:
                                forgetuser.set_password(password)
                                forgetuser.save()
                                rm.MyUser.objects.filter(username=email_new_joining).update(username=None,is_active= False,email = None)
                                rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).update(username=email_new_joining,is_active= True,email = email_new_joining)
                        else:
                            id = list(rm.MyUser.objects.values('id').order_by('-id'))
                            if len(id)>0:
                                id = id[0]['id'] + 1
                            else:
                                id = 1
                            newuser = rm.MyUser.objects.create_user(id = id,username=email_new_joining, password=password,email=email_new_joining,user_role='user')
                            newuser.is_active= True
                            newuser.is_admin=False
                            newuser.save()
                            myuser_id = list(rm.MyUser.objects.filter(email = email_new_joining).values('id'))
                            if len(myuser_id)>0:
                                Level_Desig.objects.filter(designation = txt_new_joining_designation).update(desig_user_id = myuser_id[0]['id'])
                        msg = 'Primary charge is updated successfully'

                    elif Level_Desig.objects.filter(empno = empno , status = 'P').exists():
                        prev_details =list(Level_Desig.objects.filter(empno = empno , status = 'P').values())
                        if posting_History.objects.filter(done_by = cuser,status='Forwarded',empno = empno).exists():
                            msg = f"request already exists for the employee, To request again pull back the previous request"
                        else:
                            posting_History.objects.create(empno_id = empno,done_by = cuser,current_desigination = txt_new_joining_designation,current_parent_desig_code= reporting_officer_new_joining,current_department_code_id=department_new_joining,current_rly_unit_id=place_new_joining,
                            prev_desigination=prev_details[0]['designation'],prev_parent_desig_code=prev_details[0]['parent_desig_code'],prev_department_code_id=prev_details[0]['department_code_id'],prev_rly_unit_id=prev_details[0]['rly_unit_id'],prev_contactnumber=prev_details[0]['contactnumber'],prev_official_email_ID=prev_details[0]['official_email_ID'],prev_station_name=prev_details[0]['station_name'],
                            current_contactnumber=contact_new_joining,current_official_email_ID=email_new_joining,current_station_name=station_new_joining,charge_type=charge_type_new_joining,created_date=datetime.now(),status='Forwarded',created_remarks=remarks_new_joining)
                            prev_details =list(Level_Desig.objects.filter(empno = empno , status = 'P').values('rly_unit__location_code'))
                            msg = f"Request sent to {prev_details[0]['rly_unit__location_code']} for relinquished, once accepted primary charge will be updated"
                    
                    else:
                        posting_History.objects.create(empno_id = empno,done_by = cuser,current_desigination = txt_new_joining_designation,current_parent_desig_code= reporting_officer_new_joining,current_department_code_id=department_new_joining,current_rly_unit_id=place_new_joining,
                        current_contactnumber=contact_new_joining,current_official_email_ID=email_new_joining,current_station_name=station_new_joining,charge_type=charge_type_new_joining,created_date=datetime.now(),accepted_date=datetime.now(),status='Accepted',created_remarks=remarks_new_joining)
                        prev_details =list(Level_Desig.objects.filter(designation = txt_new_joining_designation).values())
                        Level_Desig.objects.filter(designation = txt_new_joining_designation).update(modified_by=cuser_det,empno_id = empno, department_code_id = department_new_joining,parent_desig_code = reporting_officer_new_joining,rly_unit_id=place_new_joining,status=charge_type_new_joining,contactnumber=contact_new_joining,official_email_ID=email_new_joining,station_name=station_new_joining)
                        if rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).exists():
                            forgetuser=rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).first()
                            if forgetuser:
                                forgetuser.set_password(password)
                                forgetuser.save()
                                rm.MyUser.objects.filter(username=email_new_joining).update(username=None,is_active= False,email = None)
                                rm.MyUser.objects.filter(id = prev_details[0]['desig_user_id']).update(username=email_new_joining,is_active= True,email = email_new_joining)
                        else:
                            id = list(rm.MyUser.objects.values('id').order_by('-id'))
                            if len(id)>0:
                                id = id[0]['id'] + 1
                            else:
                                id = 1
                            newuser = rm.MyUser.objects.create_user(id = id,username=email_new_joining, password=password,email=email_new_joining,user_role='user')
                            newuser.is_active= True
                            newuser.is_admin=False
                            newuser.save()
                            myuser_id = list(rm.MyUser.objects.filter(email = email_new_joining).values('id'))
                            if len(myuser_id)>0:
                                Level_Desig.objects.filter(designation = txt_new_joining_designation).update(desig_user_id = myuser_id[0]['id'])
                        msg = 'Primary charge is created successfully'
                return JsonResponse(msg, safe = False)
            
            if post_type == 'history':
                history_id = request.POST.get('history_id')
                history_data = list(posting_History.objects.filter(history_id=history_id).values())
                admin_1 = list(posting_History.objects.filter(history_id=history_id).values('current_rly_unit__location_code'))
                if len(admin_1)>0:
                    admin_1 = 'Admin ' + str(admin_1[0]['current_rly_unit__location_code'])
                else:
                    admin_1 = 'Admin'
                pending = []
                if history_data[0]['prev_rly_unit_id']  is not None:
                    for i in range(len(history_data)):
                        prev_rly_unit = history_data[i]['prev_rly_unit_id']
                        if rly_unit_id == prev_rly_unit:
                            if AdminMaster.objects.filter(status='Active',rly = prev_rly_unit).exists():
                                dt_list=list(AdminMaster.objects.filter(status='Active',rly = prev_rly_unit).values())
                                pending.extend(dt_list)
                        
                        elif prev_rly_unit in child_rly:
                            if AdminMaster.objects.filter(status='Active',rly = prev_rly_unit).exists():
                                dt_list=list(AdminMaster.objects.filter(status='Active',rly = prev_rly_unit).values())
                                pending.extend(dt_list)
                    if len(pending) == 0:
                        dt_list=list(AdminMaster.objects.filter(status='Active',user_id = '111111').values())
                        pending.extend(dt_list)
                

                context = {
                    'history_data':history_data,
                    'pending':pending,
                    'admin_1':admin_1,
                }
                print(admin_1)
                return JsonResponse(context, safe = False) 
            
            if post_type == 'pullback':
                history_id = request.POST.get('history_id')
                posting_History.objects.filter(history_id=history_id).delete()
                msg = 'Successfuly Pulled Back'
                return JsonResponse(msg, safe = False) 
            
            if post_type == 'station':
                val = request.POST.get('val')
                all_station = list(station_master.objects.filter(Q(rly_id_id = val) | Q(div_id_id = val)).values('station_name').distinct().order_by('station_name'))
                return JsonResponse(all_station, safe = False) 
            return JsonResponse({"success":False}, status=400)
        
        details_data = list(Level_Desig.objects.filter((Q(rly_unit = rly_unit_id) | Q(rly_unit__in=railwayLocationMaster.objects.filter(parent_rly_unit_code = str(rly_unit_id)).values('rly_unit_code')))).values('designation','rly_unit_id__location_code','rly_unit_id__location_type','empno_id','empno_id__empname','empno_id__empmname','empno_id__emplname','contactnumber','official_email_ID').order_by('designation'))
        rly_emp_designation = list(map(lambda x: x['designation'],details_data))
        new_emp_no = list(rm.empmast.objects.values('empno','hrms_id' , 'empname', 'empmname', 'emplname').order_by('empname'))
        all_department = list(departMast.objects.filter(delete_flag = False).values('department_code','department_name').order_by('department_name'))
        all_railway = list(railwayLocationMaster.objects.filter((Q(parent_rly_unit_code = str(rly_unit_id)) | Q(rly_unit_code = rly_unit_id)),location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))
        all_station = list(station_master.objects.filter(Q(rly_id_id = rly_unit_id) | Q(div_id_id = rly_unit_id)).values('station_name').distinct().order_by('station_name'))
        requested = posting_History.objects.filter(done_by = cuser).all().order_by('-created_date')
        pending = []
        pending11 = list(posting_History.objects.filter(status='Forwarded').values().order_by('-created_date'))
        
        if rolelist == 'admin_super':
            for i in range(len(pending11)):
                pending.append(pending11[i])
        else:
            for i in range(len(pending11)):
                prev_rly_unit = pending11[i]['prev_rly_unit_id']
                if rly_unit_id == prev_rly_unit:
                    if AdminMaster.objects.filter(status='Active',rly = prev_rly_unit).exists():
                        pending.append(pending11[i])
                
                elif prev_rly_unit in child_rly:
                    if AdminMaster.objects.filter(status='Active',rly = prev_rly_unit).exists():
                        pending.append(pending11[i])
        print("Testing for admin user list")
        context ={
            'details_data' : details_data,
            'new_emp_no' : new_emp_no,
            'rly_emp_designation' : rly_emp_designation,
            'all_department':all_department,
            'all_railway' : all_railway,
            'all_station' : all_station,
            'requested' : requested,
            'pending':pending,

        }
        return render(request, "user_list.html", context)


def designation_request(request):   
    from datetime import datetime 
    usermast = MEM_usersn.objects.filter(MAV_username = request.session['username']).first()
    rolelist = usermast.MAV_userlvlcode_id

    # empnox = AdminMaster.objects.filter(Q(user_id = usermast.MAV_userid), user_id__isnull = False).values('rly_id','user_id')
    rly_unit_id = None
    cuser = None
    parent_rly = []
    if usermast:
        rly_unit_id = usermast.MAV_rlycode_id
        cuser = usermast.MAV_userid
        child_rly = list(railwayLocationMaster.objects.filter( parent_rly_unit_code  = str(rly_unit_id)).values('rly_unit_code'))
        if len(child_rly)>0:
            child_rly = list(map(lambda x: x['rly_unit_code'], child_rly))
    if request.method == 'POST' and request.is_ajax():
        post_type = request.POST.get('post_type')
        if post_type == 'similar':
            post = request.POST.get('post')
            current_user = request.user
            # if str(request.user).startswith('admin'):
            #     actual_user = str(request.user).split('admin')[1]
            # else:
            #     actual_user = request.user
            # empnox = AdminMaster.objects.filter(Q(admin_email=actual_user), user_id__isnull=False).values('rly','user_id') 
            # empnox = AdminMaster.objects.filter(Q(user_id=usermast.MAV_userid), user_id__isnull=False).values('rly','user_id')           
            rly_unit_id=None
            if usermast:
                rly_unit_id = usermast.MAV_rlycode_id
            rep_officer = list(MED_LVLDESG.objects.filter((Q(MAIRLYUNIT = rly_unit_id)|Q(MAIRLYUNIT_id__parent_rly_unit_code  = str(rly_unit_id))),MAVDESG__startswith= post+'/').values('MAVDESG'))
            rep_officer = list(map( lambda x: x['MAVDESG'],rep_officer))
            rep_officer = ', '.join(rep_officer)
            context = {
                'rep_officer':rep_officer,
            }
            return JsonResponse(context,safe=False)
    
        if post_type == 'emp_details':
            designation = request.POST.get('designation')
            reporting_officer = ''
            emp_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAVDLVL','MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAIPC7LVLMIN','MAIPCLVLMAX','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAVSTTNNAME','MAVPARDESGCODE','MAVSTTS').order_by('-MAVSTTS','MAVDESG'))
            if len(emp_details) > 0: 
                reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = emp_details[0]['MAVPARDESGCODE']).values('MAVDESG'))
                if len(reporting_officer) > 0:
                    reporting_officer = reporting_officer[0]['MAVDESG']
                else:
                    reporting_officer = ''
            context ={
                'emp_details':emp_details,
                'reporting_officer':reporting_officer,
            }
            return JsonResponse(context, safe = False) 
        if post_type == 'desig_search':
            designation = request.POST.get('designation')
            lev_desig_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAIPC7LVLMIN','MAIPCLVLMAX','MAVPARDESGCODE','MAVDEPTCODE','MAIRLYUNIT','MAVOFCLMAILID','MAVCONTNUM','MAVSTTNNAME','MAVSTTS').order_by('MAVSTTS'))
            if len(lev_desig_details) > 0: 
                for i in range(len(lev_desig_details)):
                    reporting_officer = ''
                    if lev_desig_details[i]['MAVPARDESGCODE'] is not None:
                        reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = lev_desig_details[i]['MAVPARDESGCODE']).values('MAVDESG'))
                        if len(reporting_officer) > 0:
                            reporting_officer = reporting_officer[i]['MAVDESG']
                        else:
                            reporting_officer = ''
                    lev_desig_details[i].update({'reporting_officer':reporting_officer})
                
                rly_unit_id = lev_desig_details[i]['MAIRLYUNIT']
                rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
                rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
                rep_officer = list(MED_LVLDESG.objects.filter(Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in = rly_unit_det)).values('MAVDESG'))
                rep_officer = list(map( lambda x: x['MAVDESG'],rep_officer))
                all_station = list(station_master.objects.filter(Q(rly_id_id = rly_unit_id) | Q(div_id_id = rly_unit_id)).values('station_name').distinct().order_by('station_name'))
                if lev_desig_details[0]['MAVSTTNNAME'] is not None:
                    all_station.append({'station_name':lev_desig_details[0]['MAVSTTNNAME']})
            context = {
                'lev_desig_details' : lev_desig_details,
                'rep_officer':rep_officer,
                'all_station':all_station,
            }
            return JsonResponse(context, safe = False)
        if post_type == 'station':
            val = request.POST.get('val')
            all_station = list(station_master.objects.filter(Q(rly_id_id = val) | Q(div_id_id = val)).values('station_name').distinct().order_by('station_name'))
            return JsonResponse(all_station, safe = False)  
        if post_type == 'saveDataChanged':
            msg = 'Please contact superadmin'
            pre_chargetype = request.POST.get('pre_chargetype')
            # #designation,pre_email,pre_contact,pre_minlevel,pre_maxlevel,pre_station,pre_place,pre_department,pre_reporting_officer,pre_remarks
            # designation=designation,rly_unit=pre_place,department_code=pre_department,station_name=pre_station,contactnumber=pre_contact,official_email_ID=pre_email
            # ,pc7_levelmin=pre_minlevel,pc7_levelmax=pre_maxlevel,parent_desig_code=pre_reporting_officer
            designation = request.POST.get('designation')
            pre_email = request.POST.get('pre_email')
            pre_contact = request.POST.get('pre_contact')
            pre_minlevel = request.POST.get('pre_minlevel')
            pre_maxlevel = request.POST.get('pre_maxlevel')
            pre_station = request.POST.get('pre_station')
            pre_place = request.POST.get('pre_place')
            pre_department = request.POST.get('pre_department')
            pre_reporting_officer = request.POST.get('pre_reporting_officer')
            pre_remarks = request.POST.get('pre_remarks')
            edit_forward_to_officer = request.POST.get('edit_forward_to_officer')
            if edit_forward_to_officer == '':
                edit_forward_to_officer = None
            

            if pre_reporting_officer is not None or pre_reporting_officer != '':
                reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = pre_reporting_officer).values('MAADESGCODE'))
                if len(reporting_officer) > 0:
                    pre_reporting_officer = reporting_officer[0]['MAADESGCODE']
                else:
                    pre_reporting_officer = None
            else:
                    pre_reporting_officer = None

            if MED_LVLDESG.objects.filter(~Q(MAVDESG = designation), MAVOFCLMAILID=pre_email).exists():
                msg = 'e-mail id is already used with another designation, Request cannot be processed' 

            elif pre_contact == 'P' and MED_LVLDESG.objects.filter(~Q(MAVDESG = designation),MAVCONTNUM=pre_contact, MAVSTTS = 'P').exists():
                msg = 'Contact number is already used with another designation, Request cannot be processed'

            elif MED_LVLDESG.objects.filter(MAVSTTS = pre_chargetype,MAVDESG=designation,MAIRLYUNIT=pre_place,MAVDEPTCODE=pre_department,MAVSTTNNAME=pre_station,MAVCONTNUM=pre_contact,MAVOFCLMAILID=pre_email,
                        MAIPC7LVLMIN=pre_minlevel,MAIPCLVLMAX=pre_maxlevel,MAVPARDESGCODE=pre_reporting_officer).exists():
                msg = 'All the field having the previous value only, Request cannot be processed'
            
            elif designation_Change_Request.objects.filter(status='Forwarded',request_type='Modification',desigination=designation).exists():
                msg = 'Request already exist, pull back the existing request to give new request' 
            
            else:
                prevData = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values())
                designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=pre_remarks,desigination=designation,status='Forwarded',request_type='Modification',
                    prev_charge = prevData[0]['MAVSTTS'],prev_parent_desig_code = prevData[0]['MAVPARDESGCODE'],prev_department_code_id=prevData[0]['MAVDEPTCODE_id'],prev_rly_unit_id=prevData[0]['MAIRLYUNIT_id'],prev_contactnumber=prevData[0]['MAVCONTNUM'],prev_official_email_ID=prevData[0]['MAVOFCLMAILID'],prev_station_name=prevData[0]['MAVSTTNNAME'],prev_maxlevel=prevData[0]['MAIPC7LVLMIN'],prev_minlevel=prevData[0]['MAIPCLVLMAX'],
                    forward_to_officer = edit_forward_to_officer,current_charge = pre_chargetype,current_parent_desig_code=pre_reporting_officer,current_department_code_id=pre_department,current_rly_unit_id=pre_place,current_contactnumber=pre_contact,current_official_email_ID=pre_email,current_station_name=pre_station,current_maxlevel=pre_maxlevel,current_minlevel=pre_minlevel)
                
                msg = 'success'

            return JsonResponse(msg, safe = False)
        if post_type == 'saveDataChangedSelf':
            msg = 'Please contact superadmin'
            pre_chargetype = request.POST.get('pre_chargetype')
            designation = request.POST.get('designation')
            pre_email = request.POST.get('pre_email')
            pre_contact = request.POST.get('pre_contact')
            pre_minlevel = request.POST.get('pre_minlevel')
            pre_maxlevel = request.POST.get('pre_maxlevel')
            pre_station = request.POST.get('pre_station')
            pre_place = request.POST.get('pre_place')
            pre_department = request.POST.get('pre_department')
            pre_reporting_officer = request.POST.get('pre_reporting_officer')
            pre_remarks = request.POST.get('pre_remarks')
            edit_forward_to_officer = request.POST.get('edit_forward_to_officer')
            if edit_forward_to_officer == '':
                edit_forward_to_officer = None
            

            if pre_reporting_officer is not None or pre_reporting_officer != '':
                reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = pre_reporting_officer).values('MAADESGCODE'))
                if len(reporting_officer) > 0:
                    pre_reporting_officer = reporting_officer[0]['MAADESGCODE']
                else:
                    pre_reporting_officer = None
            else:
                    pre_reporting_officer = None

            if MED_LVLDESG.objects.filter(~Q(MAVDESG = designation), MAVOFCLMAILID = pre_email).exists():
                msg = 'e-mail id is already used with another designation, Request cannot be processed' 

            elif pre_contact == 'P' and MED_LVLDESG.objects.filter(~Q(MAVDESG = designation), MAVCONTNUM = pre_contact, MAVSTTS = 'P').exists():
                msg = 'Contact number is already used with another designation, Request cannot be processed'

            elif MED_LVLDESG.objects.filter(MAVDESG=designation,MAIRLYUNIT=pre_place,MAVDEPTCODE=pre_department,MAVSTTNNAME=pre_station,MAVCONTNUM=pre_contact,MAVOFCLMAILID=pre_email,
                        MAVSTTS = pre_chargetype,MAIPC7LVLMIN=pre_minlevel,MAIPCLVLMAX=pre_maxlevel,MAVPARDESGCODE=pre_reporting_officer).exists():
                msg = 'All the field having the previous value only, Request cannot be processed'
            
            elif designation_Change_Request.objects.filter(status='Forwarded',request_type='Modification',desigination=designation).exists():
                msg = 'Request already exist, pull back the existing request to give new request' 
            
            else:
                prevData = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values())
                designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=pre_remarks,desigination=designation,status='Forwarded',request_type='Modification',
                    prev_charge = prevData[0]['MAVSTTS'],prev_parent_desig_code = prevData[0]['MAVPARDESGCODE'],prev_department_code_id=prevData[0]['MAVDEPTCODE_id'],prev_rly_unit_id=prevData[0]['MAIRLYUNIT_id'],prev_contactnumber=prevData[0]['MAVCONTNUM'],prev_official_email_ID=prevData[0]['MAVOFCLMAILID'],prev_station_name=prevData[0]['MAVSTTNNAME'],prev_maxlevel=prevData[0]['MAIPC7LVLMIN'],prev_minlevel=prevData[0]['MAIPCLVLMAX'],
                    forward_to_officer = edit_forward_to_officer,
                    current_charge = pre_chargetype,
                    current_parent_desig_code=pre_reporting_officer,current_department_code_id=pre_department,current_rly_unit_id=pre_place,current_contactnumber=pre_contact,current_official_email_ID=pre_email,current_station_name=pre_station,current_maxlevel=pre_maxlevel,current_minlevel=pre_minlevel)
                
                record_id = list(designation_Change_Request.objects.values('record_id').order_by('-record_id'))[0]['record_id']
                pullBackRemark = 'Self Accepted'
                msg = ''
                if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
                    password = 'Admin@123'
                    act_data = list(designation_Change_Request.objects.filter(record_id=record_id).values())
                    
                    if act_data[0]['request_type'] != 'New':

                        if act_data[0]['current_parent_desig_code'] is not None:
                            reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
                        else:
                            reporting_officer_new_joining = None

                        prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
                        div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                        if len(div_id_id) > 0:
                            hq_id_id = act_data[0]['current_rly_unit_id']
                            div_id_id = None
                        else:
                            hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                            
                            if hq_id_id[0]['location_type'] in ['DIV','WS']:
                                div_id_id = act_data[0]['current_rly_unit_id']
                            else:
                                div_id_id = None
                            hq_id_id = hq_id_id[0]['parent_rly_unit_code']
                            

                        MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVMDFDBY=cuser,MAVDEPTCODE = act_data[0]['current_department_code_id'],
                        MAVSTTS = pre_chargetype,MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT=act_data[0]['current_rly_unit_id'],hq_id_id=hq_id_id,div_id_id=div_id_id,
                        MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
                        MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],MAVSTTNNAME=act_data[0]['current_station_name'])
   
                        designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
                        msg = 'Successfully Accepted the Modification'
                    else:
                        if MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).exists():
                            msg = 'Designation already present'
                        else:
                            if act_data[0]['current_parent_desig_code'] is not None:
                                reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
                            else:
                                reporting_officer_new_joining = None

                            prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
                            st_post = act_data[0]['desigination'].split('/')[0]
                            data = list(Post_master.objects.filter(post_code=st_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                            
                            if len(data)>0:
                                category = data[0]['category']
                            else:
                                if st_post == 'SSE':
                                    category = st_post
                                else:
                                    category = None

                            
                            id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
                            if len(id)>0:
                                id = id[0]['MAADESGCODE'] + 1
                            else:
                                id = 1

                            get_department_name = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False,MACDEPTCODE=act_data[0]['current_department_code_id']).values('MAVDEPTNAME').order_by('MAVDEPTNAME'))
                            if len(get_department_name)>0:
                                get_department_name = get_department_name[0]['MAVDEPTNAME']
                            else:
                                get_department_name = None

                           
                            div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                            if len(div_id_id) > 0:
                                hq_id_id = act_data[0]['current_rly_unit_id']
                                div_id_id = None
                            else:
                                hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                
                                if hq_id_id[0]['location_type'] in ['DIV','WS']:
                                    div_id_id = act_data[0]['current_rly_unit_id']
                                else:
                                    div_id_id = None
                                hq_id_id = hq_id_id[0]['parent_rly_unit_code']

                            MED_LVLDESG.objects.create(hq_id_id=hq_id_id,div_id_id=div_id_id,MAADESGCODE = id,MATEFCTDATE=datetime.now(),MAVDLVL=category,
                                MAVSTTS = pre_chargetype,MAVDESG = act_data[0]['desigination'],MAVMDFDBY=cuser,
                                MAVDEPTCODE_id = act_data[0]['current_department_code_id'],MAVDEPT = get_department_name,
                            MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT_id=act_data[0]['current_rly_unit_id'],
                            MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
                            MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],
                            MAVSTTNNAME=act_data[0]['current_station_name'])

                            designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
                            msg = 'Successfully Accepted the New Designation'

                else:
                    msg = 'Failed to Accept'

                msg = 'success'

            return JsonResponse(msg, safe = False)
        
        if post_type == 'getRecord':
            record_id = request.POST.get('record_id')   
            record_data = list(designation_Change_Request.objects.filter(record_id=record_id).values(
                 'current_charge','prev_charge','record_id','request_by','request_date','request_remarks','desigination','status','request_type','action_by','action_date','action_remarks',
                'prev_parent_desig_code','prev_department_code__MAVDEPTNAME','prev_rly_unit__location_code','prev_rly_unit__location_type','prev_rly_unit__location_description','prev_contactnumber','prev_official_email_ID','prev_station_name','prev_maxlevel','prev_minlevel',
                'current_parent_desig_code','current_department_code__MAVDEPTNAME','current_rly_unit__location_code','current_rly_unit__location_type','current_rly_unit__location_description','current_contactnumber','current_official_email_ID','current_station_name','current_maxlevel','current_minlevel'
            ))
            if len(record_data) > 0: 
                reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = record_data[0]['prev_parent_desig_code']).values('MAVDESG'))
                if len(reporting_officer) > 0:
                    prev_reporting_officer = reporting_officer[0]['MAVDESG']
                else:
                    prev_reporting_officer = ''
                
                reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = record_data[0]['current_parent_desig_code']).values('MAVDESG'))
                if len(reporting_officer) > 0:
                    curr_reporting_officer = reporting_officer[0]['MAVDESG']
                else:
                    curr_reporting_officer = ''
                action_by = '-'
                if record_data[0]['action_by'] != None:
                    d1 = list(MEM_usersn.objects.filter(MAV_userid = record_data[0]['action_by']).values('MAV_userid','MAV_userdesig'))
                    if len(d1):
                        action_by = str(d1[0]['MAV_userid']) + '-' + d1[0]['MAV_userdesig']
                    
                request_by = '-'
                if record_data[0]['request_by'] != None:
                    d1 = list(MEM_usersn.objects.filter(MAV_userid = record_data[0]['request_by']).values('MAV_userid','MAV_userdesig'))
                    if len(d1):
                        request_by = str(d1[0]['MAV_userid']) + '-' + d1[0]['MAV_userdesig']
                    
                record_data[0].update({'request_by' : request_by, 'action_by' : action_by, 'prev_parent_desig_code':prev_reporting_officer,'current_parent_desig_code':curr_reporting_officer})
            
            return JsonResponse(record_data, safe = False)  
        if post_type == 'pullback':
            record_id = request.POST.get('record_id')
            pullBackRemark = request.POST.get('pullBackRemark')
            msg = ''
            if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
                designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Pulled Back')
                msg = 'Successfully Pulled Back'
            else:
                msg = 'Failed to Pull Back'
            return JsonResponse(msg, safe = False)
        if post_type == 'accept':
            record_id = request.POST.get('record_id')
            pullBackRemark = request.POST.get('pullBackRemark')
            msg = ''
            if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
                password = 'Admin@123'
                act_data = list(designation_Change_Request.objects.filter(record_id=record_id).values())
                
                if act_data[0]['request_type'] != 'New':

                    if act_data[0]['current_parent_desig_code'] is not None:
                        reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
                    else:
                        reporting_officer_new_joining = None

                    prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
                    div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                    if len(div_id_id) > 0:
                        hq_id_id = act_data[0]['current_rly_unit_id']
                        div_id_id = None
                    else:
                        hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                        
                        if hq_id_id[0]['location_type'] in ['DIV','WS']:
                            div_id_id = act_data[0]['current_rly_unit_id']
                        else:
                            div_id_id = None
                        hq_id_id = hq_id_id[0]['parent_rly_unit_code']
                        

                    MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVMDFDBY=cuser,MAVDEPTCODE = act_data[0]['current_department_code_id'],
                    MAVSTTS = act_data[0]['current_charge'],MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT=act_data[0]['current_rly_unit_id'],hq_id_id=hq_id_id,div_id_id=div_id_id,
                    MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
                    MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],MAVSTTNNAME=act_data[0]['current_station_name'])
                    designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
                    msg = 'Successfully Accepted the Modification'
                else:
                    if MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).exists():
                        msg = 'Designation already present'
                    else:
                        if act_data[0]['current_parent_desig_code'] is not None:
                            reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
                        else:
                            reporting_officer_new_joining = None

                        prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
                        st_post = act_data[0]['desigination'].split('/')[0]
                        data = list(Post_master.objects.filter(post_code=st_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                        
                        if len(data)>0:
                            category = data[0]['category']
                        else:
                            if st_post == 'SSE':
                                category = st_post
                            else:
                                category = None

                        
                       
                        id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
                        if len(id)>0:
                            id = id[0]['MAADESGCODE'] + 1
                        else:
                            id = 1

                        get_department_name = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False,MACDEPTCODE=act_data[0]['current_department_code_id']).values('MAVDEPTNAME').order_by('MAVDEPTNAME'))
                        if len(get_department_name)>0:
                            get_department_name = get_department_name[0]['MAVDEPTNAME']
                        else:
                            get_department_name = None

                        

                        div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                        if len(div_id_id) > 0:
                            hq_id_id = act_data[0]['current_rly_unit_id']
                            div_id_id = None
                        else:
                            hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                            
                            if hq_id_id[0]['location_type'] in ['DIV','WS']:
                                div_id_id = act_data[0]['current_rly_unit_id']
                            else:
                                div_id_id = None
                            hq_id_id = hq_id_id[0]['parent_rly_unit_code']

                        MED_LVLDESG.objects.create(hq_id_id=hq_id_id,div_id_id=div_id_id,MAADESGCODE = id,MATEFCTDATE=datetime.now(),MAVDLVL=category,
                            MAVSTTS = act_data[0]['current_charge'],MAVDESG = act_data[0]['desigination'],MAVMDFDBY=cuser,
                            MAVDEPTCODE_id = act_data[0]['current_department_code_id'],MAVDEPT = get_department_name,
                        MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT_id=act_data[0]['current_rly_unit_id'],
                        MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
                        MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],
                        MAVSTTNNAME=act_data[0]['current_station_name'])

                        # import re
                        # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
                        # username_converted = username_converted.upper()
                        # id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
                        # if len(id)>0:
                        #     id = id[0]['MAV_userid'] + 1
                        # else:
                        #     id = 1
                        # newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
                        # newuser.is_active= True
                        # newuser.is_admin=False
                        # newuser.save()
                        
                        # MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)

                        designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
                        msg = 'Successfully Accepted the New Designation'

            else:
                msg = 'Failed to Accept'
            return JsonResponse(msg, safe = False)
        if post_type == 'reject':
            record_id = request.POST.get('record_id')
            pullBackRemark = request.POST.get('pullBackRemark')
            msg = ''
            if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
                designation_Change_Request.objects.filter(record_id=record_id).update(action_by = cuser, action_date=datetime.now(), action_remarks=pullBackRemark,status='Rejected')
                msg = 'Successfully Rejected'
            else:
                msg = 'Failed to Reject'
            return JsonResponse(msg, safe = False)
        if post_type == 'getPostDetails':
            post = request.POST.get('post')
            context = list(Post_master.objects.filter(post_code=post).values('category','pc7_levelmin','pc7_levelmax','department_code_id__MAVDEPTNAME'))
            return JsonResponse(context, safe = False)
        if post_type == 'checkRlyType':
            rly = request.POST.get('rly')
            post = request.POST.get('post')
            location_code = ''
            parent_location_code = ''
            location_type_desc = ''
            createdDesignation = post

            context = list(railwayLocationMaster.objects.filter(rly_unit_code=rly).values('location_code','parent_location_code','location_type_desc'))
            if len(context) > 0:
                location_code = context[0]['location_code']
                parent_location_code = context[0]['parent_location_code']
                location_type_desc = context[0]['location_type_desc']
            if location_type_desc in ['RAILWAY BOARD', 'PRODUCTION UNIT', 'HEAD QUATER', 'PSU', 'INSTITUTE']:
                createdDesignation = createdDesignation + '/' + location_code
            else:
                if post != 'DRM':
                    createdDesignation = createdDesignation + '/' + location_code + '/' + parent_location_code
                else:
                    createdDesignation = createdDesignation + '/' + location_code

            data = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=createdDesignation).values('MAVDESG'))
            if len(data) > 0:
                data = list(map( lambda x: x['MAVDESG'],data))
                data = ', '.join(data)
            else:
                data = ''
            context = {
                'createdDesignation' : createdDesignation,
                'data' : data,
            }
            return JsonResponse(context, safe = False)
        if post_type == 'checkAvailability':
            designation = request.POST.get('designation')
            context = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=designation).values())
            if len(context)>0:
                msg = 'Designation Not Available'
                c = '0'
            else:
                msg = 'Designation Available'
                c = '1'
            context ={
                'msg' : msg,
                'color' : c,
            }
            return JsonResponse(context, safe = False)
        if post_type == 'saveNewDesignation':
            #new_post,new_place,new_station,new_reporting_officer,new_designation,new_contact,new_email,new_remarks
            new_chargetype = request.POST.get('new_chargetype')
            new_post = request.POST.get('new_post')
            new_place = request.POST.get('new_place')
            new_station = request.POST.get('new_station')
            new_reporting_officer = request.POST.get('new_reporting_officer')
            new_designation = request.POST.get('new_designation')
            new_forward_to_officer = request.POST.get('new_forward_to_officer')
            if new_forward_to_officer == '':
                new_forward_to_officer = None
            if new_reporting_officer == '':
                new_reporting_officer = None
            else:
                reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = new_reporting_officer).values('MAADESGCODE'))
                if len(reporting_officer) > 0:
                    new_reporting_officer = reporting_officer[0]['MAADESGCODE']
                else:
                    new_reporting_officer = None
            
            new_contact = request.POST.get('new_contact')
            new_email = request.POST.get('new_email')
            new_remarks = request.POST.get('new_remarks')
            msg = 'Some Error Exist, contact superadmin'
            context = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=new_designation).values())
            if len(context)>0:
                msg = 'Designation Not Available'
            else:
                if MED_LVLDESG.objects.filter(MAVOFCLMAILID=new_email).exists():
                    msg = 'e-mail id is already used with another designation, Request cannot be processed' 
                elif new_chargetype == 'P' and MED_LVLDESG.objects.filter(MAVCONTNUM = new_contact, MAVSTTS = 'P').exists():
                    msg = 'Contact number is already used with another designation, Request cannot be processed' 
                elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',desigination=new_designation).exists():
                    msg = 'Request already exist, pull back the existing request to give new request'
                elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',current_official_email_ID=new_email).exists():
                    msg = 'e-mail id is already used with another designation, Request cannot be processed'
                elif new_chargetype == 'P' and designation_Change_Request.objects.filter(status='Forwarded',request_type='New',current_contactnumber=new_contact,current_charge='P').exists():
                    msg = 'Contact number is already used with another designation, Request cannot be processed'
                
                else:
                    data = list(Post_master.objects.filter(post_code = new_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                    
                    
                    designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=new_remarks,desigination=new_designation,status='Forwarded',request_type='New',
                        current_charge = new_chargetype,current_parent_desig_code=new_reporting_officer,current_department_code_id=data[0]['department_code_id'],current_rly_unit_id=new_place,
                        current_contactnumber=new_contact,current_official_email_ID=new_email,current_station_name=new_station,
                        current_maxlevel=data[0]['pc7_levelmax'],current_minlevel=data[0]['pc7_levelmin'], forward_to_officer = new_forward_to_officer)
                    msg = 'success'
            return JsonResponse(msg, safe = False)
        
        if post_type == 'saveNewDesignationSelf':
            #new_post,new_place,new_station,new_reporting_officer,new_designation,new_contact,new_email,new_remarks
            new_chargetype = request.POST.get('new_chargetype')
            new_post = request.POST.get('new_post')
            new_place = request.POST.get('new_place')
            new_station = request.POST.get('new_station')
            new_reporting_officer = request.POST.get('new_reporting_officer')
            new_designation = request.POST.get('new_designation')
            new_forward_to_officer = request.POST.get('new_forward_to_officer')
            if new_forward_to_officer == '':
                new_forward_to_officer = None
            if new_reporting_officer == '':
                new_reporting_officer = None
            else:
                reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = new_reporting_officer).values('MAADESGCODE'))
                if len(reporting_officer) > 0:
                    new_reporting_officer = reporting_officer[0]['MAADESGCODE']
                else:
                    new_reporting_officer = None
            
            new_contact = request.POST.get('new_contact')
            new_email = request.POST.get('new_email')
            new_remarks = request.POST.get('new_remarks')
            msg = 'Some Error Exist, contact superadmin'
            context = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=new_designation).values())
            if len(context)>0:
                msg = 'Designation Not Available'
            else:
                if MED_LVLDESG.objects.filter(MAVOFCLMAILID = new_email).exists():
                    msg = 'e-mail id is already used with another designation, Request cannot be processed' 
                elif new_chargetype == 'P' and MED_LVLDESG.objects.filter(MAVCONTNUM = new_contact, MAVSTTS = 'P').exists():
                    msg = 'Contact number is already used with another designation, Request cannot be processed' 
                elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',desigination=new_designation).exists():
                    msg = 'Request already exist, pull back the existing request to give new request'
                elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',current_official_email_ID=new_email).exists():
                    msg = 'e-mail id is already used with another designation, Request cannot be processed'
                elif new_chargetype == 'P' and designation_Change_Request.objects.filter(status='Forwarded',request_type='New',current_contactnumber=new_contact,current_charge='P').exists():
                    msg = 'Contact number is already used with another designation, Request cannot be processed'
                
                else:
                    data = list(Post_master.objects.filter(post_code = new_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                    
                    
                    designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=new_remarks,desigination=new_designation,status='Forwarded',request_type='New',
                        current_charge = new_chargetype, current_parent_desig_code=new_reporting_officer,current_department_code_id=data[0]['department_code_id'],current_rly_unit_id=new_place,
                        current_contactnumber=new_contact,current_official_email_ID=new_email,current_station_name=new_station,
                        current_maxlevel=data[0]['pc7_levelmax'],current_minlevel=data[0]['pc7_levelmin'], forward_to_officer = new_forward_to_officer)
                    

                    record_id = list(designation_Change_Request.objects.values('record_id').order_by('-record_id'))[0]['record_id']
                    pullBackRemark = 'Self Accepted'
                    msg = ''
                    if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
                        password = 'Admin@123'
                        act_data = list(designation_Change_Request.objects.filter(record_id=record_id).values())
                        
                        if act_data[0]['request_type'] != 'New':

                            if act_data[0]['current_parent_desig_code'] is not None:
                                reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
                            else:
                                reporting_officer_new_joining = None

                            prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
                            div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                            if len(div_id_id) > 0:
                                hq_id_id = act_data[0]['current_rly_unit_id']
                                div_id_id = None
                            else:
                                hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                
                                if hq_id_id[0]['location_type'] in ['DIV','WS']:
                                    div_id_id = act_data[0]['current_rly_unit_id']
                                else:
                                    div_id_id = None
                                hq_id_id = hq_id_id[0]['parent_rly_unit_code']
                                

                            MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVMDFDBY=cuser,MAVDEPTCODE = act_data[0]['current_department_code_id'],
                            MAVSTTS = new_chargetype, MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT=act_data[0]['current_rly_unit_id'],hq_id_id=hq_id_id,div_id_id=div_id_id,
                            MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
                            MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],MAVSTTNNAME=act_data[0]['current_station_name'])

                            
                            designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
                            msg = 'Successfully Accepted the Modification'
                        else:
                            if MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).exists():
                                msg = 'Designation already present'
                            else:
                                if act_data[0]['current_parent_desig_code'] is not None:
                                    reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
                                else:
                                    reporting_officer_new_joining = None

                                prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
                                st_post = act_data[0]['desigination'].split('/')[0]
                                data = list(Post_master.objects.filter(post_code=st_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                                
                                if len(data)>0:
                                    category = data[0]['category']
                                else:
                                    if st_post == 'SSE':
                                        category = st_post
                                    else:
                                        category = None

                                
                                id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
                                if len(id)>0:
                                    id = id[0]['MAADESGCODE'] + 1
                                else:
                                    id = 1

                                

                                get_department_name = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False,MACDEPTCODE=act_data[0]['current_department_code_id']).values('MAVDEPTNAME').order_by('MAVDEPTNAME'))
                                if len(get_department_name)>0:
                                    get_department_name = get_department_name[0]['MAVDEPTNAME']
                                else:
                                    get_department_name = None

                              
                                div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                if len(div_id_id) > 0:
                                    hq_id_id = act_data[0]['current_rly_unit_id']
                                    div_id_id = None
                                else:
                                    hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                    
                                    if hq_id_id[0]['location_type'] in ['DIV','WS']:
                                        div_id_id = act_data[0]['current_rly_unit_id']
                                    else:
                                        div_id_id = None
                                    hq_id_id = hq_id_id[0]['parent_rly_unit_code']

                                MED_LVLDESG.objects.create(hq_id_id=hq_id_id,div_id_id=div_id_id,MAADESGCODE = id,MATEFCTDATE=datetime.now(),MAVDLVL=category,
                                    MAVSTTS = new_chargetype,MAVDESG = act_data[0]['desigination'],MAVMDFDBY=cuser,
                                    MAVDEPTCODE_id = act_data[0]['current_department_code_id'],MAVDEPT = get_department_name,
                                MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT_id=act_data[0]['current_rly_unit_id'],
                                MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
                                MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],
                                MAVSTTNNAME=act_data[0]['current_station_name'])

                               
                                designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
                                msg = 'Successfully Accepted the New Designation'

                    else:
                        msg = 'Failed to Accept'
                        
                    msg = 'success'
            return JsonResponse(msg, safe = False)
        

        if post_type == 'reportingOfficer':
            rly_unit_id = request.POST.get('new_place')
            
            rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
            rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
            rep_officer = list(MED_LVLDESG.objects.filter(Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in = rly_unit_det)).values('MAVDESG'))
            rep_officer = list(map( lambda x: x['MAVDESG'],rep_officer))
            
            return JsonResponse(rep_officer, safe = False)  
        
        
        return JsonResponse({"success":False}, status=400)  

    if request.user.MAV_userlvlcode_id in ['1', '2']:
        details_data = list(MED_LVLDESG.objects.filter(MABDELTFLAG = False).values('MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAIPC7LVLMIN','MAIPCLVLMAX').order_by('MAVDESG'))
    else:
        details_data = list(MED_LVLDESG.objects.filter((Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in=railwayLocationMaster.objects.filter(parent_rly_unit_code = str(rly_unit_id)).values('rly_unit_code'))),MABDELTFLAG = False).values('MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAIPC7LVLMIN','MAIPCLVLMAX').order_by('MAVDESG'))
    
    
    all_department = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False).values('MACDEPTCODE','MAVDEPTNAME').order_by('MAVDEPTNAME'))
    if request.user.MAV_userlvlcode_id in ['1', '2']:
        all_railway = list(railwayLocationMaster.objects.filter(location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))
    else:
        all_railway = list(railwayLocationMaster.objects.filter((Q(parent_rly_unit_code = str(rly_unit_id)) | Q(rly_unit_code = rly_unit_id)),location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))
    
    level = ['8','9','10','11','12','13','14','15','16','17','18']
    request_data = designation_Change_Request.objects.filter(status__in = ['Forwarded'],  request_by = usermast.MAV_userid).values().order_by('-request_date')
    post=Post_master.objects.filter(delete_flag=False).values('post_code').order_by('post_code').distinct('post_code')
    rly_emp_designation = list(map(lambda x: x['MAVDESG'],details_data))
    
    parent_rly_unit_code = list(railwayLocationMaster.objects.filter(Q(rly_unit_code = rly_unit_id),location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('parent_rly_unit_code').distinct().order_by('location_code'))
    forward_to_officer = [rly_unit_id]
    if len(parent_rly_unit_code) > 0:
        if parent_rly_unit_code[0]['parent_rly_unit_code'] != None:
            forward_to_officer =  [rly_unit_id , int(parent_rly_unit_code[0]['parent_rly_unit_code'])]
    forward_to_officer.extend([1,153])
    
    # forward_to_officer = list(AdminMaster.objects.filter(~Q(user_id=usermast.MAV_userid), rly_id__in = forward_to_officer,status = 'Active').values('designation', 'emp_name', 'user_id'))
    forward_to_officer = list(MEM_usersn.objects.filter(~Q(MAV_userid = usermast.MAV_userid),MAV_userlvlcode_id__admin_flag = True, MAV_rlycode__in =forward_to_officer).values('MAV_userid','MAV_userdesig'))
    
    for i in request_data:
        pending_with_officer = ' - '
        if i['forward_to_officer'] != None and i['status'] == 'Forwarded':
            d1 = list(MEM_usersn.objects.filter(MAV_userid = i['forward_to_officer']).values('MAV_userid','MAV_userdesig'))
            if len(d1):
                pending_with_officer = str(d1[0]['MAV_userid']) + '-' + d1[0]['MAV_userdesig']
        i.update({'pending_with_officer':pending_with_officer})
 
    pending = list(designation_Change_Request.objects.filter(status = 'Forwarded', forward_to_officer = usermast.MAV_userid).values().order_by('-request_date'))
    action_taken = list(designation_Change_Request.objects.filter((Q(request_by = usermast.MAV_userid)|Q(action_by = usermast.MAV_userid)),status__in = ['Accepted', 'Rejected', 'Pulled Back']).values().order_by('-request_date'))
    len_pending = len(pending)
    len_forwarded = len(request_data)
    
    from_other_type = request.GET.get('type')
    from_other_designation = request.GET.get('designation')
    
    context ={
        'from_other_type':from_other_type,
        'from_other_designation':from_other_designation,
        'len_pending' : len_pending,
        'len_forwarded' : len_forwarded,
        'details_data' : details_data,
        'all_department': all_department,
        'all_railway': all_railway,
        'level' : level,
        'request_data': request_data,
        'rolelist': rolelist,
        'pending': pending,
        'action_taken':action_taken,
        'post':post,
        'rly_emp_designation':rly_emp_designation,
        'forward_to_officer':forward_to_officer,
    }
    return render(request, "designation_request.html", context)
    


# def designation_request(request):   
#     from datetime import datetime 
#     usermast=MEM_usersn.objects.filter(MAV_username = request.session['username']).first()
#     rolelist=usermast.MAV_userlvlcode_id
#     # if str(request.user).startswith('admin'):
#     #     actual_user = str(request.user).split('admin')[1]
#     # else:
#     #     actual_user = request.user
#     empnox = AdminMaster.objects.filter(Q(user_id = usermast.MAV_userid), user_id__isnull = False).values('rly_id','user_id')
#     rly_unit_id=None
#     cuser = None
#     parent_rly = []
#     if empnox:
#         rly_unit_id = empnox[0]['rly_id']
#         cuser = empnox[0]['user_id']
#         child_rly = list(railwayLocationMaster.objects.filter( parent_rly_unit_code  = str(rly_unit_id)).values('rly_unit_code'))
#         if len(child_rly)>0:
#             child_rly = list(map(lambda x: x['rly_unit_code'], child_rly))
#     if request.method == 'POST' and request.is_ajax():
#         post_type = request.POST.get('post_type')
#         if post_type == 'similar':
#             post = request.POST.get('post')
#             current_user = request.user
#             # if str(request.user).startswith('admin'):
#             #     actual_user = str(request.user).split('admin')[1]
#             # else:
#             #     actual_user = request.user
#             # empnox = AdminMaster.objects.filter(Q(admin_email=actual_user), user_id__isnull=False).values('rly','user_id') 
#             empnox = AdminMaster.objects.filter(Q(user_id=usermast.MAV_userid), user_id__isnull=False).values('rly','user_id')           
#             rly_unit_id=None
#             if empnox:
#                 rly_unit_id = empnox[0]['rly']
#             rep_officer = list(MED_LVLDESG.objects.filter((Q(MAIRLYUNIT = rly_unit_id)|Q(MAIRLYUNIT_id__parent_rly_unit_code  = str(rly_unit_id))),MAVDESG__startswith= post+'/').values('MAVDESG'))
#             rep_officer = list(map( lambda x: x['MAVDESG'],rep_officer))
#             rep_officer = ', '.join(rep_officer)
#             context = {
#                 'rep_officer':rep_officer,
#             }
#             return JsonResponse(context,safe=False)
    
#         if post_type == 'emp_details':
#             designation = request.POST.get('designation')
#             reporting_officer = ''
#             emp_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAVDLVL','MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAIPC7LVLMIN','MAIPCLVLMAX','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAVSTTNNAME','MAVPARDESGCODE','MAVSTTS').order_by('-MAVSTTS','MAVDESG'))
#             if len(emp_details) > 0: 
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = emp_details[0]['MAVPARDESGCODE']).values('MAVDESG'))
#                 if len(reporting_officer) > 0:
#                     reporting_officer = reporting_officer[0]['MAVDESG']
#                 else:
#                     reporting_officer = ''
#             context ={
#                 'emp_details':emp_details,
#                 'reporting_officer':reporting_officer,
#             }
#             return JsonResponse(context, safe = False) 
#         if post_type == 'desig_search':
#             designation = request.POST.get('designation')
#             lev_desig_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAIPC7LVLMIN','MAIPCLVLMAX','MAVPARDESGCODE','MAVDEPTCODE','MAIRLYUNIT','MAVOFCLMAILID','MAVCONTNUM','MAVSTTNNAME').order_by('MAVSTTS'))
#             if len(lev_desig_details) > 0: 
#                 for i in range(len(lev_desig_details)):
#                     reporting_officer = ''
#                     if lev_desig_details[i]['MAVPARDESGCODE'] is not None:
#                         reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = lev_desig_details[i]['MAVPARDESGCODE']).values('MAVDESG'))
#                         if len(reporting_officer) > 0:
#                             reporting_officer = reporting_officer[i]['MAVDESG']
#                         else:
#                             reporting_officer = ''
#                     lev_desig_details[i].update({'reporting_officer':reporting_officer})
                
#                 rly_unit_id = lev_desig_details[i]['MAIRLYUNIT']
#                 rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
#                 rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
#                 rep_officer = list(MED_LVLDESG.objects.filter(Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in = rly_unit_det)).values('MAVDESG'))
#                 rep_officer = list(map( lambda x: x['MAVDESG'],rep_officer))
#                 all_station = list(station_master.objects.filter(Q(rly_id_id = rly_unit_id) | Q(div_id_id = rly_unit_id)).values('station_name').distinct().order_by('station_name'))
#                 if lev_desig_details[0]['MAVSTTNNAME'] is not None:
#                     all_station.append({'station_name':lev_desig_details[0]['MAVSTTNNAME']})
#                 print(lev_desig_details,all_station)
#             context = {
#                 'lev_desig_details' : lev_desig_details,
#                 'rep_officer':rep_officer,
#                 'all_station':all_station,
#             }
#             return JsonResponse(context, safe = False)
#         if post_type == 'station':
#             val = request.POST.get('val')
#             all_station = list(station_master.objects.filter(Q(rly_id_id = val) | Q(div_id_id = val)).values('station_name').distinct().order_by('station_name'))
#             return JsonResponse(all_station, safe = False)  
#         if post_type == 'saveDataChanged':
#             msg = 'Please contact superadmin'

#             # #designation,pre_email,pre_contact,pre_minlevel,pre_maxlevel,pre_station,pre_place,pre_department,pre_reporting_officer,pre_remarks
#             # designation=designation,rly_unit=pre_place,department_code=pre_department,station_name=pre_station,contactnumber=pre_contact,official_email_ID=pre_email
#             # ,pc7_levelmin=pre_minlevel,pc7_levelmax=pre_maxlevel,parent_desig_code=pre_reporting_officer
#             designation = request.POST.get('designation')
#             pre_email = request.POST.get('pre_email')
#             pre_contact = request.POST.get('pre_contact')
#             pre_minlevel = request.POST.get('pre_minlevel')
#             pre_maxlevel = request.POST.get('pre_maxlevel')
#             pre_station = request.POST.get('pre_station')
#             pre_place = request.POST.get('pre_place')
#             pre_department = request.POST.get('pre_department')
#             pre_reporting_officer = request.POST.get('pre_reporting_officer')
#             pre_remarks = request.POST.get('pre_remarks')
#             edit_forward_to_officer = request.POST.get('edit_forward_to_officer')
#             if edit_forward_to_officer == '':
#                 edit_forward_to_officer = None
            

#             if pre_reporting_officer is not None or pre_reporting_officer != '':
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = pre_reporting_officer).values('MAADESGCODE'))
#                 if len(reporting_officer) > 0:
#                     pre_reporting_officer = reporting_officer[0]['MAADESGCODE']
#                 else:
#                     pre_reporting_officer = None
#             else:
#                     pre_reporting_officer = None

#             if MED_LVLDESG.objects.filter(~Q(MAVDESG = designation), MAVOFCLMAILID=pre_email).exists():
#                 msg = 'e-mail id is already used with another designation, Request cannot be processed' 

#             elif MED_LVLDESG.objects.filter(~Q(MAVDESG = designation),MAVCONTNUM=pre_contact).exists():
#                 msg = 'Contact number is already used with another designation, Request cannot be processed'

#             elif MED_LVLDESG.objects.filter(MAVDESG=designation,MAIRLYUNIT=pre_place,MAVDEPTCODE=pre_department,MAVSTTNNAME=pre_station,MAVCONTNUM=pre_contact,MAVOFCLMAILID=pre_email,
#                         MAIPC7LVLMIN=pre_minlevel,MAIPCLVLMAX=pre_maxlevel,MAVPARDESGCODE=pre_reporting_officer).exists():
#                 msg = 'All the field having the previous value only, Request cannot be processed'
            
#             elif designation_Change_Request.objects.filter(status='Forwarded',request_type='Modification',desigination=designation).exists():
#                 msg = 'Request already exist, pull back the existing request to give new request' 
            
#             else:
#                 prevData = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values())
#                 designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=pre_remarks,desigination=designation,status='Forwarded',request_type='Modification',
#                     prev_parent_desig_code = prevData[0]['MAVPARDESGCODE'],prev_department_code_id=prevData[0]['MAVDEPTCODE_id'],prev_rly_unit_id=prevData[0]['MAIRLYUNIT_id'],prev_contactnumber=prevData[0]['MAVCONTNUM'],prev_official_email_ID=prevData[0]['MAVOFCLMAILID'],prev_station_name=prevData[0]['MAVSTTNNAME'],prev_maxlevel=prevData[0]['MAIPC7LVLMIN'],prev_minlevel=prevData[0]['MAIPCLVLMAX'],
#                     forward_to_officer = edit_forward_to_officer,current_parent_desig_code=pre_reporting_officer,current_department_code_id=pre_department,current_rly_unit_id=pre_place,current_contactnumber=pre_contact,current_official_email_ID=pre_email,current_station_name=pre_station,current_maxlevel=pre_maxlevel,current_minlevel=pre_minlevel)
                
#                 msg = 'success'

#             return JsonResponse(msg, safe = False)
#         if post_type == 'saveDataChangedSelf':
#             msg = 'Please contact superadmin'
#             designation = request.POST.get('designation')
#             pre_email = request.POST.get('pre_email')
#             pre_contact = request.POST.get('pre_contact')
#             pre_minlevel = request.POST.get('pre_minlevel')
#             pre_maxlevel = request.POST.get('pre_maxlevel')
#             pre_station = request.POST.get('pre_station')
#             pre_place = request.POST.get('pre_place')
#             pre_department = request.POST.get('pre_department')
#             pre_reporting_officer = request.POST.get('pre_reporting_officer')
#             pre_remarks = request.POST.get('pre_remarks')
#             edit_forward_to_officer = request.POST.get('edit_forward_to_officer')
#             if edit_forward_to_officer == '':
#                 edit_forward_to_officer = None
            

#             if pre_reporting_officer is not None or pre_reporting_officer != '':
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = pre_reporting_officer).values('MAADESGCODE'))
#                 if len(reporting_officer) > 0:
#                     pre_reporting_officer = reporting_officer[0]['MAADESGCODE']
#                 else:
#                     pre_reporting_officer = None
#             else:
#                     pre_reporting_officer = None

#             if MED_LVLDESG.objects.filter(~Q(MAVDESG = designation), MAVOFCLMAILID=pre_email).exists():
#                 msg = 'e-mail id is already used with another designation, Request cannot be processed' 

#             elif MED_LVLDESG.objects.filter(~Q(MAVDESG = designation),MAVCONTNUM=pre_contact).exists():
#                 msg = 'Contact number is already used with another designation, Request cannot be processed'

#             elif MED_LVLDESG.objects.filter(MAVDESG=designation,MAIRLYUNIT=pre_place,MAVDEPTCODE=pre_department,MAVSTTNNAME=pre_station,MAVCONTNUM=pre_contact,MAVOFCLMAILID=pre_email,
#                         MAIPC7LVLMIN=pre_minlevel,MAIPCLVLMAX=pre_maxlevel,MAVPARDESGCODE=pre_reporting_officer).exists():
#                 msg = 'All the field having the previous value only, Request cannot be processed'
            
#             elif designation_Change_Request.objects.filter(status='Forwarded',request_type='Modification',desigination=designation).exists():
#                 msg = 'Request already exist, pull back the existing request to give new request' 
            
#             else:
#                 prevData = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values())
#                 designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=pre_remarks,desigination=designation,status='Forwarded',request_type='Modification',
#                     prev_parent_desig_code = prevData[0]['MAVPARDESGCODE'],prev_department_code_id=prevData[0]['MAVDEPTCODE_id'],prev_rly_unit_id=prevData[0]['MAIRLYUNIT_id'],prev_contactnumber=prevData[0]['MAVCONTNUM'],prev_official_email_ID=prevData[0]['MAVOFCLMAILID'],prev_station_name=prevData[0]['MAVSTTNNAME'],prev_maxlevel=prevData[0]['MAIPC7LVLMIN'],prev_minlevel=prevData[0]['MAIPCLVLMAX'],
#                     forward_to_officer = edit_forward_to_officer,current_parent_desig_code=pre_reporting_officer,current_department_code_id=pre_department,current_rly_unit_id=pre_place,current_contactnumber=pre_contact,current_official_email_ID=pre_email,current_station_name=pre_station,current_maxlevel=pre_maxlevel,current_minlevel=pre_minlevel)
                
#                 record_id = list(designation_Change_Request.objects.values('record_id').order_by('-record_id'))[0]['record_id']
#                 pullBackRemark = 'Self Accepted'
#                 msg = ''
#                 if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
#                     password = 'Admin@123'
#                     act_data = list(designation_Change_Request.objects.filter(record_id=record_id).values())
                    
#                     if act_data[0]['request_type'] != 'New':

#                         if act_data[0]['current_parent_desig_code'] is not None:
#                             reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
#                         else:
#                             reporting_officer_new_joining = None

#                         prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
#                         div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
#                         if len(div_id_id) > 0:
#                             hq_id_id = act_data[0]['current_rly_unit_id']
#                             div_id_id = None
#                         else:
#                             hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                            
#                             if hq_id_id[0]['location_type'] in ['DIV','WS']:
#                                 div_id_id = act_data[0]['current_rly_unit_id']
#                             else:
#                                 div_id_id = None
#                             hq_id_id = hq_id_id[0]['parent_rly_unit_code']
                            

#                         MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVMDFDBY=cuser,MAVDEPTCODE = act_data[0]['current_department_code_id'],
#                         MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT=act_data[0]['current_rly_unit_id'],hq_id_id=hq_id_id,div_id_id=div_id_id,
#                         MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
#                         MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],MAVSTTNNAME=act_data[0]['current_station_name'])

#                         # import re
#                         # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
#                         # username_converted = username_converted.upper()
#                         # if MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).exists():
#                         #     forgetuser=MEM_usersn.objects.filter(id = prev_details[0]['MAVDESGUSER']).first()
#                         #     if forgetuser:
#                         #         forgetuser.set_password(password)
#                         #         forgetuser.save()
#                         #         # MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).update(MAV_username = username_converted,is_active= False,email = None)
                                
#                         #         MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).update(last_update = datetime.now(),MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                         # else:
#                         #     id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
#                         #     if len(id)>0:
#                         #         id = id[0]['MAV_userid'] + 1
#                         #     else:
#                         #         id = 1
#                         #     newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                         #     newuser.is_active= True
#                         #     newuser.is_admin=False
#                         #     newuser.save()
                            
#                         #     MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)
#                         designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
#                         msg = 'Successfully Accepted the Modification'
#                     else:
#                         if MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).exists():
#                             msg = 'Designation already present'
#                         else:
#                             if act_data[0]['current_parent_desig_code'] is not None:
#                                 reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
#                             else:
#                                 reporting_officer_new_joining = None

#                             prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
#                             st_post = act_data[0]['desigination'].split('/')[0]
#                             data = list(Post_master.objects.filter(post_code=st_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                            
#                             if len(data)>0:
#                                 category = data[0]['category']
#                             else:
#                                 if st_post == 'SSE':
#                                     category = st_post
#                                 else:
#                                     category = None

                            
#                             # if category == 'SSE':
#                             #     if reporting_officer_new_joining is not None:
#                             #         if MED_LVLDESG.objects.filter(delete_flag = False, d_level = category, parent_desig_code = reporting_officer_new_joining).count() > 10:
#                             #             return JsonResponse('Maximum limit Reached for adding supervisor.', safe = False)
                                    

#                             # if category == 'CRB':
#                             #     role = 'CRB'
#                             # else:
#                             #     role = 'user'
#                             id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
#                             if len(id)>0:
#                                 id = id[0]['MAADESGCODE'] + 1
#                             else:
#                                 id = 1

#                             get_department_name = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False,MACDEPTCODE=act_data[0]['current_department_code_id']).values('MAVDEPTNAME').order_by('MAVDEPTNAME'))
#                             if len(get_department_name)>0:
#                                 get_department_name = get_department_name[0]['MAVDEPTNAME']
#                             else:
#                                 get_department_name = None

#                             #hierarchy_level = list(category.objects.filter(category=category).values('hierarchy_level'))
#                             # if len(hierarchy_level) > 0:
#                             #     hierarchy_level = hierarchy_level[0]['hierarchy_level']
#                             # else:
#                             #     hierarchy_level = None

#                             div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
#                             if len(div_id_id) > 0:
#                                 hq_id_id = act_data[0]['current_rly_unit_id']
#                                 div_id_id = None
#                             else:
#                                 hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                
#                                 if hq_id_id[0]['location_type'] in ['DIV','WS']:
#                                     div_id_id = act_data[0]['current_rly_unit_id']
#                                 else:
#                                     div_id_id = None
#                                 hq_id_id = hq_id_id[0]['parent_rly_unit_code']

#                             MED_LVLDESG.objects.create(hq_id_id=hq_id_id,div_id_id=div_id_id,MAADESGCODE = id,MATEFCTDATE=datetime.now(),MAVSTTS='P',MAVDLVL=category,
#                                 MAVDESG = act_data[0]['desigination'],MAVMDFDBY=cuser,
#                                 MAVDEPTCODE_id = act_data[0]['current_department_code_id'],MAVDEPT = get_department_name,
#                             MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT_id=act_data[0]['current_rly_unit_id'],
#                             MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
#                             MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],
#                             MAVSTTNNAME=act_data[0]['current_station_name'])

#                             # import re
#                             # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
#                             # username_converted = username_converted.upper()
#                             # id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
#                             # if len(id)>0:
#                             #     id = id[0]['MAV_userid'] + 1
#                             # else:
#                             #     id = 1
#                             # newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                             # newuser.is_active= True
#                             # newuser.is_admin=False
#                             # newuser.save()
                            
#                             # MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)

#                             designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
#                             msg = 'Successfully Accepted the New Designation'

#                 else:
#                     msg = 'Failed to Accept'

#                 msg = 'success'

#             return JsonResponse(msg, safe = False)
        
#         if post_type == 'getRecord':
#             record_id = request.POST.get('record_id')   
#             record_data = list(designation_Change_Request.objects.filter(record_id=record_id).values(
#                 'record_id','request_by','request_date','request_remarks','desigination','status','request_type','action_by','action_date','action_remarks',
#                 'prev_parent_desig_code','prev_department_code__MAVDEPTNAME','prev_rly_unit__location_code','prev_rly_unit__location_type','prev_rly_unit__location_description','prev_contactnumber','prev_official_email_ID','prev_station_name','prev_maxlevel','prev_minlevel',
#                 'current_parent_desig_code','current_department_code__MAVDEPTNAME','current_rly_unit__location_code','current_rly_unit__location_type','current_rly_unit__location_description','current_contactnumber','current_official_email_ID','current_station_name','current_maxlevel','current_minlevel'
#             ))
#             if len(record_data) > 0: 
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = record_data[0]['prev_parent_desig_code']).values('MAVDESG'))
#                 if len(reporting_officer) > 0:
#                     prev_reporting_officer = reporting_officer[0]['MAVDESG']
#                 else:
#                     prev_reporting_officer = ''
                
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = record_data[0]['current_parent_desig_code']).values('MAVDESG'))
#                 if len(reporting_officer) > 0:
#                     curr_reporting_officer = reporting_officer[0]['MAVDESG']
#                 else:
#                     curr_reporting_officer = ''
#                 action_by = '-'
#                 if record_data[0]['action_by'] != None:
#                     d1 = list(AdminMaster.objects.filter(user_id = record_data[0]['action_by']).values('designation', 'emp_name', 'user_id'))
#                     if len(d1):
#                         action_by = d1[0]['user_id'] + '-' + d1[0]['designation'] + '-' + d1[0]['emp_name']
#                 request_by = '-'
#                 if record_data[0]['request_by'] != None:
#                     d1 = list(AdminMaster.objects.filter(user_id = record_data[0]['request_by']).values('designation', 'emp_name', 'user_id'))
#                     if len(d1):
#                         request_by = d1[0]['user_id'] + '-' + d1[0]['designation'] + '-' + d1[0]['emp_name']
                
#                 record_data[0].update({'request_by' : request_by, 'action_by' : action_by, 'prev_parent_desig_code':prev_reporting_officer,'current_parent_desig_code':curr_reporting_officer})
            
#             return JsonResponse(record_data, safe = False)  
#         if post_type == 'pullback':
#             record_id = request.POST.get('record_id')
#             pullBackRemark = request.POST.get('pullBackRemark')
#             msg = ''
#             if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
#                 designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Pulled Back')
#                 msg = 'Successfully Pulled Back'
#             else:
#                 msg = 'Failed to Pull Back'
#             return JsonResponse(msg, safe = False)
#         if post_type == 'accept':
#             record_id = request.POST.get('record_id')
#             pullBackRemark = request.POST.get('pullBackRemark')
#             msg = ''
#             if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
#                 password = 'Admin@123'
#                 act_data = list(designation_Change_Request.objects.filter(record_id=record_id).values())
                
#                 if act_data[0]['request_type'] != 'New':

#                     if act_data[0]['current_parent_desig_code'] is not None:
#                         reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
#                     else:
#                         reporting_officer_new_joining = None

#                     prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
#                     div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
#                     if len(div_id_id) > 0:
#                         hq_id_id = act_data[0]['current_rly_unit_id']
#                         div_id_id = None
#                     else:
#                         hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                        
#                         if hq_id_id[0]['location_type'] in ['DIV','WS']:
#                             div_id_id = act_data[0]['current_rly_unit_id']
#                         else:
#                             div_id_id = None
#                         hq_id_id = hq_id_id[0]['parent_rly_unit_code']
                        

#                     MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVMDFDBY=cuser,MAVDEPTCODE = act_data[0]['current_department_code_id'],
#                     MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT=act_data[0]['current_rly_unit_id'],hq_id_id=hq_id_id,div_id_id=div_id_id,
#                     MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
#                     MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],MAVSTTNNAME=act_data[0]['current_station_name'])

#                     # import re
#                     # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
#                     # username_converted = username_converted.upper()
#                     # if MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).exists():
#                     #     forgetuser=MEM_usersn.objects.filter(id = prev_details[0]['MAVDESGUSER']).first()
#                     #     if forgetuser:
#                     #         forgetuser.set_password(password)
#                     #         forgetuser.save()
#                     #         # MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).update(MAV_username = username_converted,is_active= False,email = None)
                            
#                     #         MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).update(last_update = datetime.now(),MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                     # else:
#                     #     id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
#                     #     if len(id)>0:
#                     #         id = id[0]['MAV_userid'] + 1
#                     #     else:
#                     #         id = 1
#                     #     newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                     #     newuser.is_active= True
#                     #     newuser.is_admin=False
#                     #     newuser.save()
                        
#                     #     MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)
#                     designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
#                     msg = 'Successfully Accepted the Modification'
#                 else:
#                     if MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).exists():
#                         msg = 'Designation already present'
#                     else:
#                         if act_data[0]['current_parent_desig_code'] is not None:
#                             reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
#                         else:
#                             reporting_officer_new_joining = None

#                         prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
#                         st_post = act_data[0]['desigination'].split('/')[0]
#                         data = list(Post_master.objects.filter(post_code=st_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                        
#                         if len(data)>0:
#                             category = data[0]['category']
#                         else:
#                             if st_post == 'SSE':
#                                 category = st_post
#                             else:
#                                 category = None

                        
#                         # if category == 'SSE':
#                         #     if reporting_officer_new_joining is not None:
#                         #         if MED_LVLDESG.objects.filter(delete_flag = False, d_level = category, parent_desig_code = reporting_officer_new_joining).count() > 10:
#                         #             return JsonResponse('Maximum limit Reached for adding supervisor.', safe = False)
                                

#                         # if category == 'CRB':
#                         #     role = 'CRB'
#                         # else:
#                         #     role = 'user'
#                         id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
#                         if len(id)>0:
#                             id = id[0]['MAADESGCODE'] + 1
#                         else:
#                             id = 1

#                         get_department_name = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False,MACDEPTCODE=act_data[0]['current_department_code_id']).values('MAVDEPTNAME').order_by('MAVDEPTNAME'))
#                         if len(get_department_name)>0:
#                             get_department_name = get_department_name[0]['MAVDEPTNAME']
#                         else:
#                             get_department_name = None

#                         #hierarchy_level = list(category.objects.filter(category=category).values('hierarchy_level'))
#                         # if len(hierarchy_level) > 0:
#                         #     hierarchy_level = hierarchy_level[0]['hierarchy_level']
#                         # else:
#                         #     hierarchy_level = None

#                         div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
#                         if len(div_id_id) > 0:
#                             hq_id_id = act_data[0]['current_rly_unit_id']
#                             div_id_id = None
#                         else:
#                             hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                            
#                             if hq_id_id[0]['location_type'] in ['DIV','WS']:
#                                 div_id_id = act_data[0]['current_rly_unit_id']
#                             else:
#                                 div_id_id = None
#                             hq_id_id = hq_id_id[0]['parent_rly_unit_code']

#                         MED_LVLDESG.objects.create(hq_id_id=hq_id_id,div_id_id=div_id_id,MAADESGCODE = id,MATEFCTDATE=datetime.now(),MAVSTTS='P',MAVDLVL=category,
#                             MAVDESG = act_data[0]['desigination'],MAVMDFDBY=cuser,
#                             MAVDEPTCODE_id = act_data[0]['current_department_code_id'],MAVDEPT = get_department_name,
#                         MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT_id=act_data[0]['current_rly_unit_id'],
#                         MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
#                         MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],
#                         MAVSTTNNAME=act_data[0]['current_station_name'])

#                         # import re
#                         # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
#                         # username_converted = username_converted.upper()
#                         # id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
#                         # if len(id)>0:
#                         #     id = id[0]['MAV_userid'] + 1
#                         # else:
#                         #     id = 1
#                         # newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                         # newuser.is_active= True
#                         # newuser.is_admin=False
#                         # newuser.save()
                        
#                         # MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)

#                         designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
#                         msg = 'Successfully Accepted the New Designation'

#             else:
#                 msg = 'Failed to Accept'
#             return JsonResponse(msg, safe = False)
#         if post_type == 'reject':
#             record_id = request.POST.get('record_id')
#             pullBackRemark = request.POST.get('pullBackRemark')
#             msg = ''
#             if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
#                 designation_Change_Request.objects.filter(record_id=record_id).update(action_by = cuser, action_date=datetime.now(), action_remarks=pullBackRemark,status='Rejected')
#                 msg = 'Successfully Rejected'
#             else:
#                 msg = 'Failed to Reject'
#             return JsonResponse(msg, safe = False)
#         if post_type == 'getPostDetails':
#             post = request.POST.get('post')
#             context = list(Post_master.objects.filter(post_code=post).values('category','pc7_levelmin','pc7_levelmax','department_code_id__MAVDEPTNAME'))
#             return JsonResponse(context, safe = False)
#         if post_type == 'checkRlyType':
#             rly = request.POST.get('rly')
#             post = request.POST.get('post')
#             location_code = ''
#             parent_location_code = ''
#             location_type_desc = ''
#             createdDesignation = post

#             context = list(railwayLocationMaster.objects.filter(rly_unit_code=rly).values('location_code','parent_location_code','location_type_desc'))
#             if len(context) > 0:
#                 location_code = context[0]['location_code']
#                 parent_location_code = context[0]['parent_location_code']
#                 location_type_desc = context[0]['location_type_desc']
#             if location_type_desc in ['RAILWAY BOARD', 'PRODUCTION UNIT', 'HEAD QUATER', 'PSU', 'INSTITUTE']:
#                 createdDesignation = createdDesignation + '/' + location_code
#             else:
#                 if post != 'DRM':
#                     createdDesignation = createdDesignation + '/' + location_code + '/' + parent_location_code
#                 else:
#                     createdDesignation = createdDesignation + '/' + location_code

#             data = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=createdDesignation).values('MAVDESG'))
#             if len(data) > 0:
#                 data = list(map( lambda x: x['MAVDESG'],data))
#                 data = ', '.join(data)
#             else:
#                 data = ''
#             context = {
#                 'createdDesignation' : createdDesignation,
#                 'data' : data,
#             }
#             return JsonResponse(context, safe = False)
#         if post_type == 'checkAvailability':
#             designation = request.POST.get('designation')
#             context = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=designation).values())
#             if len(context)>0:
#                 msg = 'Designation Not Available'
#                 c = '0'
#             else:
#                 msg = 'Designation Available'
#                 c = '1'
#             context ={
#                 'msg' : msg,
#                 'color' : c,
#             }
#             return JsonResponse(context, safe = False)
#         if post_type == 'saveNewDesignation':
#             #new_post,new_place,new_station,new_reporting_officer,new_designation,new_contact,new_email,new_remarks
#             new_post = request.POST.get('new_post')
#             new_place = request.POST.get('new_place')
#             new_station = request.POST.get('new_station')
#             new_reporting_officer = request.POST.get('new_reporting_officer')
#             new_designation = request.POST.get('new_designation')
#             new_forward_to_officer = request.POST.get('new_forward_to_officer')
#             if new_forward_to_officer == '':
#                 new_forward_to_officer = None
#             if new_reporting_officer == '':
#                 new_reporting_officer = None
#             else:
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = new_reporting_officer).values('MAADESGCODE'))
#                 if len(reporting_officer) > 0:
#                     new_reporting_officer = reporting_officer[0]['MAADESGCODE']
#                 else:
#                     new_reporting_officer = None
            
#             new_contact = request.POST.get('new_contact')
#             new_email = request.POST.get('new_email')
#             new_remarks = request.POST.get('new_remarks')
#             msg = 'Some Error Exist, contact superadmin'
#             context = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=new_designation).values())
#             if len(context)>0:
#                 msg = 'Designation Not Available'
#             else:
#                 if MED_LVLDESG.objects.filter(MAVOFCLMAILID=new_email).exists():
#                     msg = 'e-mail id is already used with another designation, Request cannot be processed' 

#                 elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',desigination=new_designation).exists():
#                     msg = 'Request already exist, pull back the existing request to give new request'
#                 elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',current_official_email_ID=new_email).exists():
#                     msg = 'e-mail id is already used with another designation, Request cannot be processed'
#                 else:
#                     data = list(Post_master.objects.filter(post_code = new_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                    
                    
#                     designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=new_remarks,desigination=new_designation,status='Forwarded',request_type='New',
#                         current_parent_desig_code=new_reporting_officer,current_department_code_id=data[0]['department_code_id'],current_rly_unit_id=new_place,
#                         current_contactnumber=new_contact,current_official_email_ID=new_email,current_station_name=new_station,
#                         current_maxlevel=data[0]['pc7_levelmax'],current_minlevel=data[0]['pc7_levelmin'], forward_to_officer = new_forward_to_officer)
#                     msg = 'success'
#             return JsonResponse(msg, safe = False)
        
#         if post_type == 'saveNewDesignationSelf':
#             #new_post,new_place,new_station,new_reporting_officer,new_designation,new_contact,new_email,new_remarks
#             new_post = request.POST.get('new_post')
#             new_place = request.POST.get('new_place')
#             new_station = request.POST.get('new_station')
#             new_reporting_officer = request.POST.get('new_reporting_officer')
#             new_designation = request.POST.get('new_designation')
#             new_forward_to_officer = request.POST.get('new_forward_to_officer')
#             if new_forward_to_officer == '':
#                 new_forward_to_officer = None
#             if new_reporting_officer == '':
#                 new_reporting_officer = None
#             else:
#                 reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = new_reporting_officer).values('MAADESGCODE'))
#                 if len(reporting_officer) > 0:
#                     new_reporting_officer = reporting_officer[0]['MAADESGCODE']
#                 else:
#                     new_reporting_officer = None
            
#             new_contact = request.POST.get('new_contact')
#             new_email = request.POST.get('new_email')
#             new_remarks = request.POST.get('new_remarks')
#             msg = 'Some Error Exist, contact superadmin'
#             context = list(MED_LVLDESG.objects.filter(MAVDESG__startswith=new_designation).values())
#             if len(context)>0:
#                 msg = 'Designation Not Available'
#             else:
#                 if MED_LVLDESG.objects.filter(MAVOFCLMAILID=new_email).exists():
#                     msg = 'e-mail id is already used with another designation, Request cannot be processed' 

#                 elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',desigination=new_designation).exists():
#                     msg = 'Request already exist, pull back the existing request to give new request'
#                 elif designation_Change_Request.objects.filter(status='Forwarded',request_type='New',current_official_email_ID=new_email).exists():
#                     msg = 'e-mail id is already used with another designation, Request cannot be processed'
#                 else:
#                     data = list(Post_master.objects.filter(post_code = new_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                    
                    
#                     designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks=new_remarks,desigination=new_designation,status='Forwarded',request_type='New',
#                         current_parent_desig_code=new_reporting_officer,current_department_code_id=data[0]['department_code_id'],current_rly_unit_id=new_place,
#                         current_contactnumber=new_contact,current_official_email_ID=new_email,current_station_name=new_station,
#                         current_maxlevel=data[0]['pc7_levelmax'],current_minlevel=data[0]['pc7_levelmin'], forward_to_officer = new_forward_to_officer)
                    

#                     record_id = list(designation_Change_Request.objects.values('record_id').order_by('-record_id'))[0]['record_id']
#                     pullBackRemark = 'Self Accepted'
#                     msg = ''
#                     if designation_Change_Request.objects.filter(record_id=record_id,status='Forwarded').exists():
#                         password = 'Admin@123'
#                         act_data = list(designation_Change_Request.objects.filter(record_id=record_id).values())
                        
#                         if act_data[0]['request_type'] != 'New':

#                             if act_data[0]['current_parent_desig_code'] is not None:
#                                 reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
#                             else:
#                                 reporting_officer_new_joining = None

#                             prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
#                             div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
#                             if len(div_id_id) > 0:
#                                 hq_id_id = act_data[0]['current_rly_unit_id']
#                                 div_id_id = None
#                             else:
#                                 hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                
#                                 if hq_id_id[0]['location_type'] in ['DIV','WS']:
#                                     div_id_id = act_data[0]['current_rly_unit_id']
#                                 else:
#                                     div_id_id = None
#                                 hq_id_id = hq_id_id[0]['parent_rly_unit_code']
                                

#                             MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVMDFDBY=cuser,MAVDEPTCODE = act_data[0]['current_department_code_id'],
#                             MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT=act_data[0]['current_rly_unit_id'],hq_id_id=hq_id_id,div_id_id=div_id_id,
#                             MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
#                             MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],MAVSTTNNAME=act_data[0]['current_station_name'])

#                             # import re
#                             # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
#                             # username_converted = username_converted.upper()
#                             # if MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).exists():
#                             #     forgetuser=MEM_usersn.objects.filter(id = prev_details[0]['MAVDESGUSER']).first()
#                             #     if forgetuser:
#                             #         forgetuser.set_password(password)
#                             #         forgetuser.save()
#                             #         # MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).update(MAV_username = username_converted,is_active= False,email = None)
                                    
#                             #         MEM_usersn.objects.filter(MAV_userid = prev_details[0]['MAVDESGUSER']).update(last_update = datetime.now(),MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                             # else:
#                             #     id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
#                             #     if len(id)>0:
#                             #         id = id[0]['MAV_userid'] + 1
#                             #     else:
#                             #         id = 1
#                             #     newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                             #     newuser.is_active= True
#                             #     newuser.is_admin=False
#                             #     newuser.save()
                                
#                             #     MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)
#                             designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
#                             msg = 'Successfully Accepted the Modification'
#                         else:
#                             if MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).exists():
#                                 msg = 'Designation already present'
#                             else:
#                                 if act_data[0]['current_parent_desig_code'] is not None:
#                                     reporting_officer_new_joining = act_data[0]['current_parent_desig_code']
#                                 else:
#                                     reporting_officer_new_joining = None

#                                 prev_details =list(MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).values())
#                                 st_post = act_data[0]['desigination'].split('/')[0]
#                                 data = list(Post_master.objects.filter(post_code=st_post).values('category','pc7_levelmin','pc7_levelmax','department_code_id'))
                                
#                                 if len(data)>0:
#                                     category = data[0]['category']
#                                 else:
#                                     if st_post == 'SSE':
#                                         category = st_post
#                                     else:
#                                         category = None

                                
#                                 # if category == 'SSE':
#                                 #     if reporting_officer_new_joining is not None:
#                                 #         if MED_LVLDESG.objects.filter(delete_flag = False, d_level = category, parent_desig_code = reporting_officer_new_joining).count() > 10:
#                                 #             return JsonResponse('Maximum limit Reached for adding supervisor.', safe = False)
                                        

#                                 # if category == 'CRB':
#                                 #     role = 'CRB'
#                                 # else:
#                                 #     role = 'user'
#                                 id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
#                                 if len(id)>0:
#                                     id = id[0]['MAADESGCODE'] + 1
#                                 else:
#                                     id = 1

#                                 get_department_name = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False,MACDEPTCODE=act_data[0]['current_department_code_id']).values('MAVDEPTNAME').order_by('MAVDEPTNAME'))
#                                 if len(get_department_name)>0:
#                                     get_department_name = get_department_name[0]['MAVDEPTNAME']
#                                 else:
#                                     get_department_name = None

#                                 #hierarchy_level = list(category.objects.filter(category=category).values('hierarchy_level'))
#                                 # if len(hierarchy_level) > 0:
#                                 #     hierarchy_level = hierarchy_level[0]['hierarchy_level']
#                                 # else:
#                                 #     hierarchy_level = None

#                                 div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
#                                 if len(div_id_id) > 0:
#                                     hq_id_id = act_data[0]['current_rly_unit_id']
#                                     div_id_id = None
#                                 else:
#                                     hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=act_data[0]['current_rly_unit_id']).values('parent_rly_unit_code','location_type'))
                                    
#                                     if hq_id_id[0]['location_type'] in ['DIV','WS']:
#                                         div_id_id = act_data[0]['current_rly_unit_id']
#                                     else:
#                                         div_id_id = None
#                                     hq_id_id = hq_id_id[0]['parent_rly_unit_code']

#                                 MED_LVLDESG.objects.create(hq_id_id=hq_id_id,div_id_id=div_id_id,MAADESGCODE = id,MATEFCTDATE=datetime.now(),MAVSTTS='P',MAVDLVL=category,
#                                     MAVDESG = act_data[0]['desigination'],MAVMDFDBY=cuser,
#                                     MAVDEPTCODE_id = act_data[0]['current_department_code_id'],MAVDEPT = get_department_name,
#                                 MAVPARDESGCODE = reporting_officer_new_joining,MAIRLYUNIT_id=act_data[0]['current_rly_unit_id'],
#                                 MAIPC7LVLMIN=act_data[0]['current_minlevel'],MAIPCLVLMAX=act_data[0]['current_maxlevel'],
#                                 MAVCONTNUM=act_data[0]['current_contactnumber'],MAVOFCLMAILID=act_data[0]['current_official_email_ID'],
#                                 MAVSTTNNAME=act_data[0]['current_station_name'])

#                                 # import re
#                                 # username_converted = re.sub(r'[^\w\d]', '', act_data[0]['desigination'] )
#                                 # username_converted = username_converted.upper()
#                                 # id = list(MEM_usersn.objects.values('MAV_userid').order_by('-MAV_userid'))
#                                 # if len(id)>0:
#                                 #     id = id[0]['MAV_userid'] + 1
#                                 # else:
#                                 #     id = 1
#                                 # newuser = MEM_usersn.objects.create_user(last_update = datetime.now(),MAV_userid = id,password=password,MAV_username = username_converted,is_active= True , MAV_userdesig = act_data[0]['desigination'],MAV_crtdby = request.session['username'],MAV_deptcode_id = act_data[0]['current_department_code_id'],MAV_mail = act_data[0]['current_official_email_ID'], MAV_ph = act_data[0]['current_contactnumber'],MAV_rlycode_id = act_data[0]['current_rly_unit_id'])
#                                 # newuser.is_active= True
#                                 # newuser.is_admin=False
#                                 # newuser.save()
                                
#                                 # MED_LVLDESG.objects.filter(MAVDESG = act_data[0]['desigination']).update(MAVDESGUSER = id)

#                                 designation_Change_Request.objects.filter(record_id=record_id).update(action_by=cuser,action_date=datetime.now(),action_remarks=pullBackRemark,status='Accepted')
#                                 msg = 'Successfully Accepted the New Designation'

#                     else:
#                         msg = 'Failed to Accept'
                        
#                     msg = 'success'
#             return JsonResponse(msg, safe = False)
        

#         if post_type == 'reportingOfficer':
#             rly_unit_id = request.POST.get('new_place')
            
#             rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
#             rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
#             rep_officer = list(MED_LVLDESG.objects.filter(Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in = rly_unit_det)).values('MAVDESG'))
#             rep_officer = list(map( lambda x: x['MAVDESG'],rep_officer))
            
#             return JsonResponse(rep_officer, safe = False)  
        
        
#         return JsonResponse({"success":False}, status=400)  

    
#     details_data = list(MED_LVLDESG.objects.filter((Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in=railwayLocationMaster.objects.filter(parent_rly_unit_code = str(rly_unit_id)).values('rly_unit_code')))).values('MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAIPC7LVLMIN','MAIPCLVLMAX').order_by('MAVDESG'))
#     all_department = list(MEM_DEPTMSTN.objects.filter(MABDELTFLAG = False).values('MACDEPTCODE','MAVDEPTNAME').order_by('MAVDEPTNAME'))
#     all_railway = list(railwayLocationMaster.objects.filter((Q(parent_rly_unit_code = str(rly_unit_id)) | Q(rly_unit_code = rly_unit_id)),location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))
#     level = ['8','9','10','11','12','13','14','15','16','17','18']
#     request_data = designation_Change_Request.objects.filter(status__in = ['Forwarded'],  request_by = usermast.MAV_userid).values().order_by('-request_date')
#     post=Post_master.objects.filter(delete_flag=False).values('post_code').order_by('post_code').distinct('post_code')
#     rly_emp_designation = list(map(lambda x: x['MAVDESG'],details_data))
    
#     parent_rly_unit_code = list(railwayLocationMaster.objects.filter(Q(rly_unit_code = rly_unit_id),location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('parent_rly_unit_code').distinct().order_by('location_code'))
#     forward_to_officer = [rly_unit_id]
#     if len(parent_rly_unit_code) > 0:
#         if parent_rly_unit_code[0]['parent_rly_unit_code'] != None:
#             forward_to_officer =  [rly_unit_id , parent_rly_unit_code[0]['parent_rly_unit_code']]
#     forward_to_officer = list(AdminMaster.objects.filter(~Q(user_id=usermast.MAV_userid), rly_id__in = forward_to_officer,status = 'Active').values('designation', 'emp_name', 'user_id'))

#     for i in request_data:
#         pending_with_officer = ' - '
#         if i['forward_to_officer'] != None and i['status'] == 'Forwarded':
#             d1 = list(AdminMaster.objects.filter(user_id = i['forward_to_officer']).values('designation', 'emp_name', 'user_id'))
#             if len(d1):
#                 pending_with_officer = d1[0]['user_id'] + '-' + d1[0]['designation'] + '-' + d1[0]['emp_name']
#         i.update({'pending_with_officer':pending_with_officer})
 
#     pending = list(designation_Change_Request.objects.filter(status = 'Forwarded', forward_to_officer = usermast.MAV_userid).values().order_by('-request_date'))
#     action_taken = list(designation_Change_Request.objects.filter((Q(request_by = usermast.MAV_userid)|Q(action_by = usermast.MAV_userid)),status__in = ['Accepted', 'Rejected', 'Pulled Back']).values().order_by('-request_date'))
#     len_pending = len(pending)
#     len_forwarded = len(request_data)
#     context ={
#         'len_pending' : len_pending,
#         'len_forwarded' : len_forwarded,
#         'details_data' : details_data,
#         'all_department': all_department,
#         'all_railway': all_railway,
#         'level' : level,
#         'request_data': request_data,
#         'rolelist': rolelist,
#         'pending': pending,
#         'action_taken':action_taken,
#         'post':post,
#         'rly_emp_designation':rly_emp_designation,
#         'forward_to_officer':forward_to_officer,
#     }
#     return render(request, "designation_request.html", context)
    



#-----------------------------------views for user master-------------------------------------

from django.db import transaction
@transaction.atomic
def creatuser_ajax_function(request):
    if request.method == 'POST' and request.is_ajax():  
        post_type = request.POST.get('post_type') 
        if post_type == 'other_details':
                rly_id = request.POST.get('val')
            
                divisions = railwayLocationMaster.objects.filter(parent_rly_unit_code = rly_id).values('location_code', 'rly_unit_code','location_type').order_by('location_code')

                return JsonResponse(list(divisions), safe = False) 
            
        if post_type == 'hrms_details':
            hrmsId = request.POST.get('designation')
            hrms_details = list(HRMS.objects.filter(hrms_employee_id = hrmsId).values('ipas_employee_id','employee_first_name','employee_middle_name','employee_last_name'))
            emp_no = ''
            emp_name = ''
            if len(hrms_details) > 0:
                emp_no = hrms_details[0]['ipas_employee_id']
                emp_name = hrms_details[0]['employee_first_name']
                if hrms_details[0]['employee_middle_name'] != None:
                    emp_name = emp_name + ' ' + hrms_details[0]['employee_middle_name']
                if hrms_details[0]['employee_last_name'] != None:
                    emp_name = emp_name + ' ' + hrms_details[0]['employee_last_name']

            
            context ={
                'emp_no':emp_no,
                'emp_name':emp_name,
               
            }
            return JsonResponse(context, safe = False) 
        
        if post_type == 'emp_details':
            designation = request.POST.get('designation')
            reporting_officer = ''
            acc_details = []
            emp_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAIRLYUNIT_id','MAVDEPTCODE_id','MAVDLVL','MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAIPC7LVLMIN','MAIPCLVLMAX','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAVSTTNNAME','MAVPARDESGCODE','MAVSTTS').order_by('-MAVSTTS','MAVDESG'))
            acc = list(MEM_usersn.objects.filter(MAV_userdesig = designation).values('hrms','MAV_username','MAV_divcode_id__MAV_locname','MAV_rprtto_id','MAV_finid_id','MAV_rprtto_id__MAV_userdesig','MAV_finid_id__MAV_userdesig','coordinator','MAV_userlvlcode_id'))
            if len(emp_details) > 0: 
                reporting_officer = list(MED_LVLDESG.objects.filter(MAADESGCODE = emp_details[0]['MAVPARDESGCODE']).values('MAVDESG'))
                if len(reporting_officer) > 0:
                    reporting_officer = reporting_officer[0]['MAVDESG']
                else:
                    reporting_officer = ''
            #'MAV_username','MAV_divcode_id__MAV_locname','MAV_rprtto_id__MAV_userdesig','MAV_finid_id__MAV_userdesig','coordinator'
            if len(acc):
                hrms_id = '-'
                emp_name = '-'
                emp_no = '-'
                if acc[0]['hrms'] != None:
                    hrms_id = acc[0]['hrms']
                    hrms_details = list(HRMS.objects.filter(hrms_employee_id = acc[0]['hrms']).values('ipas_employee_id','employee_first_name','employee_middle_name','employee_last_name'))
                    if len(hrms_details) > 0:
                        emp_no = hrms_details[0]['ipas_employee_id']
                        emp_name = hrms_details[0]['employee_first_name']
                        if hrms_details[0]['employee_middle_name'] != None:
                            emp_name = emp_name + ' ' + hrms_details[0]['employee_middle_name']
                        if hrms_details[0]['employee_last_name'] != None:
                            emp_name = emp_name + ' ' + hrms_details[0]['employee_last_name']

                acc_details = [
                    {
                        'MAV_rprtto_id': acc[0]['MAV_rprtto_id'],
                        'MAV_finid_id': acc[0]['MAV_finid_id'],
                        'MAV_userlvlcode_id': acc[0]['MAV_userlvlcode_id'],
                        'hrms_id':hrms_id,
                        'emp_name':emp_name,
                        'emp_no':emp_no,
                        'username':acc[0]['MAV_username'],
                        'location':acc[0]['MAV_divcode_id__MAV_locname'] if acc[0]['MAV_divcode_id__MAV_locname'] != None else '-',
                        'submit_officer':acc[0]['MAV_rprtto_id__MAV_userdesig'] if acc[0]['MAV_rprtto_id__MAV_userdesig'] != None else '-',
                        'finance_officer':acc[0]['MAV_finid_id__MAV_userdesig'] if acc[0]['MAV_finid_id__MAV_userdesig'] != None else '-',
                        'coordinator':'Yes' if acc[0]['coordinator'] == True else 'No'
                    }
                ]
            
            if emp_details[0]['MAIRLYUNIT_id__location_type'] == 'RB':
                railway = ''
                division = ''
                other = ''
                radio_type = 'rb'
                userlevel = list(MED_userlvls.objects.filter(rlgroup = 'RB', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
            elif list(rlyhead.objects.filter(rlshortcode = emp_details[0]['MAIRLYUNIT_id__location_type']).values('rltype'))[0]['rltype'] == 'HQ':
                radio_type = 'zr/pu' 
                userlevel = list(MED_userlvls.objects.filter(rlgroup = 'HQ', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
                railway = emp_details[0]['MAIRLYUNIT_id']
                division = ''
                other = ''
            elif list(rlyhead.objects.filter(rlshortcode = emp_details[0]['MAIRLYUNIT_id__location_type']).values('rltype'))[0]['rltype'] == 'DIV':
                radio_type = 'div/workshop'
                userlevel = list(MED_userlvls.objects.filter(rlgroup = 'DIV', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
                railway = list(railwayLocationMaster.objects.filter(rly_unit_code = emp_details[0]['MAIRLYUNIT_id']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
                division = emp_details[0]['MAIRLYUNIT_id']
                other = ''
            else:
                radio_type = 'Other'
                userlevel = list(MED_userlvls.objects.filter(rlgroup = 'DIV', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
                division = list(railwayLocationMaster.objects.filter(rly_unit_code = emp_details[0]['MAIRLYUNIT_id']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
                other = emp_details[0]['MAIRLYUNIT_id']
                railway = list(railwayLocationMaster.objects.filter(rly_unit_code = division).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']

            

            department = emp_details[0]['MAVDEPTCODE_id']
            
            try:
                if radio_type == 'rb':
                    obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = railwayLocationMaster.objects.filter(location_type='RB').values('rly_unit_code'), MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE'))
                    submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = railwayLocationMaster.objects.filter(location_type='RB').values('rly_unit_code'), MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(i for i in submit_proposal_to if i['MAV_deptcode'] == '1')

                elif radio_type == 'zr/pu':
                    obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = railway, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE'))
                    lst = []
                    all_rly_inc_p = [str(railway)]
                    all_parent_id = getAllParentIdList(lst,railway)
                    all_rly_inc_p.extend(all_parent_id)
                    submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = railway, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
                elif radio_type == 'div/workshop':
                    obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE'))
                    lst = []
                    all_rly_inc_p = [str(division)]
                    all_parent_id = getAllParentIdList(lst,division)
                    all_rly_inc_p.extend(all_parent_id)
                    submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
                else:
                    
                    obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = other, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE'))
                    lst = []
                    all_rly_inc_p = [str(division)]
                    all_parent_id = getAllParentIdList(lst,division)
                    all_rly_inc_p.extend(all_parent_id)
                    submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
                    finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
            except:
                obj = []
                submit_proposal_to = []
                finance_officer = []
            context ={
                'userlevel':userlevel,
                'finance_officer':finance_officer,
                'submit_proposal_to':submit_proposal_to,
                'emp_details':emp_details,
                'reporting_officer':reporting_officer,
                'acc_details':acc_details,
            }
            return JsonResponse(context, safe = False) 
        
        if post_type == 'check_user':
            railway = request.POST.get('railway')
            division = request.POST.get('division')
            other = request.POST.get('other')
            if railway == '':
                rly_unit_code = list(railwayLocationMaster.objects.filter(location_type = 'RB', location_code = 'RB').values('rly_unit_code'))[0]['rly_unit_code']
                railway = rly_unit_code
                co_div = rly_unit_code
                co_type = 'RB'
            elif division == '':
                railway = railway
                co_div = railway
                co_type = 'HQ'
            elif other == '':
                railway = division
                co_div = division
                co_type = 'DIV'
            else:
                railway = other
                co_div = division
                co_type = 'DIV'


            userid = request.POST.get('user_id')
            designation = request.POST.get('designation')
            user_type = request.POST.get('userlevel')
            department = request.POST.get('department')
            willsubmitto= request.POST.get('willsubmitto')
            financeassociate = request.POST.get('financeassociate')
            hrms_id = request.POST.get('hrms_id')
            msg = 'Do you want to proceed.'
            flag = 'T'
            co_id  = list(MED_userlvls.objects.filter(nodel_flag = True).values_list('MAV_userlvlcode', flat = True))
            coordinator = False
            if user_type in co_id:
                coordinator = True
            
            if MEM_usersn.objects.filter(designation_id = designation).exists():
                msg = 'Designation is already Exists cannot be created. '
                flag = 'F'
            elif MEM_usersn.objects.filter(MAV_username = userid).exists():
                msg = 'Username is already Exists cannot be created. '
                flag = 'F'
            elif MEM_usersn.objects.filter(hrms = hrms_id).exists():
                msg = 'HRMS Id already Linked with other designation, Do you want to Proceed. '
                flag = 'T'
            elif coordinator == True and MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).exists():
                msg = 'co-ordinator is already exist, Do you want to Proceed. '
                flag = 'T'
            return JsonResponse({'flag':flag, 'msg':msg}, safe = False) 
        
        if post_type == 'create_user':
            railway = request.POST.get('railway')
            division = request.POST.get('division')
            other = request.POST.get('other')
            if railway == '':
                rly_unit_code = list(railwayLocationMaster.objects.filter(location_type = 'RB', location_code = 'RB').values('rly_unit_code'))[0]['rly_unit_code']
                railway = rly_unit_code
                co_div = rly_unit_code
                co_type = 'RB'
            elif division == '':
                railway = railway
                co_div = railway
                co_type = 'HQ'
            elif other == '':
                railway = division
                co_div = division
                co_type = 'DIV'
            else:
                railway = other
                co_div = division
                co_type = 'DIV'


            userid = request.POST.get('user_id')
            designation = request.POST.get('designation')
            user_type = request.POST.get('userlevel')
            department = request.POST.get('department')
            willsubmitto= request.POST.get('willsubmitto')
            financeassociate = request.POST.get('financeassociate')
            hrms_id = request.POST.get('hrms_id')
            
            if MEM_usersn.objects.filter(hrms = hrms_id).exists():
                MEM_usersn.objects.filter(hrms = hrms_id).update(hrms = None)
            co_id  = list(MED_userlvls.objects.filter(nodel_flag = True).values_list('MAV_userlvlcode', flat = True))
            
            coordinator = False
            if user_type in co_id:
                coordinator = True
            if coordinator == True and MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).exists():
                MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).update(coordinator = False, MAV_userlvlcode = None)
            
            

            default_password = "Admin@123"
            hrms_object = HRMS.objects.filter(hrms_employee_id = hrms_id).first()
            hashed_password = make_password(default_password)
            current_time_date = datetime.datetime.now()
            
            if not MED_dvsnmstn.objects.filter(MAV_railcode = co_div, MAC_flag = True).exists():
                MED_dvsnmstn.objects.create(
                        MAV_railcode_id = co_div,
                        MAV_railtype = co_type,
                        MAD_datetimecrtn = current_time_date,
                        MAC_flag = True
                    )
            
            h = MEM_usersn.objects.create(
                MAV_username = userid,
                designation_id_id = designation,
                MAV_userdesig = list(MED_LVLDESG.objects.filter(MAADESGCODE = designation).values('MAVDESG'))[0]['MAVDESG'],
                MAV_rlycode_id = railway,
                MAV_divcode_id = list(MED_dvsnmstn.objects.filter(MAV_railcode = co_div).values('MAV_dvsncode'))[0]['MAV_dvsncode'],
                MAV_userlvlcode_id = user_type,
                MAV_crtdby = request.user,
                MAV_deptcode_id = department,
                MAD_datetimecrtn = current_time_date,
                MAV_rprtto_id = willsubmitto,
                MAV_finid_id = financeassociate,
                password  = hashed_password,
                hrms = hrms_id,
                is_active = True,
                coordinator = coordinator
            )

            MEM_usersn_history.objects.create(
                MAV_username = userid,
                designation_id = designation,
                MAV_userdesig = list(MED_LVLDESG.objects.filter(MAADESGCODE = designation).values('MAVDESG'))[0]['MAVDESG'],
                MAV_rlycode = railway,
                MAV_divcode = list(MED_dvsnmstn.objects.filter(MAV_railcode = co_div).values('MAV_dvsncode'))[0]['MAV_dvsncode'],
                MAV_userlvlcode = user_type,
                MAV_crtdby = request.user,
                MAV_deptcode = department,
                MAD_datetimecrtn = current_time_date,
                MAV_rprtto = willsubmitto,
                MAV_finid = financeassociate,
                hrms = hrms_id,
                coordinator = coordinator,
                type = 'NEW',
                remarks = 'Newely added records',
                datetimecrtn = current_time_date
            )
            if coordinator == True:
                MED_dvsnmstn.objects.filter(MAV_railcode = co_div, MAC_flag = True).update(MAC_user_id = h)
            MED_userprsninfo.objects.create(
                MAV_userid = list(MEM_usersn.objects.filter(MAV_username = userid).values('MAV_userid'))[0]['MAV_userid']
            )
    


            return JsonResponse('Saved successfully', safe = False) 
        
        if post_type == 'reset_password':
            designation = request.POST.get('designation')
            default_password = "Admin@123"
            hashed_password = make_password(default_password)
            MEM_usersn.objects.filter(MAV_userdesig = designation).update(password  = hashed_password)

            return JsonResponse('Saved successfully', safe = False) 
        
        if post_type == 'releinquish':
            designation = request.POST.get('designation')
            remarks = request.POST.get('remarks')
            prev_data = list(MEM_usersn.objects.filter(MAV_userdesig = designation).values())
            current_time_date = datetime.datetime.now()
            if MEM_usersn.objects.exclude(hrms__isnull = True).filter(MAV_userdesig = designation).exists():
                MEM_usersn.objects.filter(MAV_userdesig = designation).update(MAV_crtdby = str(request.user), hrms = None, last_update = current_time_date)
                
                MEM_usersn_history.objects.create(
                    prev_username = prev_data[0]['MAV_username'],
                    prev_designation_id = prev_data[0]['designation_id_id'],
                    prev_userdesig = prev_data[0]['MAV_userdesig'],
                    prev_rlycode = prev_data[0]['MAV_rlycode_id'],
                    prev_divcode = prev_data[0]['MAV_divcode_id'],
                    prev_userlvlcode = prev_data[0]['MAV_userlvlcode_id'],
                    prev_crtdby = prev_data[0]['MAV_crtdby'],
                    prev_deptcode = prev_data[0]['MAV_deptcode_id'],
                    prev_datetimecrtn = prev_data[0]['MAD_datetimecrtn'],
                    prev_rprtto = prev_data[0]['MAV_rprtto_id'],
                    prev_finid = prev_data[0]['MAV_finid_id'],
                    prev_hrms = prev_data[0]['hrms'],
                    prev_coordinator = prev_data[0]['coordinator'],
                    type = 'Vacate',
                    remarks = remarks,
                    datetimecrtn = current_time_date,
                    hrms = None,
                    MAV_crtdby = str(request.user)
                )
                msg = 'Post is Vacant Now'
            else:
                msg = 'Post is already Vacant.'

            return JsonResponse(msg, safe = False) 
        
        if post_type == 'update_user':
            designation = request.POST.get('designation')
            reporting_officer = ''
            acc_details = []
            emp_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAIRLYUNIT_id','MAVDEPTCODE_id','MAVDLVL','MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAIPC7LVLMIN','MAIPCLVLMAX','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAVSTTNNAME','MAVPARDESGCODE','MAVSTTS').order_by('-MAVSTTS','MAVDESG'))
            if emp_details[0]['MAIRLYUNIT_id__location_type'] == 'RB':
                railway = ''
                division = ''
                other = ''
            elif list(rlyhead.objects.filter(rlshortcode = emp_details[0]['MAIRLYUNIT_id__location_type']).values('rltype'))[0]['rltype'] == 'HQ':
                railway = emp_details[0]['MAIRLYUNIT_id']
                division = ''
                other = ''
            elif list(rlyhead.objects.filter(rlshortcode = emp_details[0]['MAIRLYUNIT_id__location_type']).values('rltype'))[0]['rltype'] == 'DIV':
                railway = list(railwayLocationMaster.objects.filter(rly_unit_code = emp_details[0]['MAIRLYUNIT_id']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
                division = emp_details[0]['MAIRLYUNIT_id']
                other = ''
            else:
                division = list(railwayLocationMaster.objects.filter(rly_unit_code = emp_details[0]['MAIRLYUNIT_id']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
                other = emp_details[0]['MAIRLYUNIT_id']
                railway = list(railwayLocationMaster.objects.filter(rly_unit_code = division).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']

            
            if railway == '':
                rly_unit_code = list(railwayLocationMaster.objects.filter(location_type = 'RB', location_code = 'RB').values('rly_unit_code'))[0]['rly_unit_code']
                railway = rly_unit_code
                co_div = rly_unit_code
                co_type = 'RB'
            elif division == '':
                railway = railway
                co_div = railway
                co_type = 'HQ'
            elif other == '':
                railway = division
                co_div = division
                co_type = 'DIV'
            else:
                railway = other
                co_div = division
                co_type = 'DIV'


            
            user_type = request.POST.get('change_userlevel')
            willsubmitto= request.POST.get('change_submitto')
            financeassociate = request.POST.get('change_finance')
            hrms_id = request.POST.get('hrms_id')
             
            remarks = request.POST.get('change_remarks')
            
            if MEM_usersn.objects.filter(hrms = hrms_id).exists():
                MEM_usersn.objects.filter(hrms = hrms_id).update(hrms = None)
            co_id  = list(MED_userlvls.objects.filter(nodel_flag = True).values_list('MAV_userlvlcode', flat = True))
            if hrms_id == '':
                hrms_id = None
            coordinator = False
            if user_type in co_id:
                coordinator = True
            if coordinator == True and MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).exists():
                MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).update(coordinator = False, MAV_userlvlcode = None)
            
            current_time_date = datetime.datetime.now()
            
            if not MED_dvsnmstn.objects.filter(MAV_railcode = co_div, MAC_flag = True).exists():
                MED_dvsnmstn.objects.create(
                        MAV_railcode_id = co_div,
                        MAV_railtype = co_type,
                        MAD_datetimecrtn = current_time_date,
                        MAC_flag = True
                    )
            
            prev_data = list(MEM_usersn.objects.filter(MAV_userdesig = designation).values())

            MEM_usersn.objects.filter(MAV_userdesig=designation).update(
                MAV_userlvlcode_id = user_type,
                MAV_crtdby = str(request.user),
                last_update = current_time_date,
                MAV_rprtto_id = willsubmitto,
                MAV_finid_id = financeassociate,
                hrms = hrms_id,
                is_active = True,
                coordinator = coordinator
            )
            h = MEM_usersn.objects.filter(MAV_userdesig=designation).get()
            MEM_usersn_history.objects.create(
                MAV_userlvlcode = user_type,
                MAV_crtdby = request.user,
                MAD_datetimecrtn = current_time_date,
                MAV_rprtto = willsubmitto,
                MAV_finid = financeassociate,
                hrms = hrms_id,
                coordinator = coordinator,
                datetimecrtn = current_time_date,

                prev_username = prev_data[0]['MAV_username'],
                prev_designation_id = prev_data[0]['designation_id_id'],
                prev_userdesig = prev_data[0]['MAV_userdesig'],
                prev_rlycode = prev_data[0]['MAV_rlycode_id'],
                prev_divcode = prev_data[0]['MAV_divcode_id'],
                prev_userlvlcode = prev_data[0]['MAV_userlvlcode_id'],
                prev_crtdby = prev_data[0]['MAV_crtdby'],
                prev_deptcode = prev_data[0]['MAV_deptcode_id'],
                prev_datetimecrtn = prev_data[0]['MAD_datetimecrtn'],
                prev_rprtto = prev_data[0]['MAV_rprtto_id'],
                prev_finid = prev_data[0]['MAV_finid_id'],
                prev_hrms = prev_data[0]['hrms'],
                prev_coordinator = prev_data[0]['coordinator'],
                type = 'Update',
                remarks = remarks
            )
            if coordinator == True:
                MED_dvsnmstn.objects.filter(MAV_railcode = co_div, MAC_flag = True).update(MAC_user_id = h)
            
    


            return JsonResponse('Record Updated successfully', safe = False) 
        
        return JsonResponse({"success":False}, status=400)  


def get_hrms(request):
    if request.method=='GET' or request.is_ajax():
        hrms=request.GET.get('hrms')
        userlevel=request.GET.get('userlevel')
        hrms_id = list(HRMS.objects.filter(hrms_employee_id__icontains = hrms).values('hrms_employee_id').distinct().order_by('hrms_employee_id'))
        if userlevel != '':
            if MED_userlvls.objects.filter(os_flag = False,MAV_userlvlcode = userlevel).exists():
                hrms_id = list(HRMS.objects.filter(hrms_employee_id__icontains = hrms,railway_group__in = ['A','B']).values('hrms_employee_id').distinct().order_by('hrms_employee_id'))
        return JsonResponse({'hrms_id':hrms_id},safe=False)

def fetch_designation(request):
    if request.method == 'GET' or request.is_ajax():
        railway = request.GET.get('railway')
        division = request.GET.get('division')
        department = request.GET.get('department')
        radio_type = request.GET['radio_type']
        other = request.GET['other']  
        # try:
        if radio_type == 'rb':
            obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = railwayLocationMaster.objects.filter(location_type='RB').values('rly_unit_code'), MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE').order_by('MAVDESG'))
            submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = railwayLocationMaster.objects.filter(location_type='RB').values('rly_unit_code'), MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(i for i in submit_proposal_to if i['MAV_deptcode'] == '1')

        elif radio_type == 'zr/pu':
            obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = railway, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE').order_by('MAVDESG'))
            lst = []
            all_rly_inc_p = [str(railway)]
            all_parent_id = getAllParentIdList(lst,railway)
            all_rly_inc_p.extend(all_parent_id)
            submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = railway, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
        elif radio_type == 'div/workshop':
            obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE').order_by('MAVDESG'))
            lst = []
            all_rly_inc_p = [str(division)]
            all_parent_id = getAllParentIdList(lst,division)
            all_rly_inc_p.extend(all_parent_id)
            submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
        else:
            obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE').order_by('MAVDESG'))
            lst = []
            all_rly_inc_p = [str(division)]
            all_parent_id = getAllParentIdList(lst,division)
            all_rly_inc_p.extend(all_parent_id)
            submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')

                
            # obj = list(MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MAVDEPTCODE_id = department,MABDELTFLAG = False).values('MAVDESG','MAADESGCODE').order_by('MAVDESG'))
            # lst = []
            # all_rly_inc_p = [str(division)]
            # all_parent_id = getAllParentIdList(lst,division)
            # all_rly_inc_p.extend(all_parent_id)
            # submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            # finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode').order_by('MAV_userdesig'))
            # finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
        # except:
        #     obj = []
        #     submit_proposal_to = []
        #     finance_officer = []
        return JsonResponse({'obj':obj,'finance_officer':finance_officer,'submit_proposal_to':submit_proposal_to})

def pdfandexcelgeneration(request):
    return render(request,'pdfandexcelgeneration.html')

def check_hrms(request):
    if request.method == 'GET' or request.is_ajax():
        hrms = request.GET.get('hrms')
        if MEM_usersn.objects.filter(hrms =hrms).exists():
            return JsonResponse({'exists':True})
        else:
            return JsonResponse({'exists':False})

def coordinator_check(request):
    if request.method == 'GET' or request.is_ajax():
        railway = request.GET.get('railway')
        division = request.GET.get('division')
        
        if MED_dvsnmstn.objects.filter(MAV_railcode = railway, MAV_dvsncode = division).exists():
            #print("exist")
            return JsonResponse({'exists':True})
        else:
            #print("notexist")
            return JsonResponse({'exists':False})

def getAllParentIdList(lst,child_id):
    user_rly_details= list(railwayLocationMaster.objects.filter(rly_unit_code=child_id).values('parent_rly_unit_code'))
    if len(user_rly_details):
        if user_rly_details[0]['parent_rly_unit_code'] != child_id:
            lst.append(user_rly_details[0]['parent_rly_unit_code'])
            getAllParentIdList(lst,user_rly_details[0]['parent_rly_unit_code'])
    return lst

def getAllChildIdList(lst,child_id):
    user_rly_details= list(railwayLocationMaster.objects.filter(parent_rly_unit_code = child_id).values('rly_unit_code'))
    if len(user_rly_details):
        for i in range(len(user_rly_details)):
            if user_rly_details[i]['rly_unit_code'] not in lst:
                lst.append(user_rly_details[i]['rly_unit_code'])
                getAllChildIdList(lst,user_rly_details[i]['rly_unit_code'])
    return lst


def createuser(request):
    #####  start from here
    default_flag = request.GET.get('default_flag')
    if default_flag == None:
        context = {
                'default_flag' : '0'
                
            }
        return render(request, 'createuser_before.html', context)

    lst = []
    user_rly_id = request.user.MAV_rlycode_id
    all_rly_inc_p = [str(user_rly_id)]
    all_parent_id = getAllParentIdList(lst,user_rly_id)
    all_rly_inc_p.extend(all_parent_id) 
    user_rly_code = ''
    user_rly_type = ''
    user_userlevel = []
    user_rly_head = ''
    division = []
    user_rly_details= list(railwayLocationMaster.objects.filter(rly_unit_code=user_rly_id).values())
    if len(user_rly_details):
        user_rly_code = user_rly_details[0]['location_code']
        user_rly_type = user_rly_details[0]['location_type']
    
    if user_rly_type != '':
        rly_head = list(rlyhead.objects.filter(rlshortcode = user_rly_type).values('rltype'))
        if len(rly_head):
            user_rly_head = rly_head[0]['rltype']
            user_userlevel = list(MED_userlvls.objects.filter(rlgroup = rly_head[0]['rltype'], delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
   
    if user_rly_head == 'RB':
        radio_selected = 1
    elif user_rly_head == 'HQ':
        radio_selected = 2
    else:
        radio_selected = 3
    if request.user.MAV_userlvlcode_id in ['1', '2']:
        radio_option = 'Y'
        radio_selected = 1
        user_userlevel = list(MED_userlvls.objects.filter(rlgroup = 'RB', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
        obj3 = MEM_usersn.objects.exclude(MAV_userlvlcode__admin_flag = True).filter(~Q( MAV_userid = 4838), is_active = True).values(
                'MAV_username',
                'MAV_userlvlcode__MAV_userlvlname',
                'MAV_userdesig',
                'MAV_userid',
                'MAV_rprtto__MAV_userdesig',
                'MAV_finid__MAV_userdesig',
                'MAV_rlycode__location_code',
                'MAV_divcode',
                'hrms',
                'MAV_deptcode__MAVDEPTNAME',
                'MAV_rlycode',
                'MAV_rlycode__parent_location_code'
            )
        railway = railwayLocationMaster.objects.filter(location_type__in = rlyhead.objects.filter(rltype = 'HQ').values('rlshortcode')).values('location_code', 'rly_unit_code','location_type').order_by('-location_type','location_code')
    else:
         railway = railwayLocationMaster.objects.filter(rly_unit_code = user_rly_id).values('location_code', 'rly_unit_code','location_type').order_by('-location_type','location_code')
        #  division = railwayLocationMaster.objects.filter(parent_rly_unit_code = user_rly_id, location_type__in = rlyhead.objects.filter(rltype__in = ['DIV','UNIT']).values('rlshortcode')).values('location_code', 'rly_unit_code','location_type').order_by('-location_type')
         radio_option = 'N'
         if user_rly_head in ['DIV', 'HQ']:
            lst = [user_rly_id]
            child_id = getAllChildIdList(lst, user_rly_id)
            obj3 = MEM_usersn.objects.exclude(MAV_userlvlcode__admin_flag = True).filter(~Q( MAV_userid= 4838), is_active=True, MAV_rlycode__in = child_id).values(
                'MAV_username',
                'MAV_userlvlcode__MAV_userlvlname',
                'MAV_userdesig',
                'MAV_userid',
                'MAV_rprtto__MAV_userdesig',
                'MAV_finid__MAV_userdesig',
                'MAV_rlycode__location_code',
                'MAV_divcode',
                'hrms',
                'MAV_deptcode__MAVDEPTNAME',
                'MAV_rlycode',
                'MAV_rlycode__parent_location_code'
            )
         else:
            obj3 = MEM_usersn.objects.exclude(MAV_userlvlcode__admin_flag = True).filter(~Q( MAV_userid= 4838), is_active=True, MAV_rlycode = user_rly_id).values(
                'MAV_username',
                'MAV_userlvlcode__MAV_userlvlname',
                'MAV_userdesig',
                'MAV_userid',
                'MAV_rprtto__MAV_userdesig',
                'MAV_finid__MAV_userdesig',
                'MAV_rlycode__location_code',
                'MAV_divcode',
                'hrms',
                'MAV_deptcode__MAVDEPTNAME',
                'MAV_rlycode',
                'MAV_rlycode__parent_location_code'
            )
    for item in obj3:
        MAV_divcode = item['MAV_divcode']
        MAV_rlycode = item['MAV_rlycode']
        item['division'] = '-'
        exist = list(railwayLocationMaster.objects.filter(location_type__in = rlyhead.objects.filter(rltype = 'HQ').values('rlshortcode'),rly_unit_code = MAV_rlycode).values('location_code', 'rly_unit_code','location_type','parent_location_code'))
        if  len(exist) == 0:
            item['division'] = item['MAV_rlycode__location_code']
            item['MAV_rlycode__location_code'] = item['MAV_rlycode__parent_location_code']
            
                           
        trans_obj = MED_dvsnmstn.objects.filter(MAV_dvsncode=MAV_divcode).first()
        if trans_obj:
            item['MAV_dvsnname'] = trans_obj.MAV_dvsnname
        else:
            item['MAV_dvsnname'] = None
    departs = MEM_DEPTMSTN.objects.all().order_by('MAVDEPTNAME')

    rb_userlevel = list(MED_userlvls.objects.filter(rlgroup = 'RB', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
    hq_userlevel = list(MED_userlvls.objects.filter(rlgroup = 'HQ', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
    div_userlevel = list(MED_userlvls.objects.filter(rlgroup = 'DIV', delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
    userlevel = list(MED_userlvls.objects.filter(delete_flag = False, admin_flag = False).values('MAV_userlvlcode', 'MAV_userlvlname'))
    
    context = {
        'rb_userlevel':json.dumps(rb_userlevel),
        'hq_userlevel':json.dumps(hq_userlevel),
        'div_userlevel':json.dumps(div_userlevel),
        'all_userlevel':json.dumps(userlevel),
        'radio_option' : radio_option,
        'radio_selected':radio_selected,
        'user_userlevel':user_userlevel,
        'obj3': obj3,
        'railway': railway,
        'departs': departs,
        'userlevel':userlevel,
        'default_flag':default_flag,
    }
    return render(request, 'createuser.html', context)



def getdivision(request):
    if request.method == 'GET' or request.is_ajax():
        railway_location = request.GET.get('railway')
        divisions = railwayLocationMaster.objects.filter(parent_rly_unit_code = railway_location, location_type__in = rlyhead.objects.filter(rltype__in = ['DIV']).values('rlshortcode')).values('location_code', 'rly_unit_code','location_type').order_by('location_type','location_code')
        return JsonResponse({'obj': list(divisions)})


def save_userform(request):
    if request.method == 'GET' or request.is_ajax():
        railway = request.GET.get('railway')
        division = request.GET.get('division')
        other = request.GET.get('other')
        userid = request.GET.get('user_id')
        designation = request.GET.get('designation')
        user_type = request.GET.get('userlevel')
        department = request.GET.get('department')
        willsubmitto= request.GET.get('willsubmitto')
        financeassociate = request.GET.get('financeassociate')
        hrms_id = request.GET.get('hrms_id')
        print(railway,division,other,designation,userid,user_type,department,willsubmitto,financeassociate,hrms_id)

        current_user = request.user
        print(current_user1)
        #print(userid,'//////////////////////////////////')
        #print(user_type,'/////////////////////////////////////////////////////')

        # userid = request.POST.get('userid')
        # user_type = request.POST.get('user_type')


        
        default_password = "admin@123"
        hrms_object = HRMS.objects.filter(hrms_employee_id = hrms_id).first()
        first_name = hrms_object.employee_first_name
        middle_name = hrms_object.employee_middle_name
        last_name = hrms_object.employee_last_name
        email = hrms_object.official_email_id
        phone = hrms_object.official_mobile_no 
        hashed_password = make_password(default_password)
        current_time_date = datetime.now()
        if(role == 'c'):
            rly = railwayLocationMaster.objects.filter()
            MED_dvsnmstn.objects.create(
                MAV_dvsncode = division,
                MAV_railcode = railway,
            )
        if user_type == '10' or user_type == '11' or user_type == '19':
            usergrp = '1'
        elif user_type == '20' or user_type == '21' or user_type == '29':
            usergrp = '2'
        elif user_type == '30' or user_type == '31' or user_type == '35' or user_type == '39':
            usergrp = '3'
        h = MEM_usersn.objects.create(
            MAV_username=userid,
            MAV_userdesig=designation,
            MAV_rlycode_id=railway,
            MAV_divcode=division,
            MAV_usergrpcode = usergrp,
            MAV_userlvlcode_id=user_type,
            MAV_crtdby=current_user,
            MAV_deptcode_id=department,
            MAD_datetimecrtn = current_time_date,
            # MAV_fname = first_name,
            # Mav_mname = middle_name,
            # Mav_lname = last_name,
            MAV_rprtto = willsubmitto,
            MAV_finid =financeassociate,
            password=hashed_password,
            # MAV_mail = email,
            # MAV_ph = phone,
            hrms = hrms_id
        )
        MED_userprsninfo.objects.create(
              MAV_userid_id=h
        )
        #print(";;;;;;;;;;;;;;;;;;;;")

        #print(railway,'/////////////////////////////////////')
        return JsonResponse({'Success':'Records saved successfully'})
          # Redirect to a success page after saving the data




def checkifexist(request):
    try:
        userid = request.GET.get('userid')
        user_exists = MEM_usersn.objects.filter(MAV_username=userid).exists()
        return JsonResponse({'exists': user_exists})
    except Exception as e: 
        try:
            MED_ERORTBLE.objects.create(MAVFUNNAME="checkifexist", MAV_userid=request.user, MATERORDTLS=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "errorspage.html", {})


def finAssociate(request):
    # if request.user.level=20
    if request.method=='GET' or request.is_ajax():
        usrLevel=request.GET.get('usrLevel')
        #print('function getss data')
        if usrLevel == '21' :#HQ EXECUTIVE
            usrLevel = '29'
            fin_users = list(MEM_usersn.objects.filter(MAV_userlvlcode=usrLevel).values_list('MAV_userid',flat=True).order_by('MAV_userid'))
        
        elif usrLevel == '31':
            usrLevel = '39'
            fin_users = list(MEM_usersn.objects.filter(MAV_userlvlcode=usrLevel).values_list('MAV_userid',flat=True).order_by('MAV_userid'))
        

        elif usrLevel == '11':
            usrLevel = '19'
            fin_users = list(MEM_usersn.objects.filter(MAV_userlvlcode=usrLevel).values_list('MAV_userid',flat=True).order_by('MAV_userid'))
        else:
            fin_users = ''
        #print('fin_users',fin_users)
       

        report_users = list(MEM_usersn.objects.filter().values_list('MAV_userid','MAV_userlvlcode'))

        listmyt = []
        for i in report_users:
            if int(i[1]) > int(usrLevel):
                listmyt.append(i[0])
        #print('listmyt',listmyt)

        
        #print('report_users',report_users)

        sorted_listmyt = sorted(listmyt, key=lambda x: x.lower())
        #print('Sorted listmyt:', sorted_listmyt)


        # for i in userlevel:
        #     if i.HQ Executive == 
        # return JsonResponse({'success':'data fetched successfully '})
        return JsonResponse({'fin_users':fin_users,'listmyt':sorted_listmyt},safe=False)
         
        

        # if usrLevel == 'HQ Executive' or usrLevel == 'Division/Workshop Executive':
        #     fin_users = MEM_usersn.objects.filter(MAV_userlvlcode=usrLevel).values_list('MAV_userid',flat=True)
        # else:
        #     fin_users = 'None'



#---------------------------------------------------------------------------------------------




#---------------------------------------------------------------------------------------------

def editUser(request):
    if request.method == "GET" or request.is_ajax():
        uid = request.GET.get('uid')
        userObj = list(MED_userprsninfo.objects.filter(MAV_userid=uid).values())
        if userObj:
            print('userObj', userObj[0]['MAV_mail'])
        else:
            print('No user found with the provided user ID:', uid)
        return JsonResponse({'userObj': userObj})
    return JsonResponse({'error': 'Invalid request method'})



def fetchUserDataFromMEM(request):
    if request.method == "GET" or request.is_ajax():
        uid = request.GET.get('uid')
        userData = list(MEM_usersn.objects.filter(MAV_userid=uid).values())  # Fetch data from REM_usersn table
        return JsonResponse(userData, safe=False)
    return JsonResponse({'error': 'Invalid request method'})


def get_pincode(request):
    if request.method == 'GET' or request.is_ajax():
        state = request.GET.get('state')
        pincode = list(locationMaster.objects.filter(state=state).values_list('pincode', flat=True).order_by('pincode'))
        print("pincode")
        print(pincode)
        return JsonResponse({'pincode': pincode}, safe=False)


def editUserinfo(request):
    if request.method == 'POST' or request.is_ajax():
        hrms = request.POST.get('hrms')
        username = request.POST.get('username')
        charge = request.POST.get('charge')
        unit = request.POST.get('unit')
        userlevel = request.POST.get('userlevel')
        mobileno = request.POST.get('mobileno')
        mailid = request.POST.get('mailid')
        offname = request.POST.get('offname')
        offpincode = request.POST.get('offpincode')
        submitted_to = request.POST.get('submitted_to')
        acc_associate = request.POST.get('acc_associate')
        firstname=""
        middlename=""
        lastname=""
        if hrms:
            obj = HRMS.objects.filter(hrms_employee_id = hrms)
            firstname = obj.employee_first_name
            middlename = obj.employee_middle_name
            lastname = obj.employee_last_name
        obj = MEM_usersn.objects.filter(MAV_username = username).update(hrms = hrms, MAV_ph = mobileno, MAV_mail = mailid, MAV_rprtto = submitted_to, MAV_finid = acc_associate, MAV_fname = firstname, Mav_mname = middlename, Mav_lname = lastname)
        MED_userprsninfo.objects.filter(MAV_ID = obj.MAV_userid).update(MAV_offpin = offpincode, MAV_offaddr1 = unit, MAV_offaddr2 = offname)
        return JsonResponse({"success":False}, status=400)
        
        
def check_phone(request):
    if request.method == 'GET' or request.is_ajax():
        phone = request.GET.get('phone')
        charge = request.GET.get('charge')
        if MED_LVLDESG.objects.filter(MAV_ph =phone).exists():
            if charge == 'P':
                return JsonResponse({'exists':True})
            else:
                return JsonResponse({'exists':False})
        else:
            return JsonResponse({'exists':False})
        

def checkifexist1(request):
    try:
        divisioncode=request.GET.get('divisioncode')
        if(MED_dvsnmstn.objects.filter(MAV_dvsncode=divisioncode).exists()):
            print(divisioncode,'//////////////////////////////////')
            bono=[]
        else:
            bono=[1]
        return JsonResponse(bono,safe = False)
    except Exception as e: 
        try:
            MED_ERORTBLE.objects.create(MAVFUNNAME="checkifexist",MAV_userid=request.user,MATERORDTLSwwszz=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "errorspage.html", {})
  
    
        
       
def check_email(request):
    if request.method == 'GET' or request.is_ajax():
        email = request.GET.get('email')
        charge = request.GET.get('charge')
        if MED_LVLDESG.objects.filter(MAVOFCLMAILID = email).exists():
            return JsonResponse({'exists':True})
        else:
            return JsonResponse({'exists':False})
        


### changed 12-07-24

#add post
def postmaster(request):
    # from mnpapp.models import Post_master
    if request.method == "GET" and request.is_ajax():   
        op=request.GET.get("op")     
        if op == "create":
            department = request.GET.get('department')
            pd = request.GET.get('pd')
            pc = request.GET.get('pc')
            catg = request.GET.get('catg')
            min = request.GET.get('min')
            max = request.GET.get('max')
            if Post_master.objects.all().exists():
                id=Post_master.objects.all().last().post_id
            else:
                id=0       
            a = Post_master.objects.create(post_id = id+1, post_desc = pd, post_code = pc, category = catg, pc7_levelmin = min, pc7_levelmax = max, department_code_id = department)
            return JsonResponse({'success':True,'pi':a.post_id}, safe=False)
        elif op == "delete":
            PostCode = request.GET.get('post_id')
            key = request.GET.get('key')
            if key =="disable":
                Post_master.objects.filter(post_id = PostCode ).update(delete_flag = True)
                data='1'
            else:
                Post_master.objects.filter(post_id = PostCode ).update(delete_flag = False)
                data='2'
            return JsonResponse({"success":True,'data':data},safe=False)
        elif op == "postdesc":
            val = request.GET.get('val')
            if Post_master.objects.filter(post_desc = val ).exists():
                data='1'
            else:
                data='2'
            return JsonResponse({"success":True,'data':data},safe=False)
        elif op == "postcode":
            val = request.GET.get('val')
            if Post_master.objects.filter(post_code = val ).exists():
                data='1'
            else:
                data='2'
            return JsonResponse({"success":True,'data':data},safe=False)
        elif op == "update":
            department = request.GET.get('department')
            PostCode = request.GET.get('pid')
            PostDescription = request.GET.get('pdesc')
            pc = request.GET.get('pcode')
            category = request.GET.get('cat')
            MinLevel = request.GET.get('minlevel')
            MaxLevel = request.GET.get('maxlevel')        
            Post_master.objects.filter(post_id=PostCode).update(department_code_id = department,post_desc = PostDescription, post_code = pc,category = category,pc7_levelmin = MinLevel, pc7_levelmax = MaxLevel)
            return JsonResponse({'success':True}, safe=False)
        return JsonResponse({'success':False}, safe=False)
    obj = Post_master.objects.all()
    postid = (Post_master.objects.aggregate(max_value=Max('post_id'))['max_value'])+1
    cate= Category.objects.all().values('category').distinct('category').order_by('category')
    unit=MEM_DEPTMSTN.objects.filter(MABDELTFLAG=False).values('MAVDEPTNAME','MACDEPTCODE').order_by('MAVDEPTNAME').distinct('MAVDEPTNAME')

    a=[]
    for i in range(20):
        a.append((i+1))
    return render(request, "Post_master.html", {'obj':obj,'postid':postid,'cate':cate,'level':a, 'unit':unit})

#add designation
def add_designation(request):    
    if request.method == "GET" and request.is_ajax():
        op=request.GET.get('op')
        if op=="getsection_byshop":
            shop = request.GET.get('shop')
            shop=list(Shop_section.objects.filter(shop_code=shop).values('section_desc').distinct('section_code'))
            l=[]
            for i in shop:
                l.append(i['section_desc'])
            print(l)    
            context={
                'shop':l,
            } 
            return JsonResponse(context, safe = False)
        elif op=="getshop_bydept":
            dept = request.GET.get('dept')
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=dept)[0].MACDEPTCODE
            shop=list(Shop_section.objects.filter(department_code_id=dept_id).values('shop_code').distinct('shop_code'))
            print(shop)
            l=[]
            for i in shop:
                l.append(i['shop_code'])
            print(l)    
            context={
                'shop':l,
            } 
            return JsonResponse(context, safe = False)
        elif op=="section_bydept":
            dept = request.GET.get('dept')
            sectiondept = request.GET.get('sectiondept')
            print(sectiondept)
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=dept)[0].MACDEPTCODE
            print(dept_id)
            section_desc=list(Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).values('section_desc').distinct('section_desc'))
            print(section_desc)
            context={
                'section_desc':section_desc,
            }
            return JsonResponse(context, safe = False)
        elif op=="shop_bydept":
            dept = request.GET.get('dept')
            # print("===================",dept)
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=dept)[0].MACDEPTCODE
            # print("========id===========",dept_id)
            shop_code=list(Shop_section.objects.filter(department_code_id=dept_id).values('shop_code').distinct('shop_code'))
            # print(shop_code)
            context={
                'shop_code':shop_code,
            }
            return JsonResponse(context, safe = False)
        elif op=="railwaytype":
            railwaytype=request.GET.get('rltype')
            if railwaytype=='OFFICE':
                railway=list(railwayLocationMaster.objects.filter(location_type_desc='OFFICE').values('location_code').distinct('location_code'))
            elif railwaytype=='HEAD QUATER':
                railway=list(railwayLocationMaster.objects.filter(location_type_desc='HEAD QUATER').values('location_code').distinct('location_code'))
            elif railwaytype=='PRODUCTION UNIT':
                railway=list(railwayLocationMaster.objects.filter(location_type_desc='PRODUCTION UNIT').values('location_code').distinct('location_code'))
            elif railwaytype=='INSTITUTE':
                railway=list(railwayLocationMaster.objects.filter(location_type_desc='INSTITUTE').values('location_code').distinct('location_code'))
            elif(railwaytype=='DIVISION' or railwaytype=='WORKSHOP' or railwaytype=='STORE' or railwaytype=='CONSTRUCTION'):
                railwa=railwayLocationMaster.objects.filter(Q(location_type_desc='DIVISION')|Q(location_type_desc='WORKSHOP')|Q(location_type_desc='STORE')|Q(location_type_desc='CONSTRUCTION')).values('parent_location_code').distinct('parent_location_code')
                railway=[]
                for i in railwa:
                    railway.append({'location_code': i['parent_location_code']})
                # railway_val=request.GET.get('rly')
                # print(railway_val)
                # division=list(railwayLocationMaster.objects.filter(Q(location_type_desc='DIVISION')|Q(location_type_desc='WORKSHOP')|Q(location_type_desc='STORE')|Q(location_type_desc='CONSTRUCTION')).values('location_code').distinct('location_code'))
                # division=list(railwayLocationMaster.objects.filter(parent_location_code=railway_val).values('location_code').distinct('location_code'))
            else:
                railway=[]
            context={
                'railway':railway,
                # 'division':division,
            }
            return JsonResponse(context, safe = False)  
        elif op=="cal_desig":
            post=request.GET.get('post')
            desig=list(MED_LVLDESG.objects.filter(MAVDESG__startswith = post).values())
            context={
                'desig':desig,
                'len':len(desig),
            }
            return JsonResponse(context, safe = False)
        elif op=="details_desig":
            id = request.GET.get('_id')
            id = id.split('@')
            if id[0] == 'Enable':
                MED_LVLDESG.objects.filter(MAADESGCODE = id[1]).update( MABDELTFLAG = False)
                msg = 'Designation Enabled Successfully'
            else:
                MED_LVLDESG.objects.filter(MAADESGCODE = id[1]).update( MABDELTFLAG = True)
                msg = 'Designation Disabled Successfully'
            
            return JsonResponse(msg, safe = False)
        elif op=="post_bydept":
            dept1 = request.GET.get('dept1')
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=dept1)[0].MACDEPTCODE
            post=list(Post_master.objects.filter(department_code_id=dept_id).values('post_desc').distinct('post_desc'))
            context={
                'post':post,
            }
            return JsonResponse(context, safe = False)
        return JsonResponse({"success":False}, status=400)
    elif request.method == 'POST' or request.is_ajax():
        user_rly_id = request.user.MAV_rlycode_id
        op=request.POST.get('op')
        if op=="add_postajax":
            post_type=request.POST.get('post_type')
            if post_type == 'PostCode':
                postcode=request.POST.get('postcode')
                if Post_master.objects.filter(post_code=postcode).exists():
                    msg = 'Exists'
                else:
                    msg = 'Success'
                return JsonResponse(msg,safe=False)
            if post_type == 'station':
                rly_unit_id=request.POST.get('val')
                rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
                rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
                rep_officer = list(Level_Desig.objects.filter(Q(rly_unit = rly_unit_id) | Q(rly_unit__in = rly_unit_det)).values('designation'))
                rep_officer = list(map( lambda x: x['designation'],rep_officer))
                all_station = list(station_master.objects.filter(Q(rly_id_id = rly_unit_id) | Q(div_id_id = rly_unit_id)).values('station_name').distinct().order_by('station_name'))
                context = {
                    'rep_officer':rep_officer,
                    'all_station':all_station,
                }
                return JsonResponse(context,safe=False)
            
            if post_type == 'checkRlyType':
                rly = request.POST.get('rly')
                post = request.POST.get('post')
                location_code = ''
                parent_location_code = ''
                location_type_desc = ''
                createdDesignation = post
                context = list(railwayLocationMaster.objects.filter(rly_unit_code=rly).values('location_code','parent_location_code','location_type_desc'))
                if len(context) > 0:
                    location_code = context[0]['location_code']
                    parent_location_code = context[0]['parent_location_code']
                    location_type_desc = context[0]['location_type_desc']
                if location_type_desc in ['RAILWAY BOARD', 'PRODUCTION UNIT', 'HEAD QUATER', 'PSU', 'INSTITUTE']:
                    createdDesignation = createdDesignation + '/' + location_code
                else:
                    if post != 'DRM':
                        createdDesignation = createdDesignation + '/' + location_code + '/' + parent_location_code
                    else:
                        createdDesignation = createdDesignation + '/' + location_code

                context = {
                    'createdDesignation' : createdDesignation,
                    
                }
                
                return JsonResponse(context, safe = False)
        elif op=="add_post":
            
            actual_user = request.user
            rly_unit_id = user_rly_id
            cuser = actual_user
            postname=request.POST.get('postname')
            postcode=request.POST.get('postcode')
            depart1=request.POST.get('depart1')
            category=request.POST.get('category')
            pc7_levelmax=request.POST.get('pc7_levelmax')
            pc7_levelmin=request.POST.get('pc7_levelmin')
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=depart1)[0].MACDEPTCODE
            if Post_master.objects.all().exists():
                id=Post_master.objects.all().last().post_id
            else:
                id=0
            Post_master.objects.create(post_id=id+1,modified_by=cuser,post_code=postcode,post_desc=postname,department_code_id=dept_id,category=category,pc7_levelmax=pc7_levelmax,pc7_levelmin=pc7_levelmin)
            # messages.success(request,'Data saved successfully') 
            messages.success(request,'Post added successfully as : '+postname)  
            return JsonResponse('Post added successfully as : '+postname, safe=False) 
        elif op=="save_designation":
            post = request.POST.get('post')
            designation = request.POST.get('designation')
            contact = request.POST.get('contact')
            email = request.POST.get('email')  
            pre_reporting_officer = request.POST.get('reporting_officer')
            station = request.POST.get('station')
            rly = request.POST.get('rly')
            div_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=rly,location_type_desc__in=rlyhead.objects.filter(rltype='HQ').values('rllongdesc')).values('parent_rly_unit_code','location_type'))
            if len(div_id_id) > 0:
                hq_id_id = rly
                div_id_id = None
            else:
                hq_id_id=list(railwayLocationMaster.objects.filter(rly_unit_code=rly).values('parent_rly_unit_code','location_type'))
                
                if hq_id_id[0]['location_type'] in ['DIV','WS']:
                    div_id_id = rly
                else:
                    div_id_id = None
                hq_id_id = hq_id_id[0]['parent_rly_unit_code']

            if pre_reporting_officer is not None or pre_reporting_officer != '':
                reporting_officer = list(MED_LVLDESG.objects.filter(MAVDESG = pre_reporting_officer).values('MAADESGCODE'))
                if len(reporting_officer) > 0:
                    pre_reporting_officer = reporting_officer[0]['MAADESGCODE']
                else:
                    pre_reporting_officer = None
            else:
                    pre_reporting_officer = None
            
            actual_user = request.user
            cuser = request.user
            
            
            if post != '':
                dept_id = list(Post_master.objects.filter(post_code=post).values())
                if len(dept_id) > 0:
                    category = dept_id[0]['category']
                    paylevel_max = dept_id[0]['pc7_levelmax']
                    paylevel_min = dept_id[0]['pc7_levelmin']
                    hierarchy_level = Category.objects.filter(category=category).values('hierarchy_level')[0]['hierarchy_level']
                    dept_id = dept_id[0]['department_code_id']

                    if dept_id != '' and dept_id != None:
                        department = MEM_DEPTMSTN.objects.filter(MACDEPTCODE=dept_id).values('MAVDEPTNAME')[0]['MAVDEPTNAME']
                    else:
                        department = None
            else:
                category =None
                paylevel_max=None
                paylevel_min=None
                dept_id=None
                department = None

            if category == 'CRB':
                role = 'CRB'
            else:
                role = 'user'
            if email == '':
                email=None
                msg  = 'Email Address Required'
            if contact == '':
                contact=None
                msg  = 'Success'
            msg_1 = ''  
           
            if MED_LVLDESG.objects.filter(MAVDESG = designation).exists():
                msg =  'Designation already present'
            elif MED_LVLDESG.objects.filter(MAVOFCLMAILID = email).exists():
                msg =  'Email Id already present'
            elif MED_LVLDESG.objects.filter(MAVCONTNUM = contact).exists():
                
                msg =  'Contact number already present'
            elif email != None:
                id = list(MED_LVLDESG.objects.values('MAADESGCODE').order_by('-MAADESGCODE'))
                if len(id)>0:
                    id = id[0]['MAADESGCODE'] + 1
                else:
                    id = 1

                
                
                MED_LVLDESG.objects.create(MAADESGCODE = id,hq_id_id=hq_id_id,div_id_id=div_id_id,MAVUSERROLE = role,
                                           MAVSTTS='P',MAIRLYUNIT_id=rly,MAVPARDESGCODE=pre_reporting_officer,
                                           MAVSTTNNAME=station,MAVMDFDBY=cuser,MAIPCLVLMAX=paylevel_max,
                                           MAIPC7LVLMIN=paylevel_min,MAVDLVL=category,MAVDEPT=department,
                                           MAVDESG = designation,MAVDEPTCODE_id=dept_id,MAVCONTNUM=contact,
                                           MAVOFCLMAILID=email)
                
                msg = 'Success'            
            
            return JsonResponse({'msg':msg,'msg_1':msg_1}, safe = False)
        elif op=="shop_data":
            dept = request.POST.get('dept')
            shop = request.POST.get('shop')
            print(',,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,,',dept)
            print(shop)
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=dept)[0].department_code
            print(dept_id)
            count=1
            shopcode=Shop_section.objects.filter(department_code_id=dept_id).distinct('shop_id')
            # shopcode=list(shop_section.objects.filter(department_code_id=dept_id).distinct('shop_code')).last()
            print(shopcode)
            shopcode=shopcode.count()
            shopcode+=1
            print(shopcode,"+++++++++")
            c = ('%02d' % shopcode)
            shopcode1=c
            shop_id=str(120)+str(dept_id)+str(shopcode1)
            print(shop_id)
            section_id=shop_id+'00'
            print(section_id)
            section_code=int(section_id[5:9])
            print(section_code,'--------------__________--------------------')
            Shop_section.objects.create(department_code_id=dept_id,shop_code=shop,shop_id=shop_id,section_id=section_id,section_code=section_code)
            messages.success(request,'Data saved successfully')
            return JsonResponse({'saved':'save'})
        elif op=="dept_data":
            department = request.POST.get('department')
            obj=list(MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=department).values('MAVDEPTNAME').distinct())
            sc_1=int(MEM_DEPTMSTN.objects.last().MACDEPTCODE)
            if len(obj)==0:
                print('a')
                MEM_DEPTMSTN.objects.create(MAVDEPTNAME=department, MACDEPTCODE=sc_1+1)
                messages.success(request,'Data saved successfully')
            else:
                messages.error(request,'Department Already Exists!')
                print('b')
            return JsonResponse({'saved':'save'})
        elif op=='section_data':
            dept1 = request.POST.get('dept1')
            #print(dept1)
            sectiondept = request.POST.get('sectiondept')
            #print(sectiondept)
            sec = request.POST.get('sec')
            #print(sec)
            dept_id=MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=dept1)[0].MACDEPTCODE
            #print(dept_id)
            if Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).exists():
                shopcode=Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).last().section_id
            #print(shopcode,'shopcode------')
            if Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).exists():
                shopcode_id=Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).last().shop_id
            #print(shopcode_id,'shopcode_id------')

            if Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).exists():

                section_code=Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).last().section_code
            #print(section_code,'section_code------')
            
            shop_id=int(shopcode)+1
            sec_code=int(section_code)+1
            if Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).exists():

                Shop_section.objects.filter(department_code_id=dept_id,shop_code=sectiondept).create(section_id=shop_id,section_desc=sec,shop_code=sectiondept,department_code_id=dept_id,shop_id=shopcode_id,section_code=sec_code)
                messages.success(request,'Data saved successfully')
            
                
            return JsonResponse({'saved':'save'})
        return JsonResponse({"success":False},status=400)
    elif request.method == "GET":
        user_rly_id = request.user.MAV_rlycode_id
        unit=MEM_DEPTMSTN.objects.filter(MABDELTFLAG=False).values('MAVDEPTNAME').order_by('MAVDEPTNAME').distinct('MAVDEPTNAME')
        cat=Category.objects.all().values('category').order_by('category').distinct('category')
        post=Post_master.objects.filter(~Q(post_code=None),Q(delete_flag=False)).values('post_code').order_by('post_code').distinct('post_code')
        rltype=railwayLocationMaster.objects.filter(~Q(location_type_desc=None)).values('location_type_desc').order_by('location_type_desc').distinct('location_type_desc')
        if request.user.MAV_userlvlcode_id in ['1', '2']: 
            datatable= MED_LVLDESG.objects.all()
            all_railway = list(railwayLocationMaster.objects.filter(location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))
        else:
            
            all_railway = list(railwayLocationMaster.objects.filter((Q(rly_unit_code = user_rly_id)|Q(parent_rly_unit_code = str(user_rly_id))),location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))
            datatable= MED_LVLDESG.objects.filter(MAIRLYUNIT__in = [i['rly_unit_code'] for i in all_railway]).all()

        level = ['8','9','10','11','12','13','14','15','16','17','18']
        context={
            'unit':unit,
            'post':post,
            'cat':cat,
            'all_railway':all_railway,
            'rltype':rltype,
            'datatable':datatable,
            'level':level,
            # 'railway':railway,
            # 'division':division,
        }
        
        return render(request,'add_designation.html', context)

from django.db.models import F
def addPostAjax(request):
    if request.method == 'POST' or request.is_ajax():
        post_type=request.POST.get('post_type')
        if post_type == 'PostCode':
            postcode=request.POST.get('postcode')
            if Post_master.objects.filter(post_code=postcode).exists():
                msg = 'Exists'
            else:
                msg = 'Success'
            return JsonResponse(msg,safe=False)
        if post_type == 'station':
            rly_unit_id=request.POST.get('val')
            rly_unit_det=list(railwayLocationMaster.objects.filter( rly_unit_code= rly_unit_id).values('parent_rly_unit_code'))
            rly_unit_det = list(map( lambda x: int(x['parent_rly_unit_code']),rly_unit_det))
            
            rep_officer = list(MED_LVLDESG.objects.filter(Q(MAIRLYUNIT = rly_unit_id) | Q(MAIRLYUNIT__in = rly_unit_det)).annotate(designation = F('MAVDESG')).values('designation'))
            
            rep_officer = list(map( lambda x: x['designation'],rep_officer))
            all_station = list(station_master.objects.filter(Q(rly_id_id = rly_unit_id) | Q(div_id_id = rly_unit_id)).values('station_name').distinct().order_by('station_name'))
            context = {
                'rep_officer':rep_officer,
                'all_station':all_station,
            }
            return JsonResponse(context,safe=False)
        if post_type == 'checkRlyType':
            rly = request.POST.get('rly')
            post = request.POST.get('post')
            location_code = ''
            parent_location_code = ''
            location_type_desc = ''
            createdDesignation = post
            context = list(railwayLocationMaster.objects.filter(rly_unit_code=rly).values('location_code','parent_location_code','location_type_desc'))
            if len(context) > 0:
                location_code = context[0]['location_code']
                parent_location_code = context[0]['parent_location_code']
                location_type_desc = context[0]['location_type_desc']
            if location_type_desc in ['RAILWAY BOARD', 'PRODUCTION UNIT', 'HEAD QUATER', 'PSU', 'INSTITUTE']:
                createdDesignation = createdDesignation + '/' + location_code
            else:
                if post != 'DRM':
                    createdDesignation = createdDesignation + '/' + location_code + '/' + parent_location_code
                else:
                    createdDesignation = createdDesignation + '/' + location_code

            context = {
                'createdDesignation' : createdDesignation,
            }
            return JsonResponse(context, safe = False)
    return JsonResponse({"success":False},status=400)

#department master 
def submit_department(request):
    if request.method == "GET" and request.is_ajax():
        op = request.GET.get('op')
        if op=="checkdept":
            val = request.GET.get('val')
            a=list(MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=val).values())
            if len(a)==0:
                data='1'
            else:
                data='2'
            return JsonResponse({'success':True,'data':data}, safe=False) 
        if op=="checksdept":
            val = request.GET.get('val')
            a=list(MEM_DEPTMSTN.objects.filter(MAVDEPT=val).values())
            if len(a)==0:
                data='1'
            else:
                data='2'
            return JsonResponse({'success':True,'data':data}, safe=False) 
        return JsonResponse({'success':True}, safe=False) 
    obj = MEM_DEPTMSTN.objects.all().order_by(Cast('MACDEPTCODE', IntegerField()))
    deptcode = MEM_DEPTMSTN.objects.aggregate(max_value=Max(Cast('MACDEPTCODE', IntegerField())))['max_value']
    return render(request, "submit_department.html", {'obj':obj,'deptcode':deptcode+1})

def save(request):
    if request.method == "GET":
       flag=request.GET.get('deptn')
    department_name= MEM_DEPTMSTN.objects.filter(MAVDEPTNAME=flag).exists()
    return JsonResponse( {'deptname': department_name})

def savee(request):
    if request.method == "GET" and request.is_ajax():
        dc = request.GET.get('dc')
        dn = request.GET.get('dn')
        dsn = request.GET.get('dsn')
        if MEM_DEPTMSTN.objects.filter(MACDEPTCODE=dc).exists():
            return JsonResponse({'success': False, 'deptname': True}, safe=False)
        MEM_DEPTMSTN.objects.create(MACDEPTCODE = dc,MAVDEPTNAME = dn,MAVDEPT = dsn,MAIRLYUNITCODEID=1, MAVMDFDBY = request.user)
        data=int(dc)+1
        return JsonResponse({'success':True,'data':data}, safe=False)
    return JsonResponse({'success':False}, safe=False)  

def deletee(request):
    if request.method == "GET" and request.is_ajax():
        DepartmentCode = request.GET.get('department_code')
        key = request.GET.get('key')
        if key =="disable":
            MEM_DEPTMSTN.objects.filter(MACDEPTCODE = DepartmentCode ).update(MABDELTFLAG = True)
            data='1'
        else:
            MEM_DEPTMSTN.objects.filter(MACDEPTCODE = DepartmentCode ).update(MABDELTFLAG = False)
            data='2'
        return JsonResponse({"success":True,'data':data},safe=False)
    return JsonResponse({"success":False},safe=False)

def updatedata(request):
    if request.method == "GET" and request.is_ajax():
        DepartmentCode = request.GET.get('dcode')
        DepartmentName = request.GET.get('dname')
        DepartmentshrtName = request.GET.get('dsname')
        MEM_DEPTMSTN.objects.filter(MACDEPTCODE=DepartmentCode).update(MAVDEPTNAME = DepartmentName,MAVDEPT = DepartmentshrtName, MAVMDFDBY = request.user)
        return JsonResponse({'success':True}, safe=False) 
    return JsonResponse({'success':False}, safe=False)  


###  divisionHQ
def showdivhq(request):
    if request.method == 'GET' and request.is_ajax():
        id = request.GET.get('_id')
        id = id.split('@')
        if id[0] == 'Enable':
            MED_dvsnmstn.objects.filter(MAV_dvsncode = id[1]).update(MAC_flag = True)
            msg = 'Enabled Successfully'
        else:
            MED_dvsnmstn.objects.filter(MAV_dvsncode = id[1]).update(MAC_flag = False)
            msg = 'Disabled Successfully'
            
        return JsonResponse(msg,safe = False)
        
    if request.method == 'POST'  and request.is_ajax():
        rlycode = request.POST.get('rlycode')
        from datetime import datetime
        current_time_date = datetime.now()
        if not MED_dvsnmstn.objects.filter(MAV_railcode = rlycode).exists():
            MED_dvsnmstn.objects.create(
                        MAV_railcode_id = rlycode,
                        MAV_railtype = list(railwayLocationMaster.objects.filter(rly_unit_code = rlycode).values())[0]['location_type'],
                        MAD_datetimecrtn = current_time_date,
                        MAC_flag = True
                    )
            msg = 'Location Added Successfully'
        else:
            msg = 'Location Already Present.'
        return JsonResponse(msg,safe = False)
    
    railway_code = request.user.MAV_rlycode_id
    if request.user.MAV_userlvlcode_id in ['1', '2']: 
        obj1 = MED_dvsnmstn.objects.all().order_by('-MAV_dvsncode')
        all_railway = list(railwayLocationMaster.objects.exclude(rly_unit_code__in = MED_dvsnmstn.objects.values('MAV_railcode')).filter(location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))

    else:
        lst = [railway_code]
        lst = getAllChildIdList(lst,railway_code)
        obj1 = MED_dvsnmstn.objects.filter(MAV_railcode__in = lst).all().order_by('-MAV_dvsncode')
        all_railway = list(railwayLocationMaster.objects.exclude(rly_unit_code__in = MED_dvsnmstn.objects.values('MAV_railcode')).filter(rly_unit_code__in = lst, location_type__in =['RDSO','WS','DIV','RB','ZR','PSU','CTI','PU']).values('rly_unit_code','location_description','location_code','location_type').distinct().order_by('location_code'))

    
    divname = []
    railways = []
    for i in obj1:
        if i.MAV_railtype not in divname:
            divname.append(i.MAV_railtype)
        if i.MAV_railcode.location_code not in railways:
            railways.append(i.MAV_railcode.location_code)
    divname.sort()
    railways.sort()



    context={
        'all_railway':all_railway,
        'obj1':obj1,
        'divname':divname,
        'railways':railways,
     }
    return render(request,'showdivhq.html',context)


#-----------------------------------views for user info-------------------------------------

def remove_hrms_id(request):
    if request.is_ajax():
        id = request.user.MAV_userid
        MEM_usersn.objects.filter(MAV_userid = id).update(hrms = None)
        return JsonResponse({'success':True}, safe=False)

    return JsonResponse({'success':False}, status = 400)

def user_personalinfo(request):
    if request.method == 'GET' and request.is_ajax():
        user_rly_id = request.user.MAV_rlycode.rly_unit_code
        int_data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode = user_rly_id).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
        try:
            parent_rly = [int(list(railwayLocationMaster.objects.filter(rly_unit_code = user_rly_id).values('parent_rly_unit_code'))[0]['parent_rly_unit_code'])]
        except:
            parent_rly = [0]
        child_rly = list(railwayLocationMaster.objects.filter(parent_rly_unit_code = user_rly_id).values_list('rly_unit_code'))
        child_rly = [0]
        if len(child_rly) > 0:
            parent_rly.extend(child_rly)
        ext_data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode__in = parent_rly).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
        w_type = list(workflow_type.objects.filter().values('type_id','type_name'))
        context = {

            'int_data':int_data,
            'ext_data':ext_data,
            'w_type':w_type
        }
        return JsonResponse(context, safe=False)

    if request.method == 'POST' and request.is_ajax():
        from datetime import datetime
        w_type = json.loads(request.POST.get('w_type'))
        int_officer = json.loads(request.POST.get('int_officer'))
        ext_officer = json.loads(request.POST.get('ext_officer'))
        all_type_id = []
        if len(w_type)>0:
            for i in w_type:
                all_type_id.append(i)
                internal_id = list(workflow_internal_forward.objects.filter(by_user = request.user.MAV_userid, type_id = int(i)).values_list('to_user', flat = True))
                external_id = list(workflow_external_forward.objects.filter(by_user = request.user.MAV_userid, type_id = int(i)).values_list('to_user', flat = True))
                int_off = int_officer.get(i, None)
                if int_off != None:
                    int_off = int_off.split(',')
                    for j in int_off:
                        try:
                            internal_id.remove(int(j))
                        except:
                            workflow_internal_forward.objects.create(by_user_id = request.user.MAV_userid, to_user_id = int(j),type_id_id = int(i))
                
                workflow_internal_forward.objects.filter(by_user = request.user.MAV_userid, type_id = int(i), to_user__in = internal_id).delete()
                
                int_off = ext_officer.get(i, None)
                if int_off != None:
                    int_off = int_off.split(',')
                    for j in int_off:
                        try:
                            external_id.remove(int(j))
                        except:
                            workflow_external_forward.objects.create(by_user_id = request.user.MAV_userid, to_user_id = int(j),type_id_id = int(i))
                
                
                workflow_external_forward.objects.filter(by_user = request.user.MAV_userid, type_id = int(i), to_user__in = external_id).delete()

        workflow_internal_forward.objects.exclude(type_id__in = all_type_id).filter(by_user = request.user.MAV_userid).delete()
        workflow_external_forward.objects.exclude(type_id__in = all_type_id).filter(by_user = request.user.MAV_userid).delete()

        username = request.POST.get('username')
        pre_chargetype = request.POST.get('charge')
        
        if pre_chargetype == '' or pre_chargetype == 'None':
            pre_chargetype = None
        
        unit = request.POST.get('unit')
        if unit == '':
            unit = None
        desig = request.POST.get('desig')
        
        mobileno = request.POST.get('mobileno')
        if mobileno == '':
            mobileno = None
        mailid = request.POST.get('mailid')
        if mailid == '':
            mailid = None
        user_id = request.POST.get('user_id')
        pre_email = mailid
        pre_contact = mobileno


        designation = desig

        cuser = request.user
        if MED_LVLDESG.objects.exclude(MAVOFCLMAILID = None).filter(~Q(MAVDESG = designation), MAVOFCLMAILID = pre_email).exists():
            msg = 'e-mail id is already used with another designation, Request cannot be processed' 

        elif pre_chargetype == 'P' and MED_LVLDESG.objects.exclude(MAVCONTNUM = None).filter(~Q(MAVDESG = designation), MAVCONTNUM = pre_contact, MAVSTTS = 'P').exists():
            msg = 'Contact number is already used with another designation, Request cannot be processed'        
        else:
            prevData = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values())
            designation_Change_Request.objects.create(request_by=cuser,request_date=datetime.now(),request_remarks='Self Changed',desigination=designation,status='Accepted',request_type='Modification',
                prev_charge = prevData[0]['MAVSTTS'],prev_parent_desig_code = prevData[0]['MAVPARDESGCODE'],prev_department_code_id=prevData[0]['MAVDEPTCODE_id'],prev_rly_unit_id=prevData[0]['MAIRLYUNIT_id'],prev_contactnumber=prevData[0]['MAVCONTNUM'],prev_official_email_ID=prevData[0]['MAVOFCLMAILID'],prev_station_name=prevData[0]['MAVSTTNNAME'],prev_maxlevel=prevData[0]['MAIPC7LVLMIN'],prev_minlevel=prevData[0]['MAIPCLVLMAX'],
                forward_to_officer = None,
                current_charge = pre_chargetype,
                current_contactnumber=pre_contact,current_official_email_ID=pre_email
                )
            
            MED_LVLDESG.objects.filter(MAVDESG = designation).update(
                MAVMDFDBY=str(cuser),MAVSTTS = pre_chargetype,MAVCONTNUM=pre_contact,MAVOFCLMAILID=pre_email
                )
            
            
            emp_details = list(MED_LVLDESG.objects.filter(MAVDESG = designation).values('MAIRLYUNIT_id','MAVDEPTCODE_id','MAVDLVL','MAVDESG','MAIRLYUNIT_id__location_code','MAIRLYUNIT_id__location_type','MAVEMPNUM','MAIPC7LVLMIN','MAIPCLVLMAX','MAVCONTNUM','MAVOFCLMAILID','MAVDEPTCODE_id__MAVDEPTNAME','MAVSTTNNAME','MAVPARDESGCODE','MAVSTTS').order_by('-MAVSTTS','MAVDESG'))
            if emp_details[0]['MAIRLYUNIT_id__location_type'] == 'RB':
                railway = ''
                division = ''
                other = ''
            elif list(rlyhead.objects.filter(rlshortcode = emp_details[0]['MAIRLYUNIT_id__location_type']).values('rltype'))[0]['rltype'] == 'HQ':
                railway = emp_details[0]['MAIRLYUNIT_id']
                division = ''
                other = ''
            elif list(rlyhead.objects.filter(rlshortcode = emp_details[0]['MAIRLYUNIT_id__location_type']).values('rltype'))[0]['rltype'] == 'DIV':
                railway = list(railwayLocationMaster.objects.filter(rly_unit_code = emp_details[0]['MAIRLYUNIT_id']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
                division = emp_details[0]['MAIRLYUNIT_id']
                other = ''
            else:
                division = list(railwayLocationMaster.objects.filter(rly_unit_code = emp_details[0]['MAIRLYUNIT_id']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
                other = emp_details[0]['MAIRLYUNIT_id']
                railway = list(railwayLocationMaster.objects.filter(rly_unit_code = division).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']

            
            if railway == '':
                rly_unit_code = list(railwayLocationMaster.objects.filter(location_type = 'RB', location_code = 'RB').values('rly_unit_code'))[0]['rly_unit_code']
                railway = rly_unit_code
                co_div = rly_unit_code
                co_type = 'RB'
            elif division == '':
                railway = railway
                co_div = railway
                co_type = 'HQ'
            elif other == '':
                railway = division
                co_div = division
                co_type = 'DIV'
            else:
                railway = other
                co_div = division
                co_type = 'DIV'
            
            user_type = request.POST.get('userlevel11')
            if user_type == '':
                user_type = None
            willsubmitto = request.POST.get('submitted_to')
            if willsubmitto == '':
                willsubmitto = None
            financeassociate = request.POST.get('acc_associate')
            if financeassociate == '':
                financeassociate = None
            hrms_id = request.POST.get('hrms')
            if hrms_id == '':
                hrms_id = None
                
            remarks = 'Self Updated'
            
            if MEM_usersn.objects.filter(hrms = hrms_id).exists():
                MEM_usersn.objects.filter(hrms = hrms_id).update(hrms = None)
            co_id  = list(MED_userlvls.objects.filter(nodel_flag = True).values_list('MAV_userlvlcode', flat = True))
            if hrms_id == '':
                hrms_id = None
            coordinator = False
            if user_type in co_id:
                coordinator = True
            if coordinator == True and MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).exists():
                MEM_usersn.objects.filter(coordinator = True, MAV_divcode__in = MED_dvsnmstn.objects.filter(MAV_railcode_id = co_div).values('MAV_dvsncode')).update(coordinator = False, MAV_userlvlcode = None)
            
            current_time_date = datetime.now()
            
            if not MED_dvsnmstn.objects.filter(MAV_railcode = co_div, MAC_flag = True).exists():
                MED_dvsnmstn.objects.create(
                        MAV_railcode_id = co_div,
                        MAV_railtype = co_type,
                        MAD_datetimecrtn = current_time_date,
                        MAC_flag = True
                    )
            
            prev_data = list(MEM_usersn.objects.filter(MAV_userdesig = designation).values())
            if unit != None:
                rl_id = unit
            else:
                rl_id = prev_data[0]['MAV_rlycode_id']
            MEM_usersn.objects.filter(MAV_userdesig=designation).update(
                MAV_crtdby = str(request.user),
                last_update = current_time_date,
                MAV_rprtto_id = willsubmitto,
                MAV_finid_id = financeassociate,
                hrms = hrms_id,
                MAV_rlycode_id = rl_id
                
            )
            h = MEM_usersn.objects.filter(MAV_userdesig=designation).get()
            MEM_usersn_history.objects.create(
                
                MAV_crtdby = request.user,
                MAD_datetimecrtn = current_time_date,
                MAV_rprtto = willsubmitto,
                MAV_finid = financeassociate,
                hrms = hrms_id,
                MAV_rlycode= rl_id,
                
                datetimecrtn = current_time_date,

                prev_username = prev_data[0]['MAV_username'],
                prev_designation_id = prev_data[0]['designation_id_id'],
                prev_userdesig = prev_data[0]['MAV_userdesig'],
                prev_rlycode = prev_data[0]['MAV_rlycode_id'],
                prev_divcode = prev_data[0]['MAV_divcode_id'],
                prev_userlvlcode = prev_data[0]['MAV_userlvlcode_id'],
                prev_crtdby = prev_data[0]['MAV_crtdby'],
                prev_deptcode = prev_data[0]['MAV_deptcode_id'],
                prev_datetimecrtn = prev_data[0]['MAD_datetimecrtn'],
                prev_rprtto = prev_data[0]['MAV_rprtto_id'],
                prev_finid = prev_data[0]['MAV_finid_id'],
                prev_hrms = prev_data[0]['hrms'],
                prev_coordinator = prev_data[0]['coordinator'],
                type = 'Update',
                remarks = remarks
            )
            if coordinator == True:
                MED_dvsnmstn.objects.filter(MAV_railcode = co_div, MAC_flag = True).update(MAC_user_id = h)
            msg = 'Updated Successfully.'
        
        return JsonResponse(msg, safe=False)

            
    if request.method == 'POST':
        submitValue = request.POST['submit']
        if submitValue == 'Link HRMS id':
            from datetime import datetime
            current_time_date = datetime.now()
            user_id = request.POST['user_id']
            hrms = request.POST['hrms']
            prev_data = list(MEM_usersn.objects.filter(MAV_userid = user_id).values())

            MEM_usersn.objects.filter(MAV_userid=user_id).update(
                MAV_crtdby = str(request.user),
                last_update = current_time_date,
                hrms = hrms,
                is_active = True
            )
            MEM_usersn_history.objects.create(
                MAV_crtdby = request.user,
                MAD_datetimecrtn = current_time_date,
                hrms = hrms,
                datetimecrtn = current_time_date,

                prev_username = prev_data[0]['MAV_username'],
                prev_designation_id = prev_data[0]['designation_id_id'],
                prev_userdesig = prev_data[0]['MAV_userdesig'],
                prev_rlycode = prev_data[0]['MAV_rlycode_id'],
                prev_divcode = prev_data[0]['MAV_divcode_id'],
                prev_userlvlcode = prev_data[0]['MAV_userlvlcode_id'],
                prev_crtdby = prev_data[0]['MAV_crtdby'],
                prev_deptcode = prev_data[0]['MAV_deptcode_id'],
                prev_datetimecrtn = prev_data[0]['MAD_datetimecrtn'],
                prev_rprtto = prev_data[0]['MAV_rprtto_id'],
                prev_finid = prev_data[0]['MAV_finid_id'],
                prev_hrms = prev_data[0]['hrms'],
                prev_coordinator = prev_data[0]['coordinator'],
                type = 'Update',
                remarks = 'Self Added'
            )


    current_user = request.user
    obj2 = MEM_usersn.objects.filter(MAV_username = current_user).values(
        'MAV_username', 'hrms', 'MAV_userdesig', 'MAV_deptcode', 'MAV_rlycode',  'MAV_userlvlcode', "MAV_deptcode__MAVDEPTNAME",
        'MAV_rprtto', 'MAV_finid', 'MAV_userdesig',  'MAV_userid', "MAV_mail", "MAV_ph", "coordinator", "MAV_userlvlcode__MAV_userlvlname", "MAV_userlvlcode__admin_flag",
        "MAV_rlycode__location_type", "MAV_rlycode__location_code"
        ).first()
    other_location = []
    other_chk = 'NO'
    coordinator = 'NO'
    if obj2['MAV_rlycode__location_type'] == 'RB':
        railway = 'RB'
        division = ''
        other = ''
        submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = railwayLocationMaster.objects.filter(location_type='RB').values('rly_unit_code'), MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(i for i in submit_proposal_to if i['MAV_deptcode'] == '1')
    elif list(rlyhead.objects.filter(rlshortcode = obj2['MAV_rlycode__location_type']).values('rltype'))[0]['rltype'] == 'HQ':
        lst = []
        railway = obj2['MAV_rlycode']
        all_rly_inc_p = [str(railway)]
        all_parent_id = getAllParentIdList(lst,railway)
        all_rly_inc_p.extend(all_parent_id)
        submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = railway, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
        railway = obj2['MAV_rlycode__location_code']
        division = ''
        other = ''
    elif list(rlyhead.objects.filter(rlshortcode = obj2['MAV_rlycode__location_type']).values('rltype'))[0]['rltype'] == 'DIV':
        railway = list(railwayLocationMaster.objects.filter(rly_unit_code = obj2['MAV_rlycode']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
        railway = list(railwayLocationMaster.objects.filter(rly_unit_code = railway).values('location_code'))[0]['location_code']
        
        other = ''
        other_chk = 'YES'
        other_location = list(railwayLocationMaster.objects.filter(parent_rly_unit_code = obj2['MAV_rlycode'], delete_flag = False).values('location_code','rly_unit_code'))
        lst = []
        division = obj2['MAV_rlycode']
        all_rly_inc_p = [str(division)]
        all_parent_id = getAllParentIdList(lst,division)
        all_rly_inc_p.extend(all_parent_id)
        submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
        division = obj2['MAV_rlycode__location_code']
    else:
        division = list(railwayLocationMaster.objects.filter(rly_unit_code = obj2['MAV_rlycode']).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
        lst = []
        all_rly_inc_p = [str(division)]
        all_parent_id = getAllParentIdList(lst,division)
        all_rly_inc_p.extend(all_parent_id)
        submit_proposal_to = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id__in = all_rly_inc_p, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(MEM_usersn.objects.filter(designation_id__in = MED_LVLDESG.objects.filter(MAIRLYUNIT_id = division, MABDELTFLAG = False).values('MAADESGCODE')).values('MAV_userdesig','MAV_userid','MAV_deptcode'))
        finance_officer = list(i for i in finance_officer if i['MAV_deptcode'] == '1')
        other_location = list(railwayLocationMaster.objects.filter(parent_rly_unit_code = division, delete_flag = False).values('location_code','rly_unit_code'))

        other = obj2['MAV_rlycode__location_code']
        railway = list(railwayLocationMaster.objects.filter(rly_unit_code = division).values('parent_rly_unit_code'))[0]['parent_rly_unit_code']
        division = list(railwayLocationMaster.objects.filter(rly_unit_code = division).values('location_code'))[0]['location_code']
        railway = list(railwayLocationMaster.objects.filter(rly_unit_code = railway).values('location_code'))[0]['location_code']
        other_chk = 'YES'
    
    obj2['finance_officer'] = finance_officer
    obj2['submit_proposal_to'] = submit_proposal_to
    obj2['railway'] = railway
    obj2['division'] = division
    obj2['other'] = other
    obj2['other_location'] = other_location
    obj2['other_chk'] = other_chk
    name = ''
    desig = []
    is_admin = 'NO'
    if obj2:
        rlycode = obj2['MAV_rlycode']
        if obj2['MAV_userlvlcode__admin_flag'] == True and AdminMaster.objects.filter(user_id = str(obj2['MAV_userid']), status = 'Active').exists():
            is_admin = 'YES'
            obj2['other_chk'] = 'NO'
            data = list(AdminMaster.objects.filter(user_id = str(obj2['MAV_userid'])).values())
            name  = data[0]['emp_name']
            desig = {'MAVCONTNUM':data[0]['admin_phone'] if data[0]['admin_phone'] != None else ' - ', 'MAVOFCLMAILID':data[0]['admin_email'], 'MAVSTTS':'P'}

        else:
            if obj2["hrms"] == None:
                context = {
                    'obj2':obj2,
                    'hrms_modal':'YES'
                }
                return render(request, 'user_personalinfo.html', context)
            hrms_1 = HRMS.objects.filter(hrms_employee_id=obj2["hrms"]).values().first()
            insp_ofc_name_parts = []
            if hrms_1 and hrms_1['employee_first_name']:
                insp_ofc_name_parts.append(hrms_1['employee_first_name'])
            if hrms_1 and hrms_1['employee_middle_name']:
                insp_ofc_name_parts.append(hrms_1['employee_middle_name'])
            if hrms_1 and hrms_1['employee_last_name']:
                insp_ofc_name_parts.append(hrms_1['employee_last_name'])
            name  = " ".join(insp_ofc_name_parts) if insp_ofc_name_parts else name
            desig = MED_LVLDESG.objects.filter(MAVDESG = obj2["MAV_userdesig"]).values('MAIRLYUNIT_id','MAIRLYUNIT_id__location_type','MAIRLYUNIT_id__location_code','MAIRLYUNIT', 'MAVDEPT', 'MAVCONTNUM', 'MAVOFCLMAILID', 'MAVSTTS').first()
            if obj2['coordinator'] == True:
                coordinator = 'YES'
            
        obj2['name'] = name
    
    user_rly_id = request.user.MAV_rlycode.rly_unit_code
    int_data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode = user_rly_id).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
    try:
        parent_rly = [int(list(railwayLocationMaster.objects.filter(rly_unit_code = user_rly_id).values('parent_rly_unit_code'))[0]['parent_rly_unit_code'])]
    except:
        parent_rly = [0]
    child_rly = list(railwayLocationMaster.objects.filter(parent_rly_unit_code = user_rly_id).values_list('rly_unit_code'))
    child_rly = [0]
    if len(child_rly) > 0:
        parent_rly.extend(child_rly)
    ext_data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode__in = parent_rly).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
    
    all_workflow_type = workflow_type.objects.all().order_by('type_id')
    frd_list = []
    count = 0
    for i in all_workflow_type:
        type_id = i.type_id
        type_name = i.type_name
        int_lst = []
        int_str = ''
        ext_lst = []
        ext_str = ''
        int_frd = workflow_internal_forward.objects.filter(by_user = request.user.MAV_userid, type_id = int(type_id)).values('to_user','to_user_id__MAV_userdesig')
        ext_frd = workflow_external_forward.objects.filter(by_user = request.user.MAV_userid, type_id = int(type_id)).values('to_user','to_user_id__MAV_userdesig')
        for j in int_frd:
            int_lst.append(j['to_user'])
            if int_str != '':
                int_str += ', '
            int_str += j['to_user_id__MAV_userdesig']
        for j in ext_frd:
            ext_lst.append(j['to_user'])
            if ext_str != '':
                ext_str += ', '
            ext_str += j['to_user_id__MAV_userdesig']

        if int_frd or ext_frd:
            frd_list.append({
                'count':count,
                'type_id':type_id,
                'type_name':type_name,
                'int_id':int_lst,
                'int_desig':int_str,
                'ext_id':ext_lst,
                'ext_desig':ext_str
            })
            count += 1
    max_workflow_name = all_workflow_type.count()
    global_count = len(frd_list)
    context = {
        'is_admin':is_admin,
        'desig': desig,
        'obj2': obj2,
        'coordinator':coordinator,
        'other_chk':other_chk,
        'int_data':int_data,
        'ext_data':ext_data,
        'frd_list':frd_list,
        'global_count':global_count,
        'all_workflow_type':all_workflow_type,
        'max_workflow_name':max_workflow_name
    }

    return render(request, 'user_personalinfo.html', context)

def hrms_emp(request):
    if request.method == 'GET' or request.is_ajax():
        hrms = request.GET.get('hrms')
        details = HRMS.objects.filter(hrms_employee_id=hrms).values('employee_middle_name','employee_last_name','hrms_employee_id', 'employee_first_name', 'designation', 'ipas_employee_id').first()
        if details:  # Check if details exist
            insp_ofc_name_parts = []
            employee_first_name = ''
            if details and details['employee_first_name']:
                insp_ofc_name_parts.append(details['employee_first_name'])
            if details and details['employee_middle_name']:
                insp_ofc_name_parts.append(details['employee_middle_name'])
            if details and details['employee_last_name']:
                insp_ofc_name_parts.append(details['employee_last_name'])
            
            employee_first_name  = " ".join(insp_ofc_name_parts) if insp_ofc_name_parts else employee_first_name
            hrms_employee_id = details['hrms_employee_id']
            designation = details['designation']
            ipas_employee_id = details['ipas_employee_id']
            data = {
                'hrms_employee_id': hrms_employee_id,
                'employee_first_name': employee_first_name,
                'designation': designation,
                'ipas_employee_id': ipas_employee_id
            }
            return JsonResponse(data)
        else:
            return JsonResponse({'error': 'Employee not found'}, status=404)

def user_preference(request):
    cuser = request.user
    if request.method == 'POST':
        
        preference = request.POST.get('preference_value')
        preference_type = request.POST.get('preference_for')
        MEM_usersn.objects.filter(MAV_userid = cuser.MAV_userid).update(
            preference = preference,
            preference_type = preference_type
            )
        messages.success(request,"Preference Added Successfully.")
        
    
    user_preference = MEM_usersn.objects.filter(MAV_userid = cuser.MAV_userid).values('preference','preference_type').first()
    context = {
        'preference':user_preference['preference'],
        'preference_type':user_preference['preference_type'],
    }
    return render(request, 'user_preference.html', context)


def changePassword(request):
    user = request.user
    if request.method == "POST":
        current_password = request.POST.get('oldPassword').strip()
        new_password = request.POST.get('newPassword').strip()
        user = request.user
        current_password=decrypt(current_password)
        new_password=decrypt(new_password)
        user_obj = authenticate(request,  username=user, password=current_password)
        if user_obj is not None:
            user.set_password(new_password)
            user.save()
            messages.success(request, 'Password changed successfully.')
            return redirect('/')
        else:
            messages.error(request, 'Incorrect old password.')
            return redirect('changePassword')

    return render(request, 'changePassword.html')


##############  railway location 17-07-24


def railwayMaster(request):
    try:
        station = station_master.objects.values('stnshortcode','station_name').distinct()
        datatable=list(railwayLocationMaster.objects.filter(deleted_flag = False).values())
        context={
            'station':station,
            'datatable':datatable,
        }
        return render(request,'railwayMaster.html',context)  
    except Exception as e: 
        print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})


def savediv(request):
    try:
        if request.method == "GET":
            shortcode = request.GET.get('shortcode')
            description = request.GET.get('description')
            parentcode = request.GET.get('parentcode')
            station = request.GET.get('station')
            rlytype = request.GET.get('rlytype')
            rlyunit = request.GET.get('rlyunit')
            if station == '':
                station = None
            else:
                station = (station.split("-")[0])[:5]
            dict1 = {"Railwayunit":"Unit","DIRECTORATE":"DIR","DIVISION": "DIV", "OFFICE": "O","HEAD QUATER": "ZR", "PRODUCTION UNIT": "PU","PSU": "PSU","INSTITUTE": "CTI","WORKSHOP": "WS","RAILWAY BOARD": "RB"}
            ltype = None
           
            ltype = dict1.get(rlytype)
            if ltype == 'Unit':
                ltype = rlyunit
            pid = railwayLocationMaster.objects.filter(location_code = parentcode).values('rly_unit_code')
            id=railwayLocationMaster.objects.filter().order_by('-rly_unit_code')[0].rly_unit_code
            id += 1
            msg = 'Same Short Code cannot be added'
            o_id = '0'
            if not railwayLocationMaster.objects.filter(location_code=shortcode).exists():
                o_id = '1'
                try:
                    parent_rly_unit_code = str(railwayLocationMaster.objects.filter(location_code = parentcode).values('rly_unit_code').first()['rly_unit_code'])
                except:
                    parent_rly_unit_code = None
                railwayLocationMaster.objects.create(modified_by = str(request.user),parent_rly_unit_code = parent_rly_unit_code, station_code = station, location_type = ltype, rly_unit_code=id, location_code=shortcode,location_type_desc=rlytype,location_description=description,parent_location_code=parentcode,parent_id=pid)
                msg = 'Added Successfully'
            
            return JsonResponse({'id': o_id, 'msg': msg}, safe=False)
        return JsonResponse({'success': False}, status=400)
    except Exception as e:
        try:
            rm.error_Table.objects.create(fun_name="savediv",user_id=request.user,err_details=str(e))
        except:
            print("Internal Error!!!")
        return render(request, "errorspage.html", {})


def able_rlyorg(request):
    if request.method == "GET":
        rlytype=request.GET.get('rlytype')
        parent=[]
        unit=[]
        if rlytype == "DIRECTORATE":
            parent=[{'parent_location_code': 'PSU'}, {'parent_location_code': 'RB'}]
        elif rlytype == "Railwayunit":
            unit = list(Railwayunit.objects.values('Unit_description','Unit_shortcode'))
            parent = list(railwayLocationMaster.objects.filter(Q(location_type_desc='DIVISION')| Q(location_type_desc='OFFICE')| Q(location_type_desc='WORKSHOP')).values('parent_location_code').distinct())
        else:
            parent=list(railwayLocationMaster.objects.filter(location_type_desc=rlytype).values('parent_location_code').distinct())
       
        context={
            'parent':parent,
            'unit':unit,
        }
        return JsonResponse(context, safe=False)
    return JsonResponse({'success': False}, status=400)


def savehq(request):
    try:
        if request.method == "GET":
            shortcode1=request.GET.get('shortcode1')
            description1=request.GET.get('description1')
            station=request.GET.get('station1')
            rlytype=request.GET.get('rlytype')
            if station == '':
                station = None
            else:
                station = (station.split("-")[0])[:5]
            
            
            dict1 = {"Railwayunit":"Unit","DIRECTORATE":"DIR","DIVISION": "DIV", "OFFICE": "O","HEAD QUATER": "ZR", "PRODUCTION UNIT": "PU","PSU": "PSU","INSTITUTE": "CTI","WORKSHOP": "WS","RAILWAY BOARD": "RB"}
            ltype=None
            
            ltype = dict1.get(rlytype)
            
            id=railwayLocationMaster.objects.filter().order_by('-rly_unit_code')[0].rly_unit_code
            id+=1
            msg = 'Same Short Code cannot be added'
            o_id = '0'
            if not railwayLocationMaster.objects.filter(location_code=shortcode1).exists():
                o_id = '1'
                if ltype in ['RB','CTI','PU','PSU','ZR']:
                    parent_rly_unit_code = str(railwayLocationMaster.objects.filter(location_code = 'RB', location_type = 'RB').values('rly_unit_code').first()['rly_unit_code'])
                else:
                    parent_rly_unit_code = None
                railwayLocationMaster.objects.create(modified_by = str(request.user),parent_rly_unit_code = parent_rly_unit_code, station_code = station, location_type=ltype,rly_unit_code=id,location_code=shortcode1,location_type_desc=rlytype,location_description=description1,parent_location_code='RB',parent_id='153')
                msg = 'Added Successfully'
            return JsonResponse({'id': o_id, 'msg': msg}, safe=False)
        return JsonResponse({'success': False}, status=400)
    except Exception as e:
        try:
            rm.error_Table.objects.create(fun_name="savehq",user_id=request.user,err_details=str(e))
        except:
            print("Internal Error!!!")
        #messages.error(request, 'Error : '+str(e))
        return render(request, "errorspage.html", {})



def custom_filter(filter_func, iterable):
    if isinstance(iterable, (list, tuple)):    
        iterable = iter(iterable)
    
    class FilterIterator:

        def __iter__(self):
            return self
        
        def __next__(self):
            while True:
                item = next(iterable)
                if filter_func(item):
                    return item
    
    return FilterIterator()

########################  workflow start
def create_workflow_status(request):
    try:
        if request.method == 'POST':
            submit_val = request.POST.get('submit')
            if submit_val == 'Create/Update':
                id = request.POST.get('status_id')
                status_name = request.POST.get('status_name')
                status_desc = request.POST.get('status_desc')
                if id != '':
                    if workflow_status.objects.exclude(status_id = id).filter(status_name = status_name).exists():
                        messages.error(request, 'Status Name already present')
                    else:
                        workflow_status.objects.filter(status_id = id).update(status_name = status_name, status_desc = status_desc)
                        messages.success(request, 'Successfully Updated.')
                else:
                    if workflow_status.objects.filter(status_name = status_name).exists():
                        messages.error(request, 'Status Name already present')
                    else:
                        workflow_status.objects.create(status_name = status_name, status_desc = status_desc)
                        messages.success(request, 'Successfully Added.')

        status = workflow_status.objects.all().order_by('status_id')
        context = {
            'status':status,
        }
        return render(request,'workflow_status.html',context)  
    except Exception as e: 
        print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

def create_workflow_type(request):
    try:
        if request.method == 'POST':
            submit_val = request.POST.get('submit')
            if submit_val == 'Create/Update':
                id = request.POST.get('type_id')
                type_name = request.POST.get('type_name')
                type_desc = request.POST.get('type_desc')
                if id != '':
                    if workflow_type.objects.exclude(type_id = id).filter(type_name = type_name).exists():
                        messages.error(request, 'Workflow Type Name already present')
                    else:
                        workflow_type.objects.filter(type_id = id).update(type_name = type_name, type_desc = type_desc)
                        messages.success(request, 'Successfully Updated.')
                else:
                    if workflow_type.objects.filter(type_name = type_name).exists():
                        messages.error(request, 'Workflow Type Name already present')
                    else:
                        workflow_type.objects.create(type_name = type_name, type_desc = type_desc)
                        messages.success(request, 'Successfully Added.')

        status = workflow_type.objects.all().order_by('type_id')
        context = {
            'status':status,
        }
        return render(request,'workflow_type.html',context)  
    except Exception as e: 
        print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

def create_workflow_activity(request):
    try:
        if request.method == 'POST':
            submit_val = request.POST.get('submit')
            if submit_val == 'Create/Update':
                for_user = request.POST.getlist('for_user[]')
                for_user = ','.join(for_user)
                can_initiate = request.POST.get('can_initiate')
                if can_initiate == 'Yes':
                    can_initiate = True
                else:
                    can_initiate = False
                activity_name = request.POST.get('activity_name')
                module_name = request.POST.get('module_name')
                id = request.POST.get('activity_id')
                import datetime
                curr_date = datetime.datetime.now()
                
                if id != '':
                    workflow_activity.objects.filter(activity_name = activity_name).update(module_name = module_name, modified_on = curr_date, for_user = for_user, can_initiate = can_initiate, modified_by = request.user)
                    messages.success(request, 'Successfully Updated.')
                else:
                    if workflow_activity.objects.filter(activity_name = activity_name).exists():
                        messages.error(request, 'Activity Name already present')
                    else:
                        workflow_activity.objects.create(activity_name = activity_name, module_name = module_name, modified_on = curr_date, for_user = for_user, can_initiate = can_initiate, modified_by = request.user)
                        messages.success(request, 'Successfully Added.')
                    

        status = workflow_activity.objects.values().order_by('activity_name')
        for i in status:
            if i['can_initiate'] == True:
                can_initiate = 'Yes'
            else:
                can_initiate = 'No'
            for_u = i['for_user']
            if for_u == 'all':
                user = ['For All User']
            else:
                user = []
                for_u = for_u.split(',')
                for j in for_u:
                    val = list(MED_userlvls.objects.filter(MAV_userlvlcode = j).values('MAV_userlvlname'))
                    if len(val) > 0:
                        user.append(val[0]['MAV_userlvlname'])
            
            i.update({'user':user , 'can_initiate':can_initiate})
        userlvl = MED_userlvls.objects.filter(delete_flag = False).values('MAV_userlvlcode','MAV_userlvlname')

        context = {
            'status':status,
            'userlvl':userlvl,
            'lvl' : json.dumps(list(userlvl))
        }
        return render(request,'workflow_activity.html',context)  
    except Exception as e: 
        print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

def create_user_work_assigned(request):
    try:
        import datetime
        curr_date = datetime.datetime.now()
        if request.method == 'GET' and request.is_ajax():
            ajax_type = request.GET.get('ajax_type')
            if ajax_type == 'edit':
                id = request.GET.get('id')
                data = list(workflow_user_power.objects.filter(id = id).values())
                return JsonResponse(data,safe=False)
            if ajax_type == 'delete':
                id = request.GET.get('id')
                prev_data = list(workflow_user_power.objects.filter(id = id).values())
                workflow_user_power_history.objects.create(
                            user_flag = prev_data[0]['user_flag_id'], for_user = prev_data[0]['for_user_id'], 
                            approve = prev_data[0]['approve'], reject = prev_data[0]['reject'], intforward = prev_data[0]['intforward'], extforward = prev_data[0]['extforward'],
                            revert = prev_data[0]['revert'], finalize = prev_data[0]['finalize'], sanction = prev_data[0]['sanction'], vetting = prev_data[0]['vetting'], drafting = prev_data[0]['drafting'], 
                            comment = prev_data[0]['comment'], revise = prev_data[0]['revise'], modified_on = prev_data[0]['modified_on'], modified_by = prev_data[0]['modified_by_id'],
                            updated_on = curr_date, updated_by_id = request.user.MAV_userid
                        )
                workflow_user_power.objects.filter(id = id).delete()
                return JsonResponse('',safe=False)
            return JsonResponse({'success': False}, status=400)

        if request.method == 'POST':
            submit_val = request.POST.get('submit')
            if submit_val == 'Create/Update':
                #approve,reject,intforward,extforward,revert,finalize,sanction,vetting,drafting,comment,revise
                workflow_id = request.POST.get('workflow_type')
                user_id = request.POST.get('user_id')
                approve = True if request.POST.get('approve') else False
                reject = True if request.POST.get('reject') else False
                intforward = True if request.POST.get('intforward') else False
                extforward = True if request.POST.get('extforward') else False
                revert = True if request.POST.get('revert') else False
                finalize = True if request.POST.get('finalize') else False
                sanction = True if request.POST.get('sanction') else False
                vetting = True if request.POST.get('vetting') else False
                drafting = True if request.POST.get('drafting') else False
                comment = True if request.POST.get('comment') else False
                revise = True if request.POST.get('revise') else False
                
                if workflow_id != 'all':
                    if workflow_user_power.objects.filter(user_flag = workflow_id,for_user = user_id).exists():
                        prev_data = list(workflow_user_power.objects.filter(user_flag = workflow_id,for_user = user_id).values())

                        workflow_user_power.objects.filter(user_flag = workflow_id,for_user = user_id).update(
                            approve = approve, reject = reject, intforward = intforward, extforward = extforward,
                            revert = revert, finalize = finalize, sanction = sanction, vetting = vetting, drafting = drafting, 
                            comment = comment, revise = revise, modified_on = curr_date, modified_by_id = request.user.MAV_userid
                        )

                        workflow_user_power_history.objects.create(
                            user_flag = prev_data[0]['user_flag_id'], for_user = prev_data[0]['for_user_id'], 
                            approve = prev_data[0]['approve'], reject = prev_data[0]['reject'], intforward = prev_data[0]['intforward'], extforward = prev_data[0]['extforward'],
                            revert = prev_data[0]['revert'], finalize = prev_data[0]['finalize'], sanction = prev_data[0]['sanction'], vetting = prev_data[0]['vetting'], drafting = prev_data[0]['drafting'], 
                            comment = prev_data[0]['comment'], revise = prev_data[0]['revise'], modified_on = prev_data[0]['modified_on'], modified_by = prev_data[0]['modified_by_id'],
                            updated_on = curr_date, updated_by_id = request.user.MAV_userid
                        )
                        messages.success(request, 'Successfully Updated.')
                    else:
                        workflow_user_power.objects.create(user_flag_id = workflow_id, for_user_id = user_id,
                            approve = approve, reject = reject, intforward = intforward, extforward = extforward,
                            revert = revert, finalize = finalize, sanction = sanction, vetting = vetting, drafting = drafting, 
                            comment = comment, revise = revise, modified_on = curr_date, modified_by_id = request.user.MAV_userid
                        )
                        messages.success(request, 'Successfully Added.')
                else:
                    workflow = workflow_type.objects.all()
                    for i in workflow:
                        workflow_id = i.type_id
                        if workflow_user_power.objects.filter(user_flag = workflow_id,for_user = user_id).exists():
                            prev_data = list(workflow_user_power.objects.filter(user_flag = workflow_id,for_user = user_id).values())

                            workflow_user_power.objects.filter(user_flag = workflow_id,for_user = user_id).update(
                                approve = approve, reject = reject, intforward = intforward, extforward = extforward,
                                revert = revert, finalize = finalize, sanction = sanction, vetting = vetting, drafting = drafting, 
                                comment = comment, revise = revise, modified_on = curr_date, modified_by_id = request.user.MAV_userid
                            )

                            workflow_user_power_history.objects.create(
                                user_flag = prev_data[0]['user_flag_id'], for_user = prev_data[0]['for_user_id'], 
                                approve = prev_data[0]['approve'], reject = prev_data[0]['reject'], intforward = prev_data[0]['intforward'], extforward = prev_data[0]['extforward'],
                                revert = prev_data[0]['revert'], finalize = prev_data[0]['finalize'], sanction = prev_data[0]['sanction'], vetting = prev_data[0]['vetting'], drafting = prev_data[0]['drafting'], 
                                comment = prev_data[0]['comment'], revise = prev_data[0]['revise'], modified_on = prev_data[0]['modified_on'], modified_by = prev_data[0]['modified_by_id'],
                                updated_on = curr_date, updated_by_id = request.user.MAV_userid
                            )
                        else:
                            workflow_user_power.objects.create(user_flag_id = workflow_id, for_user_id = user_id,
                                approve = approve, reject = reject, intforward = intforward, extforward = extforward,
                                revert = revert, finalize = finalize, sanction = sanction, vetting = vetting, drafting = drafting, 
                                comment = comment, revise = revise, modified_on = curr_date, modified_by_id = request.user.MAV_userid
                            )
                    messages.success(request, 'Successfully Added/Updated.')


        workflow = workflow_type.objects.all()
        railway_code = request.user.MAV_rlycode_id
        if request.user.MAV_userlvlcode_id in ['1', '2']: 
            designation = list(MEM_usersn.objects.filter(is_active = True).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))

        else:
            all_railway = list(railwayLocationMaster.objects.filter(Q(rly_unit_code = railway_code)|Q(parent_rly_unit_code = railway_code)).values_list('rly_unit_code', flat=True))
            designation = list(MEM_usersn.objects.filter(is_active = True, MAV_rlycode__in = all_railway ).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
        mapping_dict = {
            'approve':'Approve','reject':'Reject','intforward':'Internal Forward','extforward':'External Forward','revert':'Revert',
            'finalize':'Finalize','sanction':'Sanction','vetting':'Vetting','drafting':'Drafting','comment':'Comment','revise':'Revise'
        }
        data = list(workflow_user_power.objects.filter(
            for_user__in = [i['MAV_userid'] for i in designation]
        ).values('id','user_flag','user_flag_id__type_name','for_user','for_user_id__MAV_userdesig',
                 'approve','reject','intforward','extforward','revert','finalize','sanction','vetting','drafting','comment','revise'))
        for i in data:
            rights = ''
            for key, values in mapping_dict.items():
                if i[key] == True:
                    if rights != '':
                        rights += ', '
                    rights += values
            i.update({'access_right':rights})


        context = {
            'workflow':workflow,
            'designation':designation,
            'data':data,
           
        }
        return render(request,'create_user_work_assigned.html',context)  
    except Exception as e: 
        print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

def create_level_work_assigned(request):
    try:
        import datetime
        curr_date = datetime.datetime.now()
        if request.method == 'GET' and request.is_ajax():
            ajax_type = request.GET.get('ajax_type')
            if ajax_type == 'edit':
                id = request.GET.get('id')
                data = list(MED_userlvls.objects.filter(MAV_userlvlcode = id).values())
                return JsonResponse(data,safe=False)
            return JsonResponse({'success': False}, status=400)

        if request.method == 'POST':
            submit_val = request.POST.get('submit')
            if submit_val == 'Create/Update':
                #approve,reject,intforward,extforward,revert,finalize,sanction,vetting,drafting,comment,revise
                workflow_id = request.POST.get('workflow_type')
                approve = True if request.POST.get('approve') else False
                reject = True if request.POST.get('reject') else False
                intforward = True if request.POST.get('intforward') else False
                extforward = True if request.POST.get('extforward') else False
                revert = True if request.POST.get('revert') else False
                finalize = True if request.POST.get('finalize') else False
                sanction = True if request.POST.get('sanction') else False
                vetting = True if request.POST.get('vetting') else False
                drafting = True if request.POST.get('drafting') else False
                comment = True if request.POST.get('comment') else False
                revise = True if request.POST.get('revise') else False
                MED_userlvls.objects.filter(MAV_userlvlcode = workflow_id).update(
                            approve = approve, reject = reject, intforward = intforward, extforward = extforward,
                            revert = revert, finalize = finalize, sanction = sanction, vetting = vetting, drafting = drafting, 
                            comment = comment, revise = revise
                        )
                messages.success(request, 'Successfully Updated.')
               
        designation = list(MED_userlvls.objects.filter(delete_flag = False).values('MAV_userlvlname','MAV_userlvlcode').order_by('MAV_userlvlname'))
        mapping_dict = {
            'approve':'Approve','reject':'Reject','intforward':'Internal Forward','extforward':'External Forward','revert':'Revert',
            'finalize':'Finalize','sanction':'Sanction','vetting':'Vetting','drafting':'Drafting','comment':'Comment','revise':'Revise'
        }
        data = list(MED_userlvls.objects.filter(delete_flag = False
        ).values('MAV_userlvlcode','MAV_userlvlname',
                 'approve','reject','intforward','extforward','revert','finalize','sanction','vetting','drafting','comment','revise'))
        for i in data:
            rights = ''
            for key, values in mapping_dict.items():
                if i[key] == True:
                    if rights != '':
                        rights += ', '
                    rights += values
            i.update({'access_right':rights})
        

        context = {
            'designation':designation,
            'data':data,
           
        }
        return render(request,'create_level_work_assigned.html',context)  
    except Exception as e: 
        print("Internal Error!!!")
        return render(request, "myadmin_errors.html", {})

@transaction.atomic
def workflow_application(request):
    gap = 15
    len_pending, len_comments, len_forwarded, showing, total = 0, 0, 0, 0, 0
    len_rejected, len_approved, len_sanction= 0, 0, 0
    thead = ['Activity Name', 'File ID', 'Status', 'Sent By', 'Remarks', 'Date', 'History', 'Action']
    thead_len = len(thead)
    table_len = 0
    cuser = request.user.MAV_userid
    if request.method == 'POST' and request.is_ajax():
        ajax_type = request.POST.get('ajax_type')  
        if ajax_type == 'SaveInfo': 
            try:
                remarks = request.POST.get('remarks')
                officer_id = json.loads(request.POST.get('officer_id'))
                trans_id = request.POST.get('trans_id')
                curr_date = datetime.datetime.now()
                for i in officer_id:
                    workflow_transaction_for_info.objects.create(trans_id_id = trans_id,
                                                                by_user_id = cuser,
                                                                to_user_id = i,
                                                                date = curr_date,
                                                                remarks = remarks)
                
                msg = 'Information sent successfully.'
            except:
                msg = 'Some error exists, contact Admin.'
            return JsonResponse(msg, safe = False)
        
        if ajax_type == 'SaveMessage': 
            remarks = request.POST.get('remarks')
            officer_id = request.POST.get('officer_id')
            globalBtnValue = request.POST.get('globalBtnValue')
            trans_id = request.POST.get('globalTransId')
            if officer_id == '':
                to_user = None
            else:
                to_user = int(officer_id)
            try:
                file = request.FILES['file']
            except:
                file = None
            curr_date = datetime.datetime.now()
            curr_time = curr_date.time()
            per_dict = {'intForward':1,'extForward':6,'comments':11,'approve':5,'reject':2,'revert':7,'finalize':8,'sanction':9,'vetting':10,'reply':13,'vetted':14}
            main_table_change = [1,6,5,2,7,8,9,10,14] 
            status_id = per_dict.get(globalBtnValue,None)
            msg = 'Something went wrong, Contact Admin.'
            if status_id == None:
                msg = 'Workflow status is not mapped, please contact admin'
            else:
                tran_data = list(workflow_transaction.objects.filter(trans_id = trans_id).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',  'workflow_id_id__type_id_id__table_name','workflow_id_id__type_id_id__column_name','workflow_id_id__type_id_id__column_pk'))
                if len(tran_data) == 0:
                    msg = 'transaction Not found in database, Contact Admin.'
                else:
                    if not status_id in [11]:
                        workflow_transaction.objects.filter(trans_id = trans_id).update(reply = True)
                    if status_id in [13]:
                        workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = tran_data[0]['by_user'],
                                        reply = True,
                                        read_flag = True
                                    )
                    elif status_id in [14]:
                        workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = tran_data[0]['by_user'],
                                        reply = False,
                                        read_flag = False
                                    )
                        to_user = tran_data[0]['by_user']
                    elif status_id in [8]:
                        workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = cuser,
                                        reply = False,
                                        read_flag = True
                                    )
                        to_user = cuser

                    else:
                        if status_id == 2:
                            workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = None,
                                        reply = True,
                                        read_flag = True
                                    )
                        elif status_id == 7:
                            workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = tran_data[0]['by_user']
                            )
                            to_user = tran_data[0]['by_user']

                        else:
                            if to_user == None:
                                workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                            by_user_id = cuser,
                                            status_id = status_id,
                                            date = curr_date,
                                            remarks = remarks,
                                            doc = file,
                                            to_user_id = to_user,
                                            read_flag = True
                                        )
                            else:
                                workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                            by_user_id = cuser,
                                            status_id = status_id,
                                            date = curr_date,
                                            remarks = remarks,
                                            doc = file,
                                            to_user_id = to_user
                                        )

                    msg = 'Done Successfully.'
                    if status_id in main_table_change:
                        if status_id == 9:
                            workflow_activity_request.objects.filter(workflow_id = tran_data[0]['workflow_id']).update(
                                                                    status_id = status_id,
                                                                pending_with_id = None)
                        else:
                            workflow_activity_request.objects.filter(workflow_id = tran_data[0]['workflow_id']).update(
                                                                    status_id = status_id,
                                                                 pending_with_id = to_user)
                        try: 
                            table_name = tran_data[0]['workflow_id_id__type_id_id__table_name']
                            column_name = tran_data[0]['workflow_id_id__type_id_id__column_name']
                            column_pk = tran_data[0]['workflow_id_id__type_id_id__column_pk']
                            table_name = globals()[table_name]
                            if status_id == 8:
                                updateArgs = {column_name:status_id , 'form_status' : 1}
                            else:
                                updateArgs = {column_name:status_id}
                            filter_args = {column_pk : tran_data[0]['workflow_id_id__mod_id']}
                            table_name.objects.filter(**filter_args).update(**updateArgs)
                        except:
                            msg = 'Status not changed in Main Table, Contact Admin'
            return JsonResponse(msg, safe = False)

        if ajax_type == 'SaveMessageAll': 
            remarks = request.POST.get('remarks')
            officer_id = request.POST.get('officer_id')
            globalBtnValue = request.POST.get('globalBtnValue')
            trans_id_All = request.POST.get('globalTransId')
            trans_id_All = trans_id_All.split(',')

            if officer_id == '':
                to_user = None
            else:
                to_user = int(officer_id)
            try:
                file = request.FILES['file']
            except:
                file = None
            curr_date = datetime.datetime.now()
            curr_time = curr_date.time()
            per_dict = {'intForward':1,'extForward':6,'comments':11,'approve':5,'reject':2,'revert':7,'finalize':8,'sanction':9,'vetting':10,'reply':13,'vetted':14}
            main_table_change = [1,6,5,2,7,8,9,10] 
            status_id = per_dict.get(globalBtnValue,None)
            msg = 'Something went wrong, Contact Admin.'
            if status_id == None:
                msg = 'Workflow status is not mapped, please contact admin'
            else:
                for ii in trans_id_All:
                    trans_id = ii
                    tran_data = list(workflow_transaction.objects.filter(trans_id = trans_id).values(
                        'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',  'workflow_id_id__type_id_id__table_name','workflow_id_id__type_id_id__column_name','workflow_id_id__type_id_id__column_pk'))
                    if len(tran_data) == 0:
                        msg = 'transaction Not found in database, Contact Admin.'
                    else:
                        if not status_id in [11]:
                            workflow_transaction.objects.filter(trans_id = trans_id).update(reply = True)
                        if status_id in [13]:
                            workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                            by_user_id = cuser,
                                            status_id = status_id,
                                            date = curr_date,
                                            remarks = remarks,
                                            doc = file,
                                            to_user_id = tran_data[0]['by_user'],
                                            reply = True,
                                            read_flag = True
                                        )
                        
                        elif status_id in [14]:
                            workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = tran_data[0]['by_user'],
                                        reply = False,
                                        read_flag = False
                                    )
                            to_user = tran_data[0]['by_user']
                        elif status_id in [8]:
                            workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                        by_user_id = cuser,
                                        status_id = status_id,
                                        date = curr_date,
                                        remarks = remarks,
                                        doc = file,
                                        to_user_id = cuser,
                                        reply = False,
                                        read_flag = True
                                    )
                            to_user = cuser
                        
                        else:
                            if status_id == 2:
                                workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                            by_user_id = cuser,
                                            status_id = status_id,
                                            date = curr_date,
                                            remarks = remarks,
                                            doc = file,
                                            to_user_id = None,
                                            reply = True,
                                            read_flag = True
                                        )
                            elif status_id == 7:
                                workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                            by_user_id = cuser,
                                            status_id = status_id,
                                            date = curr_date,
                                            remarks = remarks,
                                            doc = file,
                                            to_user_id = tran_data[0]['by_user']
                                )
                                to_user = tran_data[0]['by_user']

                            else:
                                if to_user == None:
                                    workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                                by_user_id = cuser,
                                                status_id = status_id,
                                                date = curr_date,
                                                remarks = remarks,
                                                doc = file,
                                                to_user_id = to_user,
                                                read_flag = True
                                            )
                                else:
                                    workflow_transaction.objects.create(workflow_id_id = tran_data[0]['workflow_id'],
                                                by_user_id = cuser,
                                                status_id = status_id,
                                                date = curr_date,
                                                remarks = remarks,
                                                doc = file,
                                                to_user_id = to_user
                                            )

                        msg = 'Done Successfully.'
                        if status_id in main_table_change:
                            if status_id == 9:
                                workflow_activity_request.objects.filter(workflow_id = tran_data[0]['workflow_id']).update(
                                                                        status_id = status_id,
                                                                    pending_with_id = None)
                            else:
                                workflow_activity_request.objects.filter(workflow_id = tran_data[0]['workflow_id']).update(
                                                                        status_id = status_id,
                                                                    pending_with_id = to_user)
                            try:
                                table_name = tran_data[0]['workflow_id_id__type_id_id__table_name']
                                column_name = tran_data[0]['workflow_id_id__type_id_id__column_name']
                                column_pk = tran_data[0]['workflow_id_id__type_id_id__column_pk']
                                table_name = globals()[table_name]
                                if status_id == 8:
                                    updateArgs = {column_name:status_id , 'form_status' : 1}
                                else:
                                    updateArgs = {column_name:status_id}
                                filter_args = {column_pk : tran_data[0]['workflow_id_id__mod_id']}
                                table_name.objects.filter(**filter_args).update(**updateArgs)
                            except:
                                msg = 'Status not changed in Main Table, Contact Admin'
                
            return JsonResponse(msg, safe = False)

        if ajax_type == 'SearchData':
            cuser = request.user.MAV_userid
            cdesig = request.user.MAV_userdesig
            call_type = request.POST.get('call_type')
            from_date = request.POST.get('from_date').split('-')
            from_date = from_date[2] + '-' + from_date[1] + '-' + from_date[0]
            to_date = request.POST.get('to_date').split('-')
            to_date = to_date[2] + '-' + to_date[1] + '-' + to_date[0]
            activity = json.loads(request.POST.get('activity'))
            railway = json.loads(request.POST.get('railway'))
            file_id = json.loads(request.POST.get('file_id'))
            status = json.loads(request.POST.get('status'))
            sent_by = json.loads(request.POST.get('sent_by'))
            sent_to = json.loads(request.POST.get('sent_to'))
            desc = request.POST.get('desc')

            if len(activity) == 0:
                activity = list(workflow_activity_request.objects.values_list('type_id',flat=True).distinct())
            if len(railway) == 0:
                railway = list(workflow_activity_request.objects.values_list('railway',flat=True).distinct())
                railway.append(None)
            if len(file_id) == 0:
                file_id = list(workflow_activity_request.objects.values_list('mod_name',flat=True).distinct())
            if len(status) == 0:
                status = list(workflow_transaction.objects.values_list('status',flat=True).distinct())
                status.append(0)
            if len(sent_by) == 0:
                sent_by = list(MEM_usersn.objects.filter(is_active=True).values_list('MAV_userid',flat=True).distinct())
                sent_by.append(None)
            if len(sent_to) == 0:
                sent_to = list(MEM_usersn.objects.filter(is_active=True).values_list('MAV_userid',flat=True).distinct())
                sent_to.append(None)
            
            if 'information' in call_type:
                if desc == '':
                    if call_type == 'sent_information':
                        search_codition = list(workflow_activity_request.objects.filter(
                            (Q(workflow_transaction__workflow_transaction_for_info__to_user__in=sent_to) | (Q(workflow_transaction__workflow_transaction_for_info__to_user__isnull=True) if None in sent_to else Q())),
                            (Q(railway__in=railway) | (Q(railway__isnull=True) if None in railway else Q())),
                            workflow_transaction__workflow_transaction_for_info__date__date__gte = from_date,
                            workflow_transaction__workflow_transaction_for_info__date__date__lte = to_date,
                            type_id__in = activity,
                            mod_name__in = file_id
                        ).values_list('workflow_transaction__workflow_transaction_for_info__id',flat = True).distinct())
                    else:
                        search_codition = list(workflow_activity_request.objects.filter(
                        (Q(workflow_transaction__workflow_transaction_for_info__by_user__in=sent_by) | (Q(workflow_transaction__workflow_transaction_for_info__by_user__isnull=True) if None in sent_by else Q())),
                        (Q(railway__in=railway) | (Q(railway__isnull=True) if None in railway else Q())),
                            workflow_transaction__workflow_transaction_for_info__date__date__gte = from_date,
                            workflow_transaction__workflow_transaction_for_info__date__date__lte = to_date,
                            type_id__in = activity,
                            
                            mod_name__in = file_id,
                           
                        ).values_list('workflow_transaction__workflow_transaction_for_info__id',flat = True).distinct())

                else:
                    if call_type == 'sent_information':
                        search_codition = list(workflow_activity_request.objects.filter(
                            (Q(workflow_transaction__workflow_transaction_for_info__to_user__in=sent_to) | (Q(workflow_transaction__workflow_transaction_for_info__to_user__isnull=True) if None in sent_to else Q())),
                        (Q(railway__in=railway) | (Q(railway__isnull=True) if None in railway else Q())),
                            workflow_transaction__workflow_transaction_for_info__date__date__gte = from_date,
                            workflow_transaction__workflow_transaction_for_info__date__date__lte = to_date,
                            type_id__in = activity,
                            
                            mod_name__in = file_id,
                            desc__icontains = desc
                        ).values_list('workflow_transaction__workflow_transaction_for_info__id',flat = True).distinct())
                    else:
                        search_codition = list(workflow_activity_request.objects.filter(
                        (Q(workflow_transaction__workflow_transaction_for_info__by_user__in=sent_by) | (Q(workflow_transaction__workflow_transaction_for_info__by_user__isnull=True) if None in sent_by else Q())),
                        (Q(railway__in=railway) | (Q(railway__isnull=True) if None in railway else Q())),
                            workflow_transaction__workflow_transaction_for_info__date__date__gte = from_date,
                            workflow_transaction__workflow_transaction_for_info__date__date__lte = to_date,
                            type_id__in = activity,
                            
                            mod_name__in = file_id,
                            desc__icontains = desc
                        ).values_list('workflow_transaction__workflow_transaction_for_info__id',flat = True).distinct())

            else:
                if desc == '':
                    search_codition = list(workflow_activity_request.objects.filter(
                        (Q(workflow_transaction__to_user__in=sent_to) | (Q(workflow_transaction__to_user__isnull=True) if None in sent_to else Q())),
                        (Q(workflow_transaction__by_user__in=sent_by) | (Q(workflow_transaction__by_user__isnull=True) if None in sent_by else Q())),
                        (Q(railway__in=railway) | (Q(railway__isnull=True) if None in railway else Q())),
                        workflow_transaction__date__date__gte = from_date,
                        workflow_transaction__date__date__lte = to_date,
                        type_id__in = activity,
                        workflow_transaction__status__in = status,
                        mod_name__in = file_id,
                        
                    ).values_list('workflow_transaction__trans_id',flat = True).distinct())
                else:
                    search_codition = list(workflow_activity_request.objects.filter(
                        (Q(workflow_transaction__to_user__in=sent_to) | (Q(workflow_transaction__to_user__isnull=True) if None in sent_to else Q())),
                        (Q(workflow_transaction__by_user__in=sent_by) | (Q(workflow_transaction__by_user__isnull=True) if None in sent_by else Q())),
                        (Q(railway__in=railway) | (Q(railway__isnull=True) if None in railway else Q())),
                        workflow_transaction__date__date__gte = from_date,
                        workflow_transaction__date__date__lte = to_date,
                        type_id__in = activity,
                        workflow_transaction__status__in = status,
                        mod_name__in = file_id,
                        desc__icontains = desc
                    ).values_list('workflow_transaction__trans_id',flat = True).distinct())

            if call_type == 'forwarded':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction.objects.filter(trans_id__in = search_codition).filter(by_user = cuser, status__in = [1,6,7,11,10,13,14], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                print(distinct_w)
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Sent To', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'pending_for_comments':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                
                workflow = list(workflow_transaction.objects.filter(trans_id__in = search_codition).filter(to_user = cuser, status__in = [11], reply = False, pull_back = False ).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        # if d1[0]['status'] == 0:
                        #     d1[0].update({'designation' : d1[0]['by_user_id__MAV_userdesig']})
                        # else:
                        #      d1[0].update({'designation' : d1[0]['to_user_id__MAV_userdesig']})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'pending_for_action':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                
                workflow = list(workflow_transaction.objects.filter((Q(by_user = cuser , status__in = [0], reply = False) | Q(to_user = cuser, status__in = [1,6,5,7,10,14,8], reply = False)), pull_back = False, trans_id__in = search_codition ).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        # if d1[0]['status'] == 0:
                        #     d1[0].update({'designation' : d1[0]['by_user_id__MAV_userdesig']})
                        # else:
                        #      d1[0].update({'designation' : d1[0]['to_user_id__MAV_userdesig']})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]

                wor_type = []
                already_type = []
                for i in workflow:
                    if i['workflow_id_id__type_id'] not in already_type:
                        already_type.append(i['workflow_id_id__type_id'])
                        wor_type.append({'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']})

                row = '<select style="height:30px;width:100%;background-color:#5C4033; color:white; font-weight:bold" id="select-all-type" onchange="funEnableType(this.value)"><option value="0">Select To Enable</option>'
                for i in wor_type:
                    id = i['id']
                    name = i['name']
                    row += f'<option  value="{id}">{name}</option>'
                row += '</select>'
                #thead = ['<input type="checkbox" name="mainCheckBox" onclick="funCheckAll(this)"> Select All','Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
                thead = [row,'Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
                
                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'rejected':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = [] 
                workflow = list(workflow_transaction.objects.filter(trans_id__in = search_codition).filter(workflow_id__in = 
                                                                    workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [2], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Rejected By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'sanction':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction.objects.filter(trans_id__in = search_codition).filter(workflow_id__in = 
                                                                    workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [9], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        d1[0].update({'status_id__status_name' : 'Sanction'})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sanctioned By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'approved':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction.objects.filter(trans_id__in = search_codition).filter(workflow_id__in = 
                                                                    workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [5], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        d1[0].update({'status_id__status_name' : 'Approve'})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Approved By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'sent_information':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction_for_info.objects.filter(id__in = search_codition).filter(by_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                            'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                            'trans_id','trans_id_id__workflow_id',
                                                                                            'trans_id_id__workflow_id_id__mod_name',
                                                                                            'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                            'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
                
                distinct_w = [i['trans_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['by_user'] == cuser, workflow))
                    distinct_d = [i['date']  for i in workflow]
                    distinct_d = list(set(distinct_d))
                    for k in distinct_d:
                        d1 = list(custom_filter(lambda x: x['date'] == k, d2))
                        if len(d1) > 0:
                            to = ''
                            for j in d1:
                                if to != '':
                                    to = to + ', '
                                desg = j['to_user_id__MAV_userdesig']      
                                
                                to = to + desg
                            d1[0].update({'to_user_id__MAV_userdesig' : to})
                            data.append(d1[0])
                
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name', 'Railway/Type','File ID', 'File Description', 'Document', 'Sent To', 'Date','File Movement', 'Remarks']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'received_information':
                start = int(request.POST.get('start'))
                gap = int(request.POST.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction_for_info.objects.filter(id__in = search_codition).filter(to_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                            'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                            'trans_id','trans_id_id__workflow_id',
                                                                                            'trans_id_id__workflow_id_id__mod_name',
                                                                                            'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                            'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
                
                distinct_w = [i['trans_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['to_user'] == cuser, workflow))
                    distinct_d = [i['date']  for i in workflow]
                    distinct_d = list(set(distinct_d))
                    for k in distinct_d:
                        d1 = list(custom_filter(lambda x: x['date'] == k, d2))
                        if len(d1) > 0:
                            to = ''
                            for j in d1:
                                if to != '':
                                    to = to + ', '
                                desg = j['by_user_id__MAV_userdesig']
                                to = to + desg
                            d1[0].update({'to_user_id__MAV_userdesig' : to})
                            data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name', 'Railway/Type','File ID', 'File Description', 'Document', 'Sent By', 'Date','File Movement', 'Remarks']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
     
    workflow = list(workflow_transaction.objects.filter((Q(by_user = cuser , status__in = [0], reply = False) | Q(to_user = cuser, status__in = [1,6,5,7,10,14,8], reply = False)), pull_back = False ).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
            ).order_by('-trans_id'))
    distinct_w = [i['workflow_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    data = []
    for i in distinct_w:
        d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
        if len(d1) > 0:
            data.append(d1[0])
    len_pending = len(data)
    workflow = list(workflow_transaction.objects.filter(to_user = cuser, status__in = [11], reply = False, pull_back = False ).values('trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'))
    distinct_w = [i['workflow_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    data = []
    for i in distinct_w:
        d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
        if len(d1) > 0:
            data.append(d1[0])
    len_comments = len(data)
    data = []
    workflow = list(workflow_transaction.objects.filter(by_user = cuser, status__in = [1,6,7,11,10,13,14],pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
            ).order_by('-trans_id'))
            
    distinct_w = [i['workflow_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    for i in distinct_w:
        d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
        if len(d1) > 0:
            data.append(d1[0])
    len_forwarded = len(data)
    data = []
    workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [2], pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
            ).order_by('-trans_id'))
    distinct_w = [i['workflow_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    for i in distinct_w:
        d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
        if len(d1) > 0:
            data.append(d1[0])
    len_rejected = len(data)
    data = []
    workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [5], pull_back = False ).values(
        'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
        'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
        'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
    ).order_by('-trans_id'))
    distinct_w = [i['workflow_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    for i in distinct_w:
        d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
        if len(d1) > 0:
            d1[0].update({'status_id__status_name' : 'Approve'})
            data.append(d1[0])
    len_approved = len(data)
    data = []
    workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [9], pull_back = False).values(
        'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
        'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
        'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
    ).order_by('-trans_id'))
    distinct_w = [i['workflow_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    for i in distinct_w:
        d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
        if len(d1) > 0:
            d1[0].update({'status_id__status_name' : 'Sanction'})
            data.append(d1[0])
    len_sanction = len(data)
    
    data = []
    workflow = list(workflow_transaction_for_info.objects.filter(to_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                           'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                           'trans_id','trans_id_id__workflow_id',
                                                                                           'trans_id_id__workflow_id_id__mod_name',
                                                                                           'trans_id_id__workflow_id_id__type_id_id__type_name').order_by('-id'))
            
    distinct_w = [i['trans_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    for i in distinct_w:
        d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['to_user'] == cuser, workflow))
        distinct_d = [i['date']  for i in workflow]
        distinct_d = list(set(distinct_d))
        for k in distinct_d:
            d1 = list(custom_filter(lambda x: x['date'] == k, d2))
            if len(d1) > 0:
                to = ''
                for j in d1:
                    if to != '':
                        to = to + ', '
                    desg = j['by_user_id__MAV_userdesig']
                    to = to + desg
                d1[0].update({'to_user_id__MAV_userdesig' : to})
                data.append(d1[0])
            
    len_rinfo = len(data)

    data = []
    workflow = list(workflow_transaction_for_info.objects.filter(by_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                           'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                           'trans_id','trans_id_id__workflow_id',
                                                                                           'trans_id_id__workflow_id_id__mod_name',
                                                                                           'trans_id_id__workflow_id_id__type_id_id__type_name').order_by('-id'))        
    distinct_w = [i['trans_id']  for i in workflow]
    distinct_w = list(set(distinct_w))
    for i in distinct_w:
        d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['by_user'] == cuser, workflow))
        distinct_d = [i['date']  for i in workflow]
        distinct_d = list(set(distinct_d))
        for k in distinct_d:
            d1 = list(custom_filter(lambda x: x['date'] == k, d2))
            if len(d1) > 0:
                to = ''
                for j in d1:
                    if to != '':
                        to = to + ', '
                    desg = j['to_user_id__MAV_userdesig']
                    to = to + desg
                d1[0].update({'to_user_id__MAV_userdesig' : to})
                data.append(d1[0])
    len_sinfo = len(data)

    designation = list(MEM_usersn.objects.filter(is_active = True).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))

    context = {
        'gap':gap,
        'designation':designation,
        'len_pending':len_pending,
        'len_comments':len_comments,
        'len_forwarded':len_forwarded,
        'len_rejected':len_rejected,
        'len_approved':len_approved,
        'len_sanction':len_sanction,
        'len_sinfo':len_sinfo,
        'len_rinfo':len_rinfo,
        'showing':showing,
        'total':total,
        'thead':thead,
        'thead_len':thead_len,
        'table_len':table_len,
    }
    return render(request, 'workflow_application.html', context)


@transaction.atomic
def workflow_application_call(request):
    gap = 15
    import datetime
    curr_date = datetime.datetime.now()
    cuser = request.user.MAV_userid
    cdesig = request.user.MAV_userdesig
    try:
        a = request.user.MAV_rlycode.location_code
        b = request.user.MAV_rlycode.location_type
        railway = a +'/'+b
    except:
        railway = ' - '
    
    if request.method == 'GET': 
        ajax_type = request.GET.get('ajax_type') 
        if ajax_type == 'PullBack':
            trans_id = int(request.GET.get('trans_id'))
            
            data = list(workflow_transaction.objects.filter(trans_id = trans_id).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
            ).order_by('-trans_id'))

            workflow = list(workflow_transaction.objects.filter(workflow_id = data[0]['workflow_id']).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url','pull_back'
            ).order_by('-trans_id'))
            t_id = ''
            for i in range(1,len(workflow)):
                if workflow[i]['status'] == 0 and workflow[i]['pull_back'] == False:
                    pending_with = workflow[i]['by_user']
                    t_id = workflow[i]['trans_id']
                    status = workflow[i]['status']
                    break
                elif workflow[i]['status'] in [1,6,5,10,14]  and workflow[i]['pull_back'] == False:
                    pending_with = workflow[i]['to_user']
                    t_id = workflow[i]['trans_id']
                    status = workflow[i]['status']
                    break
            msg = 'Cannnot Pull Back, Contact Admin'
            print('sssssssssssssssssssssss         ',trans_id,t_id)
            if t_id != '':
                workflow_transaction.objects.filter(trans_id = trans_id).update(pull_back = True)
                workflow_transaction.objects.filter(trans_id = t_id).update(
                    reply = False,
                    status = status
                    )
                workflow_activity_request.objects.filter(workflow_id = workflow[0]['workflow_id']).update(
                    status = status,
                    pending_with_id = pending_with
                )
                msg = 'Pull Backed successfully'
            return JsonResponse(msg,safe=False)
        
        if ajax_type == 'GetOfficer':
            btn_id = request.GET.get('btn_id')
            type_id = request.GET.get('type_id')
            show_all = request.GET.get('show_all')
            user_rly_id = request.user.MAV_rlycode.rly_unit_code
            data = []
            if btn_id == 'approve':
                finid = request.user.MAV_rprtto_id
                if show_all != '1':
                    if finid != None:
                        data = list(MEM_usersn.objects.filter(is_active = True, MAV_userid = finid).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                    else:
                        data = list(MEM_usersn.objects.filter(is_active = True, MAV_rlycode__in = railwayLocationMaster.objects.filter(location_code = 'RB').values('rly_unit_code')).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                else:
                    data = list(MEM_usersn.objects.filter(is_active = True, MAV_rlycode__in = railwayLocationMaster.objects.filter(location_code = 'RB').values('rly_unit_code')).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
          
            elif btn_id == 'vetting':
                finid = request.user.MAV_finid_id
                if finid != None:
                    data = list(MEM_usersn.objects.filter(is_active = True, MAV_userid = finid).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
            elif show_all == '1':
                if btn_id == 'intForward':
                    data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode = user_rly_id).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                elif btn_id == 'comments':
                    data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode = user_rly_id).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                elif btn_id == 'extForward':
                    try:
                        parent_rly = [int(list(railwayLocationMaster.objects.filter(rly_unit_code = user_rly_id).values('parent_rly_unit_code'))[0]['parent_rly_unit_code'])]
                    except:
                        parent_rly = [0]
                    child_rly = list(railwayLocationMaster.objects.filter(parent_rly_unit_code = user_rly_id).values_list('rly_unit_code'))
                    child_rly = [0]
                    if len(child_rly) > 0:
                        parent_rly.extend(child_rly)
                    data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode__in = parent_rly).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
            else:
                if btn_id == 'intForward':
                    data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(
                        is_active = True, MAV_userid__in = workflow_internal_forward.objects.filter(by_user = request.user.MAV_userid, type_id = type_id).values('to_user')).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                if btn_id == 'comments':
                    data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(
                        is_active = True, MAV_userid__in = workflow_internal_forward.objects.filter(by_user = request.user.MAV_userid, type_id = type_id).values('to_user')).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                
                elif btn_id == 'extForward':
                    data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(
                        is_active = True, MAV_userid__in = workflow_external_forward.objects.filter(by_user = request.user.MAV_userid, type_id = type_id).values('to_user')).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))

                if len(data) == 0:
                    if btn_id == 'intForward':
                        data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode = user_rly_id).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                    elif btn_id == 'comments':
                        data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode = user_rly_id).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
                
                    elif btn_id == 'extForward':
                        try:
                            parent_rly = [int(list(railwayLocationMaster.objects.filter(rly_unit_code = user_rly_id).values('parent_rly_unit_code'))[0]['parent_rly_unit_code'])]
                        except:
                            parent_rly = [0]
                        child_rly = list(railwayLocationMaster.objects.filter(parent_rly_unit_code = user_rly_id).values_list('rly_unit_code'))
                        child_rly = [0]
                        if len(child_rly) > 0:
                            parent_rly.extend(child_rly)
                        data = list(MEM_usersn.objects.exclude(MAV_userid = request.user.MAV_userid).filter(is_active = True, MAV_rlycode__in = parent_rly).values('MAV_userdesig','MAV_userid').order_by('MAV_userdesig'))
            
            context = {
                'data':data
            }
                        
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'ExpandDetails':
            trans_id = request.GET.get('trans_id')
            workflow_transaction.objects.filter(trans_id = trans_id).update(read_flag = True)


            data = list(workflow_transaction.objects.filter(trans_id = trans_id).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url','workflow_id_id__type_id_id__column_pk',
                'workflow_id_id__desc','workflow_id_id__railway','workflow_id_id__type_id_id__table_name','workflow_id_id__type_id_id__column_name',
                'workflow_id_id__pending_with_id__designation_id_id__MAVDLVL'
            ).order_by('-trans_id'))
            
            thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
            type_id = data[0]['workflow_id_id__type_id']
            permission = list(workflow_user_power.objects.filter(user_flag = type_id, for_user = request.user.MAV_userid).values())
            if len(permission) == 0:
                try:
                    user_lvl = request.user.MAV_userlvlcode.MAV_userlvlcode
                except:
                    user_lvl = 90
                permission = list(MED_userlvls.objects.filter(delete_flag = False, MAV_userlvlcode = user_lvl).values())
            
            href = data[0]['workflow_id_id__url']
            des_type = data[0]['workflow_id_id__pending_with_id__designation_id_id__MAVDLVL']
            draft_per = False
            revise_url = data[0]['workflow_id_id__url'] + f"/?submit=editprop&id={data[0]['workflow_id_id__mod_id']}"
            if data[0]['status'] == 11 and len(permission) > 0:
                permission[0].update({'approve': False, 'reject': False, 'intforward': False, 'extforward': False, 
                                   'revert': False, 'finalize': False, 'sanction': False, 'vetting': False, 'drafting': False, 'revise': False})
            
            if len(permission) > 0:
                
                    
                draft = permission[0]['drafting']

                table_name = data[0]['workflow_id_id__type_id_id__table_name']
                column_name = data[0]['workflow_id_id__type_id_id__column_name']
                column_pk = data[0]['workflow_id_id__type_id_id__column_pk']
                table_name = globals()[table_name]
                
                filter_args = {column_pk : data[0]['workflow_id_id__mod_id']}
                prsln_data = table_name.objects.filter(**filter_args).first()
                sanction = permission[0]['sanction']
                try:
                    if type_id == 1 and sanction:
                        if des_type == 'DRM' or des_type == 'CWM':
                            chkSanction = prsln_data.MAVDRMSANC
                            if chkSanction != 'Y':
                                permission[0].update({'sanction':False})
                        if des_type == 'GM':
                            chkSanction = prsln_data.MAVGMSANC
                            if chkSanction != 'Y':
                                permission[0].update({'sanction':False})
                except:
                    pass
                if draft and href != None:
                    if prsln_data.form_status == 0:
                        draft_per = True
                        href = href + f"/?submit=WorkflowEdit&id={data[0]['workflow_id_id__mod_id']}"
                revise = permission[0]['revise']
                finalize = permission[0]['finalize']
                if prsln_data.form_status == 1 and revise:
                    permission[0].update({'revise':True})
                else:
                    permission[0].update({'revise':False})
                if prsln_data.form_status == 0 and finalize:
                    permission[0].update({'finalize':True})
                else:
                    permission[0].update({'finalize':False})

                if permission[0]['revise'] == False:
                    revise_url = ''
            context = {
                'data':data,
                'thead':thead,
                'cdesig':cdesig,
                'permission':permission,
                'draft_per':draft_per,
                'href':href,
                'revise_url':revise_url,
            }
                        
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'FileMovement':
            workflow_id = request.GET.get('workflow_id')
            workflow = list(workflow_transaction.objects.filter(workflow_id = workflow_id, pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','doc',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
            ).order_by('-trans_id'))

            for i in range(len(workflow)):
                status = workflow[i]['status']
                ref_no = ''
                if status in [7,13]:
                    frm = workflow[i]['by_user'] 
                    to = workflow[i]['to_user']
                    for j in range(i,len(workflow)):
                        if workflow[j]['by_user'] == to and workflow[j]['to_user'] == frm:
                            ref_no = '<span style="color:brown;"> (' + str(workflow[j]['trans_id']) + ')</span>'
                            break
                workflow[i].update({'ref_no':ref_no})
                
            return JsonResponse(workflow,safe=False)
        
        if ajax_type == 'forwarded':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            workflow = list(workflow_transaction.objects.filter(by_user = cuser, status__in = [1,6,7,11,10,13,14],pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
            distinct_w = [i['workflow_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                if len(d1) > 0:
                    data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Sent To', 'Date','Document', 'File Movement', 'Action']

            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'pending_for_comments':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            
            workflow = list(workflow_transaction.objects.filter(to_user = cuser, status__in = [11], reply = False, pull_back = False ).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
            distinct_w = [i['workflow_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                if len(d1) > 0:
                    # if d1[0]['status'] == 0:
                    #     d1[0].update({'designation' : d1[0]['by_user_id__MAV_userdesig']})
                    # else:
                    #      d1[0].update({'designation' : d1[0]['to_user_id__MAV_userdesig']})
                    data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'pending_for_action':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            
            workflow = list(workflow_transaction.objects.filter((Q(by_user = cuser , status__in = [0], reply = False) | Q(to_user = cuser, status__in = [1,6,5,7,10,14,8], reply = False)), pull_back = False ).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
            distinct_w = [i['workflow_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                if len(d1) > 0:
                    # if d1[0]['status'] == 0:
                    #     d1[0].update({'designation' : d1[0]['by_user_id__MAV_userdesig']})
                    # else:
                    #      d1[0].update({'designation' : d1[0]['to_user_id__MAV_userdesig']})
                    data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]

            wor_type = []
            already_type = []
            for i in workflow:
                if i['workflow_id_id__type_id'] not in already_type:
                    already_type.append(i['workflow_id_id__type_id'])
                    wor_type.append({'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']})

            row = '<select style="height:30px;width:100%;background-color:#5C4033; color:white; font-weight:bold" id="select-all-type" onchange="funEnableType(this.value)"><option value="0">Select To Enable</option>'
            for i in wor_type:
                id = i['id']
                name = i['name']
                row += f'<option  value="{id}">{name}</option>'
            row += '</select>'
            #thead = ['<input type="checkbox" name="mainCheckBox" onclick="funCheckAll(this)"> Select All','Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
            thead = [row,'Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
            
            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'Initiate':
            module = request.GET.get('module')
            status = request.GET.get('status')
            description = request.GET.get('description')
            id = request.GET.get('id')
            doc = request.GET.get('doc')
            if doc == 'doc' or doc == '':
                doc = None
            url = request.GET.get('url')
            if url == 'url' or url == '':
                url = None
            msg = ''
            ws = list(workflow_status.objects.filter(status_name = status).values('status_id'))
            if len(ws) > 0:
                status_id = ws[0]['status_id']
                wt = list(workflow_type.objects.filter(module_name = module).values('type_id'))
                if len(wt) > 0:
                    type_id = wt[0]['type_id']
                    proposal = request.GET.get('proposal')
                    if workflow_activity_request.objects.filter(mod_id = id,type_id = type_id ).exists():
                        msg = f'Cannot {status}, as this {module} is already present in Workflow.'
                    else:
                        workflow_id = workflow_activity_request.objects.create(type_id_id = type_id,
                                                                status_id = status_id, 
                                                                url = url,
                                                                doc_url = doc,
                                                                mod_id = id,
                                                                mod_name = proposal,
                                                                pending_with_id = request.user.MAV_userid,
                                                                desc = description[:500],
                                                                railway = railway)
                        
                        workflow_transaction.objects.create(workflow_id = workflow_id,
                                    by_user_id = request.user.MAV_userid,
                                    status_id = status_id,
                                    date = curr_date,
                                    remarks = 'Initiated By Self'
                                    )
                        
                        msg = f'Successfully {status}, Please go to workflow application for further Action.'
                else:
                    msg = f'Cannot {status}, as this module is not linked with Workflow. Please contact Admin.'
                
            else:
                msg = f'Cannot {status}, as this Status is not linked with Workflow. Please contact Admin.'
           
            return JsonResponse(msg,safe=False)
        
        if ajax_type == 'rejected':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = [] 
            workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [2], pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
            distinct_w = [i['workflow_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                if len(d1) > 0:
                    data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Rejected By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'sanction':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [9], pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
            distinct_w = [i['workflow_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                if len(d1) > 0:
                    d1[0].update({'status_id__status_name' : 'Sanction'})
                    data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sanctioned By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'approved':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [5], pull_back = False).values(
                'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
            distinct_w = [i['workflow_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                if len(d1) > 0:
                    d1[0].update({'status_id__status_name' : 'Approve'})
                    data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Approved By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'sent_information':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            workflow = list(workflow_transaction_for_info.objects.filter(by_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                           'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                           'trans_id','trans_id_id__workflow_id',
                                                                                           'trans_id_id__workflow_id_id__mod_name',
                                                                                           'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                           'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
            
            distinct_w = [i['trans_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['by_user'] == cuser, workflow))
                distinct_d = [i['date']  for i in workflow]
                distinct_d = list(set(distinct_d))
                for k in distinct_d:
                    d1 = list(custom_filter(lambda x: x['date'] == k, d2))
                    if len(d1) > 0:
                        to = ''
                        for j in d1:
                            if to != '':
                                to = to + ', '
                            desg = j['to_user_id__MAV_userdesig']      
                            
                            to = to + desg
                        d1[0].update({'to_user_id__MAV_userdesig' : to})
                        data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name', 'Railway/Type','File ID', 'File Description', 'Document', 'Sent To', 'Date','File Movement', 'Remarks']

            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'received_information':
            start = int(request.GET.get('start'))
            gap = int(request.GET.get('text_gap'))
            end = start + gap
            data = []
            workflow = list(workflow_transaction_for_info.objects.filter(to_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                           'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                           'trans_id','trans_id_id__workflow_id',
                                                                                           'trans_id_id__workflow_id_id__mod_name',
                                                                                           'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                           'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
            
            distinct_w = [i['trans_id']  for i in workflow]
            distinct_w = list(set(distinct_w))
            for i in distinct_w:
                d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['to_user'] == cuser, workflow))
                distinct_d = [i['date']  for i in workflow]
                distinct_d = list(set(distinct_d))
                for k in distinct_d:
                    d1 = list(custom_filter(lambda x: x['date'] == k, d2))
                    if len(d1) > 0:
                        to = ''
                        for j in d1:
                            if to != '':
                                to = to + ', '
                            desg = j['by_user_id__MAV_userdesig']
                            to = to + desg
                        d1[0].update({'to_user_id__MAV_userdesig' : to})
                        data.append(d1[0])
            try:
                data = sorted(data,key = lambda x: x['date'], reverse=True)
            except:
                pass
            total = len(data)
            if end > total:
                end = total
            data = data[start:end]
            thead = ['Activity Name', 'Railway/Type','File ID', 'File Description', 'Document', 'Sent By', 'Date','File Movement', 'Remarks']

            context = {
                'start':start,
                'end':end,
                'data':data,
                'total':total,
                'gap':gap,
                'thead':thead,
                'cdesig':cdesig
                
            }
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'previousInfo':
            transid = int(request.GET.get('transid'))
           
            workflow = list(workflow_transaction_for_info.objects.filter(trans_id = transid).values_list('to_user_id__MAV_userdesig', flat=True).distinct())
            context = ', '.join(workflow)
            return JsonResponse(context,safe=False)
        
        if ajax_type == 'AdvancedSearch':
            call_type = request.GET.get('call_type')
            if call_type == 'pending_for_action':
                workflow = list(workflow_transaction.objects.filter((Q(by_user = cuser , status__in = [0], reply = False) | Q(to_user = cuser, status__in = [1,6,5,7,10,14,8], reply = False)), pull_back = False ).values(
                'status','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                activity = unique_dict_list([{'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['workflow_id_id__railway']} for i in workflow if i['workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['workflow_id_id__mod_name']} for i in workflow if i['workflow_id_id__mod_name'] != None])
                statusName = unique_dict_list([{'id':i['status'], 'name':i['status_id__status_name']} for i in workflow])
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                

            elif call_type == 'forwarded':
                workflow = list(workflow_transaction.objects.filter(by_user = cuser, status__in = [1,6,7,11,10,13,14],pull_back = False).values(
                'status','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
                activity = unique_dict_list([{'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['workflow_id_id__railway']} for i in workflow if i['workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['workflow_id_id__mod_name']} for i in workflow if i['workflow_id_id__mod_name'] != None])
                statusName = unique_dict_list([{'id':i['status'], 'name':i['status_id__status_name']} for i in workflow])
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                
            elif call_type == 'pending_for_comments':
                workflow = list(workflow_transaction.objects.filter(to_user = cuser, status__in = [11], reply = False, pull_back = False ).values(
                'status','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
                activity = unique_dict_list([{'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['workflow_id_id__railway']} for i in workflow if i['workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['workflow_id_id__mod_name']} for i in workflow if i['workflow_id_id__mod_name'] != None])
                statusName = unique_dict_list([{'id':i['status'], 'name':i['status_id__status_name']} for i in workflow])
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                
            elif call_type == 'rejected':
                workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [2], pull_back = False).values(
                'status','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
                activity = unique_dict_list([{'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['workflow_id_id__railway']} for i in workflow if i['workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['workflow_id_id__mod_name']} for i in workflow if i['workflow_id_id__mod_name'] != None])
                statusName = unique_dict_list([{'id':i['status'], 'name':i['status_id__status_name']} for i in workflow])
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                
            elif call_type == 'sanction':
                workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [9], pull_back = False).values(
                'status','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
                activity = unique_dict_list([{'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['workflow_id_id__railway']} for i in workflow if i['workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['workflow_id_id__mod_name']} for i in workflow if i['workflow_id_id__mod_name'] != None])
                statusName = unique_dict_list([{'id':i['status'], 'name':i['status_id__status_name']} for i in workflow])
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                
            elif call_type == 'approved':
                workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [5], pull_back = False).values(
                'status','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                'workflow_id_id__type_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                'workflow_id_id__desc','workflow_id_id__railway'
            ).order_by('-trans_id'))
                activity = unique_dict_list([{'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['workflow_id_id__railway']} for i in workflow if i['workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['workflow_id_id__mod_name']} for i in workflow if i['workflow_id_id__mod_name'] != None])
                statusName = unique_dict_list([{'id':i['status'], 'name':i['status_id__status_name']} for i in workflow])
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                
            elif call_type == 'sent_information':
                workflow = list(workflow_transaction_for_info.objects.filter(by_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                           'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                           'trans_id','trans_id_id__workflow_id',
                                                                                           'trans_id_id__workflow_id_id__mod_name',
                                                                                           'trans_id_id__workflow_id_id__type_id_id',
                                                                                           'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                           'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
                activity = unique_dict_list([{'id':i['trans_id_id__workflow_id_id__type_id_id'], 'name':i['trans_id_id__workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['trans_id_id__workflow_id_id__railway']} for i in workflow if i['trans_id_id__workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['trans_id_id__workflow_id_id__mod_name']} for i in workflow if i['trans_id_id__workflow_id_id__mod_name'] != None])
                statusName = []
                by_user = []
                to_user = unique_dict_list([{'id':i['to_user'], 'name':i['to_user_id__MAV_userdesig']} for i in workflow if i['to_user'] != None])
                
            elif call_type == 'received_information':
                workflow = list(workflow_transaction_for_info.objects.filter(to_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                           'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                           'trans_id','trans_id_id__workflow_id',
                                                                                           'trans_id_id__workflow_id_id__mod_name',
                                                                                           'trans_id_id__workflow_id_id__type_id_id',
                                                                                           'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                           'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
                activity = unique_dict_list([{'id':i['trans_id_id__workflow_id_id__type_id_id'], 'name':i['trans_id_id__workflow_id_id__type_id_id__type_name']} for i in workflow])
                railwayName = unique_dict_list([{'name':i['trans_id_id__workflow_id_id__railway']} for i in workflow if i['trans_id_id__workflow_id_id__railway'] != None])
                fileName = unique_dict_list([{'name':i['trans_id_id__workflow_id_id__mod_name']} for i in workflow if i['trans_id_id__workflow_id_id__mod_name'] != None])
                statusName = []
                by_user = unique_dict_list([{'id':i['by_user'], 'name':i['by_user_id__MAV_userdesig']} for i in workflow if i['by_user'] != None])
                to_user = []

            context = {
                    'activity':activity,
                    'railwayName':railwayName,
                    'fileName':fileName,
                    'statusName':statusName,
                    'by_user':by_user,
                    'to_user':to_user
                    }

            return JsonResponse(context,safe=False)
        
        if ajax_type == 'SearchData':
            call_type = request.GET.get('call_type')

            from_date = request.GET.get('from_date')
            to_date = request.GET.get('to_date')
            activity = request.GET.get('activity')
            railway = request.GET.get('railway')
            file_id = request.GET.get('file_id')
            status = request.GET.get('status')
            sent_by = request.GET.get('sent_by')
            sent_to = request.GET.get('sent_to')
            desc = request.GET.get('desc')
            
            
            if len(activity) == 0:
                activity = list(workflow_activity_request.objects.values_list('workflow_activity_request',flat=True).distinct())
            if len(railway) == 0:
                railway = list(workflow_activity_request.objects.values_list('railway',flat=True).distinct())
            if len(file_id) == 0:
                file_id = list(workflow_activity_request.objects.values_list('mod_name',flat=True).distinct())
            if len(status) == 0:
                status = list(workflow_activity_request.objects.values_list('status',flat=True).distinct())
            if len(sent_by) == 0:
                sent_by = list(workflow_transaction.objects.values_list('by_user',flat=True).distinct())
            if len(sent_to) == 0:
                sent_to = list(workflow_transaction.objects.values_list('to_user',flat=True).distinct())
            
            search_codition = list(workflow_activity_request.objects.filter(
                workflow_transaction__date__date__gte = '2024-08-10'
            ).values_list('workflow_id',flat = True))

           



            if call_type == 'forwarded':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction.objects.filter(by_user = cuser, status__in = [1,6,7,11,10,13,14],pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Sent To', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'pending_for_comments':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                
                workflow = list(workflow_transaction.objects.filter(to_user = cuser, status__in = [11], reply = False, pull_back = False ).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        # if d1[0]['status'] == 0:
                        #     d1[0].update({'designation' : d1[0]['by_user_id__MAV_userdesig']})
                        # else:
                        #      d1[0].update({'designation' : d1[0]['to_user_id__MAV_userdesig']})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'pending_for_action':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                
                workflow = list(workflow_transaction.objects.filter((Q(by_user = cuser , status__in = [0], reply = False) | Q(to_user = cuser, status__in = [1,6,5,7,10,14,8], reply = False)), pull_back = False ).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        # if d1[0]['status'] == 0:
                        #     d1[0].update({'designation' : d1[0]['by_user_id__MAV_userdesig']})
                        # else:
                        #      d1[0].update({'designation' : d1[0]['to_user_id__MAV_userdesig']})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]

                wor_type = []
                already_type = []
                for i in workflow:
                    if i['workflow_id_id__type_id'] not in already_type:
                        already_type.append(i['workflow_id_id__type_id'])
                        wor_type.append({'id':i['workflow_id_id__type_id'], 'name':i['workflow_id_id__type_id_id__type_name']})

                row = '<select style="height:30px;width:100%;background-color:#5C4033; color:white; font-weight:bold" id="select-all-type" onchange="funEnableType(this.value)"><option value="0">Select To Enable</option>'
                for i in wor_type:
                    id = i['id']
                    name = i['name']
                    row += f'<option  value="{id}">{name}</option>'
                row += '</select>'
                #thead = ['<input type="checkbox" name="mainCheckBox" onclick="funCheckAll(this)"> Select All','Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
                thead = [row,'Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sent By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
                
                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'rejected':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = [] 
                workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                    workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [2], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Rejected By', 'Pending With', 'Date','Document', 'File Movement', 'Action']
                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'sanction':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                    workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [9], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        d1[0].update({'status_id__status_name' : 'Sanction'})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Sanctioned By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'approved':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                                    workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [5], pull_back = False).values(
                    'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig',
                    'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
                    'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url',
                    'workflow_id_id__desc','workflow_id_id__railway'
                ).order_by('-trans_id'))
                distinct_w = [i['workflow_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d1 = list(custom_filter(lambda x: x['workflow_id'] == i, workflow))
                    if len(d1) > 0:
                        d1[0].update({'status_id__status_name' : 'Approve'})
                        data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name','Railway/Type', 'File ID', 'File Desc', 'Status', 'Approved By', 'Pending With', 'Date','Document', 'File Movement', 'Action']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'sent_information':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction_for_info.objects.filter(by_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                            'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                            'trans_id','trans_id_id__workflow_id',
                                                                                            'trans_id_id__workflow_id_id__mod_name',
                                                                                            'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                            'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
                
                distinct_w = [i['trans_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['by_user'] == cuser, workflow))
                    distinct_d = [i['date']  for i in workflow]
                    distinct_d = list(set(distinct_d))
                    for k in distinct_d:
                        d1 = list(custom_filter(lambda x: x['date'] == k, d2))
                        if len(d1) > 0:
                            to = ''
                            for j in d1:
                                if to != '':
                                    to = to + ', '
                                desg = j['to_user_id__MAV_userdesig']      
                                
                                to = to + desg
                            d1[0].update({'to_user_id__MAV_userdesig' : to})
                            data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name', 'Railway/Type','File ID', 'File Description', 'Document', 'Sent To', 'Date','File Movement', 'Remarks']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
            
            if call_type == 'received_information':
                start = int(request.GET.get('start'))
                gap = int(request.GET.get('text_gap'))
                end = start + gap
                data = []
                workflow = list(workflow_transaction_for_info.objects.filter(to_user = cuser).values('by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','by_user','to_user',
                                                                                            'date','trans_id_id__workflow_id_id__doc_url','remarks','read_flag','trans_id_id__workflow_id_id__mod_id',
                                                                                            'trans_id','trans_id_id__workflow_id',
                                                                                            'trans_id_id__workflow_id_id__mod_name',
                                                                                            'trans_id_id__workflow_id_id__type_id_id__type_name',
                                                                                            'trans_id_id__workflow_id_id__railway','trans_id_id__workflow_id_id__desc').order_by('-id'))
                
                distinct_w = [i['trans_id']  for i in workflow]
                distinct_w = list(set(distinct_w))
                for i in distinct_w:
                    d2 = list(custom_filter(lambda x: x['trans_id'] == i and x['to_user'] == cuser, workflow))
                    distinct_d = [i['date']  for i in workflow]
                    distinct_d = list(set(distinct_d))
                    for k in distinct_d:
                        d1 = list(custom_filter(lambda x: x['date'] == k, d2))
                        if len(d1) > 0:
                            to = ''
                            for j in d1:
                                if to != '':
                                    to = to + ', '
                                desg = j['by_user_id__MAV_userdesig']
                                to = to + desg
                            d1[0].update({'to_user_id__MAV_userdesig' : to})
                            data.append(d1[0])
                try:
                    data = sorted(data,key = lambda x: x['date'], reverse=True)
                except:
                    pass
                total = len(data)
                if end > total:
                    end = total
                data = data[start:end]
                thead = ['Activity Name', 'Railway/Type','File ID', 'File Description', 'Document', 'Sent By', 'Date','File Movement', 'Remarks']

                context = {
                    'start':start,
                    'end':end,
                    'data':data,
                    'total':total,
                    'gap':gap,
                    'thead':thead,
                    'cdesig':cdesig
                    
                }
                return JsonResponse(context,safe=False)
        
            
        
        return JsonResponse({'success': False}, status=400)

def workflow_search_desc(request):
    if 'q' in request.GET:
        cuser = request.user.MAV_userid
        query = request.GET.get('q')
        call_type = request.GET.get('call_type')
        workflow = []
        if call_type == 'pending_for_action':
            workflow = list(workflow_transaction.objects.filter((Q(by_user = cuser , status__in = [0], reply = False) | Q(to_user = cuser, status__in = [1,6,5,7,10,14,8], reply = False)), pull_back = False, workflow_id_id__desc__icontains = query )
                                .values_list('workflow_id_id__desc', flat=True).order_by('-trans_id').distinct())[:20]
        
        elif call_type == 'forwarded':
            workflow = list(workflow_transaction.objects.filter(by_user = cuser, status__in = [1,6,7,11,10,13,14],pull_back = False, workflow_id_id__desc__icontains = query)
                            .values_list('workflow_id_id__desc', flat=True).order_by('-trans_id').distinct())[:20]

        elif call_type == 'pending_for_comments':
            workflow = list(workflow_transaction.objects.filter(to_user = cuser, status__in = [11], reply = False, pull_back = False , workflow_id_id__desc__icontains = query)
                            .values_list('workflow_id_id__desc', flat=True).order_by('-trans_id').distinct())[:20]
            
        elif call_type == 'rejected':
            workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                            workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [2], pull_back = False, workflow_id_id__desc__icontains = query)
                                                            .values_list('workflow_id_id__desc', flat=True).order_by('-trans_id').distinct())[:20]
        elif call_type == 'sanction':
            workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                            workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [9], pull_back = False, workflow_id_id__desc__icontains = query)
                                                            .values_list('workflow_id_id__desc', flat=True).order_by('-trans_id').distinct())[:20]
        elif call_type == 'approved':
            workflow = list(workflow_transaction.objects.filter(workflow_id__in = 
                                                            workflow_transaction.objects.filter(Q(by_user = cuser)|Q(to_user = cuser)).values('workflow_id'), status__in = [5], pull_back = False, workflow_id_id__desc__icontains = query)
                                                            .values_list('workflow_id_id__desc', flat=True).order_by('-trans_id').distinct())[:20]
        elif call_type == 'sent_information':
            workflow = list(workflow_transaction_for_info.objects.filter(by_user = cuser, trans_id_id__workflow_id_id__desc__icontains = query)
                            .values_list('trans_id_id__workflow_id_id__desc', flat=True).order_by('-id').distinct())[:20]
                           
        elif call_type == 'received_information':
            workflow = list(workflow_transaction_for_info.objects.filter(to_user = cuser, trans_id_id__workflow_id_id__desc__icontains = query)
                            .values_list('trans_id_id__workflow_id_id__desc', flat=True).order_by('-id').distinct())[:20]
        return JsonResponse(workflow, safe=False)
    return JsonResponse([], safe=False)

def unique_dict_list(dict_list):
    seen = set()
    unique_dicts = []
    
    for d in dict_list:
        frozen_dict = frozenset(d.items())
        if frozen_dict not in seen:
            seen.add(frozen_dict)
            unique_dicts.append(dict(frozen_dict))

    return unique_dicts


def workflow_pdf(request,workflow_id, *args, **kwargs):
    import datetime
    workflow = list(workflow_transaction.objects.filter(workflow_id = workflow_id, pull_back = False).values(
        'trans_id','workflow_id','status','date','remarks','read_flag','status_id__status_name','by_user','to_user','by_user_id__MAV_userdesig','to_user_id__MAV_userdesig','doc',
        'workflow_id_id__type_id','workflow_id_id__doc_url','workflow_id_id__mod_id','workflow_id_id__mod_name','workflow_id_id__type_id_id__type_name',
        'workflow_id_id__pending_with_id__MAV_userdesig','workflow_id_id__url'
    ).order_by('-trans_id'))
    
    encrpt = encryption_decription()
    attac_count = 1
    merge_list = []
    file_obj = FileFormatter()
    username = request.user.MAV_username
    directory = "media/converted"  
    prefix = username
    excluding_keyword = 'final'

    for i in range(len(workflow)):
        status = workflow[i]['status']
        ref_no = ''
        if status in [7,13]:
            frm = workflow[i]['by_user'] 
            to = workflow[i]['to_user']
            for j in range(i,len(workflow)):
                if workflow[j]['by_user'] == to and workflow[j]['to_user'] == frm:
                    ref_no =  '(' +str(workflow[j]['trans_id']) +')'
                    break
        workflow[i].update({'ref_no':ref_no})
        if workflow[i]['to_user'] == None:
            workflow[i].update({'to_user_id__MAV_userdesig':'-'})
        if(workflow[i]['remarks'] == 'Initiated By Self'):
            remarks = ''
        else:
            remarks = encrpt.decryptWithAesEinspect(workflow[i]['remarks'])
        if workflow[i]['doc'] == None or workflow[i]['doc'] == '':
            attachement = '  --  '
        else:

            attachement = 'Attachement-'+str(attac_count)
            up_file = workflow[i]['doc']
            up_relative_path = f'media/{up_file}'
            up_abs_path = os.path.abspath(up_relative_path)
            file_type = file_obj.determine_file_type(up_abs_path)
            
            if file_type != 'Unknown':
                try:
                    if file_type == 'PDF':
                        folder_abs_path = os.path.abspath('media/converted')
                        blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                        file_obj.create_blank_pdf(blank_abs_path)
                        title = f'Attachement-{attac_count}'
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                        merge_list.append(out_abs_path)

                    elif file_type == 'Image':
                        title = f'Attachement-{attac_count}'
                        folder_abs_path = os.path.abspath('media/converted')
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                        merge_list.append(out_abs_path)

                    attac_count += 1
                except:
                    pass

        
        workflow[i].update({'attachement':attachement,'remarks':remarks})
    
    context = {
        'workflow':workflow,
        'username':username,
    }
    
    file_no = workflow[0]['workflow_id_id__mod_name']
    file_name = f'{username}_workflow.pdf'
    file_obj.render_to_file_pdfkit('workflow_pdf1.html', context, file_name, file_no,'Workflow Application')
    
    folder_abs_path = os.path.abspath('media/converted')
    file_name = f'{username}_workflow.pdf'
    file_name = f'{folder_abs_path}/{file_name}'
    file_name = os.path.abspath(file_name)
    merge_list.insert(0,file_name)

    pdf_path = f'{folder_abs_path}/{username}_final.pdf'
    file_obj.merge_pdfs(merge_list, pdf_path)
    file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, excluding_keyword)

   
    with open(pdf_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
        response = HttpResponse(pdf_content, content_type='application/pdf')        
        response['Content-Disposition'] = 'inline; filename="file.pdf"'
        return response
    
def find_railway(rly_unit_code):
    railway = rly_unit_code
    p = list(railwayLocationMaster.objects.filter(rly_unit_code = rly_unit_code).values(
        'rly_unit_code','location_code','location_type','parent_location_code','parent_rly_unit_code'))
    if p[0]['parent_location_code'] != 'RB':
        railway = find_railway(p[0]['parent_rly_unit_code'])
    return railway

def find_div(rly_unit_code):
    division = rly_unit_code
    p = list(railwayLocationMaster.objects.filter(rly_unit_code = rly_unit_code).values(
        'rly_unit_code','location_code','location_type','parent_location_code','parent_rly_unit_code'))
    p1 = list(railwayLocationMaster.objects.filter(rly_unit_code = p[0]['parent_rly_unit_code'] ).values(
        'rly_unit_code','location_code','location_type','parent_location_code','parent_rly_unit_code'))
    if p1[0]['parent_location_code'] != 'RB':
        division = find_div(p[0]['parent_rly_unit_code'])
    return division

def find_div_railway(rly_unit_code):
    division, railway = find_div(rly_unit_code) , find_railway(rly_unit_code)
    p = list(railwayLocationMaster.objects.filter(rly_unit_code = division).values(
        'rly_unit_code','location_code','location_type','parent_location_code','parent_rly_unit_code'))
    division = p[0]['location_code']
    p = list(railwayLocationMaster.objects.filter(rly_unit_code = railway).values(
        'rly_unit_code','location_code','location_type','parent_location_code','parent_rly_unit_code'))
    railway = p[0]['location_code']
    if division == railway:
        division = '-'
    return division, railway
    
def mnp_document_pdf(request, id, *args, **kwargs):
    import datetime
    from django.contrib.staticfiles import finders
    file_path = finders.find('images/indian-railways.jpg')
    ###  /* <img src="{{file_path}}" style="height: 90px;width: 110px;"> */
    proposal = MEM_PRSLN.objects.filter(ID = id).all()
    slno = proposal[0].MAVPRSLNO
    rep_add = proposal[0].MAVADDNRPLC
    location = list(railwayLocationMaster.objects.filter(rly_unit_code = proposal[0].MAVRLYCODE_id).values('location_code','location_type'))
    division, railway = find_div_railway(proposal[0].MAVRLYCODE_id)
    cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = slno).values().order_by('MANCPCODE'))
    cost_parameter = ['Optional Accessories','Excise Duty','CST','Freight','Insurance',
                        'Contingencies','Mech.Sub Estimate','Electrical Sub Estimate','Eng Sub Estimate',
                        'S % T Sub Estimate','Other Charges','D&G','GST']
    cost_data = []
    for i in range(1, len(cost_parameter) + 1):
        filtered_data = list(custom_filter(lambda x : x['MANCPCODE'] == i , cost))
        if len(filtered_data):
            cost_data.append({'par':cost_parameter[i-1], 'unit':filtered_data[0]['MANCPAMNT'], 'value':filtered_data[0]['MANCPPER']})
        else:
            cost_data.append({'par':cost_parameter[i-1], 'unit':0, 'value':0})
    just = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MATJSFN'))
    encrpt = encryption_decription()
    if len(just) > 0:
        try:
            just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
        except:
            just = just[0]['MATJSFN']
    else:
        just = ''
    replacement = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO = slno).values('MAVASSTCODE','MAIYEARPURC','MAVITEMCODE','MAIEXPLIFE','MAVDESC','MAICOST'))
    if len(replacement):
        catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = replacement[0]['MAVASSTCODE'])
        replacement[0].update({'MAVASSTCODE':catg_id.MAV_ITEM_CODE})
    rep_just = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO = slno).values('MANSIFTNO','MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL',
                                                                            'MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB'))
    addition = list(MED_PRSLRORN.objects.filter(MAVPRSLNO = slno).values())
    add = ''
    rorType = '1'
    ror_attacch = None
    if len(addition) > 0:
        encrpt = encryption_decription()
        if addition[0]['RORREQUIRED'] == 'N':
            rorType = '1'
            try:
                add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
            except:
                add = addition[0]['MATRORDETL']
        else:
            rorType = '2'
            if addition[0]['RORPDFNAME'] != None:
                ror_attacch = addition[0]['RORPDFNAME']
            try:
                add = encrpt.decryptWithAesEinspect(addition[0]['RORREMARKS'])
            except:
                add = addition[0]['RORREMARKS']
    
    curr_date = datetime.datetime.now()
    created_on = curr_date.strftime('%d-%m-%Y')

    #### get uploaded file 
    file_obj = FileFormatter()
    uploaded_file = []
    all_file_uploaded = list(MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MAVPDFNAME','MAVORGPDFNAME','MADUPLDDATETIME').order_by('MADUPLDDATETIME'))
    attac_count = 1
    username = request.user.MAV_username
    merge_list = []
    directory = "media/converted"  # Change this to your directory
    prefix = username
    excluding_keyword = 'final'
    for i in all_file_uploaded:
        up_file = i['MAVORGPDFNAME']
        up_relative_path = f'media/{up_file}'
        up_abs_path = os.path.abspath(up_relative_path)
        file_type = file_obj.determine_file_type(up_abs_path)
        print(file_type)
        if file_type != 'Unknown':
            try:
                if file_type == 'PDF':
                    folder_abs_path = os.path.abspath('media/converted')
                    blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                    file_obj.create_blank_pdf(blank_abs_path)
                    title = f'Attachement-{attac_count}'
                    out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                    file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                    merge_list.append(out_abs_path)

                elif file_type == 'Image':
                    title = f'Attachement-{attac_count}'
                    folder_abs_path = os.path.abspath('media/converted')
                    out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                    file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                    merge_list.append(out_abs_path)

                uploaded_file.append(i)
                attac_count += 1
            except:
                pass
    attac_count = 0
    if ror_attacch != None:
        up_file = ror_attacch
        up_relative_path = f'media/{up_file}'
        up_abs_path = os.path.abspath(up_relative_path)
        file_type = file_obj.determine_file_type(up_abs_path)
        if file_type != 'Unknown':
            try:
                if file_type == 'PDF':
                    folder_abs_path = os.path.abspath('media/converted')
                    blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                    file_obj.create_blank_pdf(blank_abs_path)
                    title = f'Annexure-{attac_count}'
                    out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                    file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                    merge_list.append(out_abs_path)

                elif file_type == 'Image':
                    title = f'Annexure-{attac_count}'
                    folder_abs_path = os.path.abspath('media/converted')
                    out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                    file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                    merge_list.append(out_abs_path)     
            except:
                pass 
    
    if  proposal[0].form_status == 0:
        # slno = proposal[0].MAVDRFTPRSLNO
        proposal_type = 'Draft MNP Proposal'
    else:
        proposal_type = 'MNP Proposal'
    context = {
        # 'file_name':file_name,
        'rorType':rorType,
            'attac_count':attac_count,
        'created_on':created_on,
        'file_path':file_path,
        'proposal':proposal,
        'slno':slno,
        'division':division,
        'railway':railway,
        'location':location,
        'cost_data':cost_data,
        'just':just,
        'rep_add':rep_add,
        'replacement':replacement,
        'addition':addition,
        'rep_just':rep_just,
        'uploaded_file':uploaded_file,
        'add':add,
    }
    file_no = slno
    folder_abs_path = os.path.abspath('media/converted')
    file_name = f'{username}_main.pdf'
    file_obj.render_to_file_pdfkit('mnp_document_pdf.html', context, file_name, file_no, proposal_type)
    file_name = f'{folder_abs_path}/{file_name}'
    file_name = os.path.abspath(file_name)

    # file_name = file_obj.render_to_file('mnp_document_pdf.html', context, file_name)
    # file_name = f'{folder_abs_path}/{file_name}'
    file_name = os.path.abspath(file_name)


    merge_list.insert(0,file_name)

    pdf_path = f'{folder_abs_path}/{username}_final.pdf'
    file_obj.merge_pdfs(merge_list, pdf_path)
    file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, excluding_keyword)

    
    with open(pdf_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
        response = HttpResponse(pdf_content, content_type='application/pdf')        
        response['Content-Disposition'] = 'inline; filename="file.pdf"'
        return response
    
def mnp_document_pdf_combine(request, *args, **kwargs):
    import datetime
    from django.contrib.staticfiles import finders
    ids = request.GET.getlist('ids')
    options = request.GET.getlist('options')
    oproposal, ocost, oror, oreplacement, ojustification, odoc = False, False, False, False, False, False
    if '1' in options:
        oproposal = True
    if '2' in options:
        ocost = True
    if '3' in options:
        oror = True
    if '4' in options:
        oreplacement = True
    if '5' in options:
        ojustification = True
    if '6' in options:
        odoc = True
    final_list = []
    file_obj = FileFormatter()
    username = request.user.MAV_username
    directory = "media/converted1" 
    prefix = username
    file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, '  @#@ ')
    for id in ids:
        proposal = MEM_PRSLN.objects.filter(ID = id).all()
        slno = proposal[0].MAVPRSLNO
        rep_add = proposal[0].MAVADDNRPLC
        location = list(railwayLocationMaster.objects.filter(rly_unit_code = proposal[0].MAVRLYCODE_id).values('location_code','location_type'))
        division, railway = find_div_railway(proposal[0].MAVRLYCODE_id)
        cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = slno).values().order_by('MANCPCODE'))
        cost_parameter = ['Optional Accessories','Excise Duty','CST','Freight','Insurance',
                            'Contingencies','Mech.Sub Estimate','Electrical Sub Estimate','Eng Sub Estimate',
                            'S % T Sub Estimate','Other Charges','D&G','GST']
        cost_data = []
        for i in range(1, len(cost_parameter) + 1):
            filtered_data = list(custom_filter(lambda x : x['MANCPCODE'] == i , cost))
            if len(filtered_data):
                cost_data.append({'par':cost_parameter[i-1], 'unit':filtered_data[0]['MANCPAMNT'], 'value':filtered_data[0]['MANCPPER']})
            else:
                cost_data.append({'par':cost_parameter[i-1], 'unit':0, 'value':0})
        just = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MATJSFN'))
        encrpt = encryption_decription()
        if len(just) > 0:
            try:
                just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
            except:
                just = just[0]['MATJSFN']
        else:
            just = ''
        replacement = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO = slno).values('MAVASSTCODE','MAIYEARPURC','MAVITEMCODE','MAIEXPLIFE','MAVDESC','MAICOST'))
        if len(replacement):
            catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = replacement[0]['MAVASSTCODE'])
            replacement[0].update({'MAVASSTCODE':catg_id.MAV_ITEM_CODE})
        rep_just = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO = slno).values('MANSIFTNO','MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL',
                                                                                'MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB'))
        addition = list(MED_PRSLRORN.objects.filter(MAVPRSLNO = slno).values())
        add = ''
        rorType = '1'
        ror_attacch = None
        if len(addition) > 0:
            encrpt = encryption_decription()
            if addition[0]['RORREQUIRED'] == 'N':
                rorType = '1'
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
                except:
                    add = addition[0]['MATRORDETL']
            else:
                rorType = '2'
                if addition[0]['RORPDFNAME'] != None:
                    ror_attacch = addition[0]['RORPDFNAME']
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['RORREMARKS'])
                except:
                    add = addition[0]['RORREMARKS']
        
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')

        #### get uploaded file 
        uploaded_file = []
        all_file_uploaded = list(MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MAVPDFNAME','MAVORGPDFNAME','MADUPLDDATETIME').order_by('MADUPLDDATETIME'))
        attac_count = 1
        
        merge_list = []
        
        excluding_keyword = 'final'
        if odoc:
            for i in all_file_uploaded:
                up_file = i['MAVORGPDFNAME']
                up_relative_path = f'media/{up_file}'
                up_abs_path = os.path.abspath(up_relative_path)
                file_type = file_obj.determine_file_type(up_abs_path)
                if file_type != 'Unknown':
                    try:
                        if file_type == 'PDF':
                            folder_abs_path = os.path.abspath('media/converted1')
                            blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                            file_obj.create_blank_pdf(blank_abs_path)
                            title = f'Attachement-{attac_count}'
                            out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                            file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                            merge_list.append(out_abs_path)

                        elif file_type == 'Image':
                            title = f'Attachement-{attac_count}'
                            folder_abs_path = os.path.abspath('media/converted1')
                            out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                            file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                            merge_list.append(out_abs_path)

                        uploaded_file.append(i)
                        attac_count += 1
                    except:
                        pass

        attac_count = 0
        if ror_attacch != None:
            up_file = ror_attacch
            up_relative_path = f'media/{up_file}'
            up_abs_path = os.path.abspath(up_relative_path)
            file_type = file_obj.determine_file_type(up_abs_path)
            if file_type != 'Unknown':
                try:
                    if file_type == 'PDF':
                        folder_abs_path = os.path.abspath('media/converted')
                        blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                        file_obj.create_blank_pdf(blank_abs_path)
                        title = f'Annexure-{attac_count}'
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                        merge_list.append(out_abs_path)

                    elif file_type == 'Image':
                        title = f'Annexure-{attac_count}'
                        folder_abs_path = os.path.abspath('media/converted')
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                        merge_list.append(out_abs_path)     
                except:
                    pass 
           
        if  proposal[0].form_status == 0:
            proposal_type = 'Draft MNP Proposal'
        else:
            proposal_type = 'MNP Proposal'
        context = {
            'oproposal':oproposal,
            'ocost':ocost,
            'oror':oror,
            'oreplacement':oreplacement,
            'ojustification':ojustification,
            'odoc': odoc,
            'created_on':created_on,
            'proposal':proposal,
            'slno':slno,
            'division':division,
            'railway':railway,
            'location':location,
            'cost_data':cost_data,
            'just':just,
            'rep_add':rep_add,
            'replacement':replacement,
            'addition':addition,
            'rep_just':rep_just,
            'uploaded_file':uploaded_file,
            'add':add,
            'rorType':rorType,
            'attac_count':attac_count,
        }

        file_no = slno
        folder_abs_path = os.path.abspath('media/converted1')
        file_name = f'{username}_main_{id}.pdf'
        file_obj.render_to_file_pdfkit1('mnp_document_pdf_combine.html', context, file_name, file_no, proposal_type)
        file_name = f'{folder_abs_path}/{file_name}'
        file_name = os.path.abspath(file_name)
        file_name = os.path.abspath(file_name)
        merge_list.insert(0,file_name)
        pdf_path = f'{folder_abs_path}/{username}_final_{id}.pdf'
        file_obj.merge_pdfs(merge_list, pdf_path)
        file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, excluding_keyword)
        final_list.append(pdf_path)
    pdf_path = f'{folder_abs_path}/{username}_final1_{id}.pdf'
    file_obj.merge_pdfs(final_list, pdf_path)
    file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, 'final1')
    with open(pdf_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
        response = HttpResponse(pdf_content, content_type='application/pdf')        
        response['Content-Disposition'] = 'inline; filename="file.pdf"'
        return response
    
def mnp_document_pdf_comparision(request, *args, **kwargs):
    import datetime
    ids = request.GET.getlist('ids')
    options = request.GET.getlist('options')
    oproposal, ocost, oror, oreplacement, ojustification, odoc = False, False, False, False, False, False
    print(options)
    if '1' in options:
        oproposal = True
    if '2' in options:
        ocost = True
    if '3' in options:
        oror = True
    if '4' in options:
        oreplacement = True
    if '5' in options:
        ojustification = True
    if '6' in options:
        odoc = True
    final_list = []
    # Fetch proposals based on the given IDs
    proposal = MEM_PRSLN.objects.filter(ID__in=ids).all().order_by('ID')
    cost_parameter = ['Optional Accessories','Excise Duty','CST','Freight','Insurance',
                            'Contingencies','Mech.Sub Estimate','Electrical Sub Estimate','Eng Sub Estimate',
                            'S % T Sub Estimate','Other Charges','D&G','GST']
    encrpt = encryption_decription()
    rep_add_list = []
    for i in proposal:
        slno = i.MAVPRSLNO
        rep_add = i.MAVADDNRPLC

        location = list(railwayLocationMaster.objects.filter(rly_unit_code=i.MAVRLYCODE_id).values('location_code', 'location_type'))
        division, railway = find_div_railway(i.MAVRLYCODE_id)
        
        i.division = division
        i.railway = railway
        cost_data = []
        cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = slno).values().order_by('MANCPCODE'))
        for ii in range(1, len(cost_parameter) + 1):
            filtered_data = list(custom_filter(lambda x : x['MANCPCODE'] == ii , cost))
            if len(filtered_data):
                cost_data.append({'par':cost_parameter[ii-1], 'unit':filtered_data[0]['MANCPAMNT'], 'value':filtered_data[0]['MANCPPER']})
            else:
                cost_data.append({'par':cost_parameter[ii-1], 'unit':0, 'value':0})
        
        i.cost_data = cost_data
        just = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MATJSFN'))
        
        if len(just) > 0:
            try:
                just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
            except:
                just = just[0]['MATJSFN']
        else:
            just = ''
        i.just = just

        replacement = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO = slno).values('MAVASSTCODE','MAIYEARPURC','MAVITEMCODE','MAIEXPLIFE','MAVDESC','MAICOST'))
        if len(replacement):
            catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = replacement[0]['MAVASSTCODE'])
            replacement[0].update({'MAVASSTCODE':catg_id.MAV_ITEM_CODE})
        rep_just = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO = slno).values('MANSIFTNO','MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL',
                                                                                'MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB'))
        i.replacement = replacement
        i.rep_just = rep_just
        addition = list(MED_PRSLRORN.objects.filter(MAVPRSLNO = slno).values())
        add = ''
        rorType = '1'
        ror_attacch = None
        if len(addition) > 0:
            encrpt = encryption_decription()
            if addition[0]['RORREQUIRED'] == 'N':
                rorType = '1'
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
                except:
                    add = addition[0]['MATRORDETL']
            else:
                rorType = '2'
                if addition[0]['RORPDFNAME'] != None:
                    ror_attacch = addition[0]['RORPDFNAME']
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['RORREMARKS'])
                except:
                    add = addition[0]['RORREMARKS']
        
        i.addition = addition
        i.add = add
        i.rorType = rorType
        i.ror_attacch = ror_attacch
        i.rep_add = rep_add
        rep_add_list.append(rep_add)

       
    username = request.user.MAV_username
    directory = "media/converted1" 
    prefix = username
    excluding_keyword = 'final'
    merge_list = []
    file_obj = FileFormatter()
    file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, '  @#@ ')

        
    
    proposal_type = 'MNP Proposal Comparision'
    
    context = {
        'oproposal':oproposal,
        'ocost':ocost,
        'oror':oror,
        'oreplacement':oreplacement,
        'ojustification':ojustification,
        'odoc': odoc,
        
        'proposal':proposal,
        'rep_add_list':rep_add_list,
    }
    
    folder_abs_path = os.path.abspath('media/converted1')
    file_name = f'{username}_final.pdf'
    file_obj.render_to_file_pdfkit2('mnp_document_comparision_pdf.html', context, file_name, '', proposal_type)
    file_name = f'{folder_abs_path}/{file_name}'
    file_name = os.path.abspath(file_name)

    with open(file_name, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
        response = HttpResponse(pdf_content, content_type='application/pdf')        
        response['Content-Disposition'] = 'inline; filename="file.pdf"'
        return response
    print('ffffffffffffffff')

    for id in ids:
        proposal = MEM_PRSLN.objects.filter(ID = id).all()
        slno = proposal[0].MAVPRSLNO
        rep_add = proposal[0].MAVADDNRPLC
        location = list(railwayLocationMaster.objects.filter(rly_unit_code = proposal[0].MAVRLYCODE_id).values('location_code','location_type'))
        division, railway = find_div_railway(proposal[0].MAVRLYCODE_id)
        cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = slno).values().order_by('MANCPCODE'))
        cost_parameter = ['Optional Accessories','Excise Duty','CST','Freight','Insurance',
                            'Contingencies','Mech.Sub Estimate','Electrical Sub Estimate','Eng Sub Estimate',
                            'S % T Sub Estimate','Other Charges','D&G','GST']
        cost_data = []
        for i in range(1, len(cost_parameter) + 1):
            filtered_data = list(custom_filter(lambda x : x['MANCPCODE'] == i , cost))
            if len(filtered_data):
                cost_data.append({'par':cost_parameter[i-1], 'unit':filtered_data[0]['MANCPAMNT'], 'value':filtered_data[0]['MANCPPER']})
            else:
                cost_data.append({'par':cost_parameter[i-1], 'unit':0, 'value':0})
        just = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MATJSFN'))
        encrpt = encryption_decription()
        if len(just) > 0:
            try:
                just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
            except:
                just = just[0]['MATJSFN']
        else:
            just = ''
        replacement = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO = slno).values('MAVASSTCODE','MAIYEARPURC','MAVITEMCODE','MAIEXPLIFE','MAVDESC','MAICOST'))
        if len(replacement):
            catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = replacement[0]['MAVASSTCODE'])
            replacement[0].update({'MAVASSTCODE':catg_id.MAV_ITEM_CODE})
        rep_just = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO = slno).values('MANSIFTNO','MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL',
                                                                                'MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB'))
        addition = list(MED_PRSLRORN.objects.filter(MAVPRSLNO = slno).values())
        add = ''
        if len(addition) > 0:
            try:
                add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
            except:
                add = addition[0]['MATRORDETL']
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')

        #### get uploaded file 
        file_obj = FileFormatter()
        uploaded_file = []
        
        
        merge_list = []
        directory = "media/converted1" 
        prefix = username
        excluding_keyword = 'final'
       
        proposal_type = 'MNP Proposal Comparision'
        context = {
            'oproposal':oproposal,
            'ocost':ocost,
            'oror':oror,
            'oreplacement':oreplacement,
            'ojustification':ojustification,
            'odoc': odoc,
            'created_on':created_on,
            'proposal':proposal,
            'slno':slno,
            'division':division,
            'railway':railway,
            'location':location,
            'cost_data':cost_data,
            'just':just,
            'rep_add':rep_add,
            'replacement':replacement,
            'addition':addition,
            'rep_just':rep_just,
            'uploaded_file':uploaded_file,
            'add':add,
        }

        file_no = slno
        folder_abs_path = os.path.abspath('media/converted1')
        file_name = f'{username}_main_{id}.pdf'
        file_obj.render_to_file_pdfkit2('mnp_document_comparision_pdf.html', context, file_name, '', proposal_type)
        file_name = f'{folder_abs_path}/{file_name}'
        file_name = os.path.abspath(file_name)
        file_name = os.path.abspath(file_name)
        merge_list.insert(0,file_name)
        pdf_path = f'{folder_abs_path}/{username}_final_{id}.pdf'
        file_obj.merge_pdfs(merge_list, pdf_path)
        file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, excluding_keyword)
        final_list.append(pdf_path)
    pdf_path = f'{folder_abs_path}/{username}_final1_{id}.pdf'
    file_obj.merge_pdfs(final_list, pdf_path)
    file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, 'final1')
    with open(pdf_path, 'rb') as pdf_file:
        pdf_content = pdf_file.read()
        response = HttpResponse(pdf_content, content_type='application/pdf')        
        response['Content-Disposition'] = 'inline; filename="file.pdf"'
        return response
    


from PIL import Image
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import inch
from PyPDF2 import PdfFileReader, PdfFileWriter
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
from io import BytesIO
import glob
from io import BytesIO
from django.http import HttpResponse
from django.template.loader import get_template
from xhtml2pdf import pisa
import base64 
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad,unpad
from django.conf import settings
import os
import pdfkit
from django.template.loader import get_template
from django.template import TemplateDoesNotExist, TemplateSyntaxError


class FileFormatter:
    def is_pdf(self,file_path):
        """Check if the file is a PDF by attempting to read it with PyPDF2."""
        try:
            with open(file_path, 'rb') as f:
                reader = PdfFileReader(f)
                return True
        except Exception:
            return False

    def is_image(self,file_path):
        """Check if the file is an image by attempting to open it with PIL."""
        try:
            with Image.open(file_path) as img:
                # If PIL can open it, then it's an image
                return True
        except Exception:
            return False

    def determine_file_type(self,file_path):
        """Determine if the file is a PDF or an image."""
        # Check file extension as a preliminary step
        _, file_extension = os.path.splitext(file_path)
        file_extension = file_extension.lower()
        if file_extension in ['.pdf']:
            return 'PDF' if self.is_pdf(file_path) else 'Unknown'

        # Common image file extensions
        image_extensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff', '.webp']
        if file_extension in image_extensions:
            return 'Image' if self.is_image(file_path) else 'Unknown'

        return 'Unknown'

    def convert_image_to_pdf(self,image_path, pdf_path, title):
        img = Image.open(image_path)
        a4_width, a4_height = A4
        img_width, img_height = img.size
        aspect_ratio = img_width / img_height
        if aspect_ratio > (a4_width / a4_height):
            new_width = a4_width
            new_height = a4_width / aspect_ratio
        else:
            new_width = a4_height * aspect_ratio
            new_height = a4_height
        c = canvas.Canvas(pdf_path, pagesize=A4)
        x_offset = (a4_width - new_width) / 2
        y_offset = (a4_height - new_height) / 2
        c.drawImage(image_path, x_offset, y_offset, width=new_width, height=new_height)
        c.setFont("Helvetica-Bold", 8)
        title_width = c.stringWidth(title, "Helvetica-Bold", 8)
        margin = 0.2 * inch
        c.drawString(a4_width - title_width - margin, a4_height - margin, title)
        c.save()

    def create_title_pdf(self,title, font_size=8, page_size=A4):
        buffer = BytesIO()
        c = canvas.Canvas(buffer, pagesize=page_size)
        width, height = page_size
        c.setFont("Helvetica-Bold", font_size)
        text_width = c.stringWidth(title, "Helvetica-Bold", font_size)
        x_position = width - text_width - 12
        y_position = height - 22
        c.drawString(x_position, y_position, title)
        c.save()
        buffer.seek(0)
        return buffer

    def add_title_to_first_page(self,input_pdf_path, output_pdf_path, title):
        title_pdf_buffer = self.create_title_pdf(title)
        with open(input_pdf_path, 'rb') as input_pdf_file:
            input_pdf = PdfFileReader(input_pdf_file)
            output_pdf = PdfFileWriter()
            title_pdf = PdfFileReader(title_pdf_buffer)
            title_page = title_pdf.getPage(0)
            first_page = input_pdf.getPage(0)
            first_page.mergePage(title_page)
            output_pdf.addPage(first_page)
            for page_num in range(1, input_pdf.getNumPages()):
                output_pdf.addPage(input_pdf.getPage(page_num))
            
            with open(output_pdf_path, 'wb') as output_pdf_file:
                output_pdf.write(output_pdf_file)

    def create_blank_pdf(self,output_path, page_size=A4):
        c = canvas.Canvas(output_path, pagesize=page_size)
        c.save()

    def merge_pdfs(self,pdf_list, output_path):
        pdf_writer = PdfFileWriter()

        for pdf_path in pdf_list:
            pdf_reader = PdfFileReader(pdf_path)
            for page_num in range(pdf_reader.numPages):
                page = pdf_reader.getPage(page_num)
                pdf_writer.addPage(page)
        
        with open(output_path, 'wb') as output_file:
            pdf_writer.write(output_file)

    def delete_files_with_prefix_excluding_keyword(self,directory, prefix, exclusion_keyword):
        """Delete all files in the directory starting with the specified prefix,
        excluding files that contain the specified exclusion keyword."""
        
        # Construct the pattern for files starting with the prefix
        pattern = os.path.join(directory, f"{prefix}*")
        
        # Find all files matching the pattern
        files_to_delete = glob.glob(pattern)
        
        for file_path in files_to_delete:
            # Get the file name from the path
            file_name = os.path.basename(file_path)
            
            # Check if the file name contains the exclusion keyword
            if exclusion_keyword not in file_name:
                try:
                    os.remove(file_path)  # Delete the file
                    print(f"Deleted file: {file_path}")
                except Exception as e:
                    print(f"Error deleting file {file_path}: {e}")
            else:
                print(f"Skipped file: {file_path} (contains exclusion keyword)")

    def render_to_file(self,template_src, context_dict={}, file_name = 'abc'):
        template = get_template(template_src)
        html  = template.render(context_dict)
        file_path = os.path.join(os.path.abspath(os.path.dirname("__file__")),"media/converted", file_name)
        with open(file_path, 'wb') as pdf:
            pisa.pisaDocument(BytesIO(html.encode("UTF-8")), pdf)
        return file_name

    def render_to_file_pdfkit(self, template_src, context_dict={}, file_name='abc',file_no = 0, pdf_type = ''):
        try:
            # Load and render the template with context
            template = get_template(template_src)
            html = template.render(context_dict)
        except TemplateDoesNotExist:
            raise FileNotFoundError(f"Template '{template_src}' does not exist.")
        except TemplateSyntaxError as e:
            raise ValueError(f"Template syntax error in '{template_src}': {e}")
        except Exception as e:
            raise RuntimeError(f"Error rendering template '{template_src}': {e}")

        # Define the file path where the PDF will be saved
        file_path = os.path.join(os.path.abspath(os.path.dirname("__file__")),"media/converted", file_name)

        # Ensure the media/converted directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Configure pdfkit to use wkhtmltopdf
        config = pdfkit.configuration(wkhtmltopdf='/usr/local/bin/wkhtmltopdf')
        #config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')
        import tempfile, datetime
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as temp:
                temp.write(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                </head>
                <body>
                        <center>
                        <table>
                        <tbody>
                        <tr>
                                    <td style="color:blue;font-weight:bold;font-size: 24px;text-align:center;">Indian Railways</td>
                            </tr>
                        <tr><td style="color:black;font-weight:bold;font-size: 16px;text-align:center;">{pdf_type}</td></tr>
                            </tbody>
                        </table>
                        </center>
                        <p style="margin-top:0;padding-top:0;color:grey;font-size: 12px;text-align:right;">File Number:- {file_no}
                        <br> Generated on:- {created_on}
                        </p>
                </body>
                </html>
                """)
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.85in',
            'margin-bottom': '0.5in',
            'margin-right': '0.5in',
            'margin-left': '0.5in',
            'encoding': "UTF-8",
            'header-html': temp.name,
            'footer-center': "Page [page] of [topage]",
            'footer-font-size': "6",
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ],
            'enable-local-file-access': False,
            'no-outline': None
        }


        try:
            pdfkit.from_string(html, file_path, configuration=config, options=options)
        except Exception as e:
            raise RuntimeError(f"Error generating PDF: {e}")
        temp.close()
        return file_path

    def render_to_file_pdfkit1(self, template_src, context_dict={}, file_name='abc',file_no = 0, pdf_type = ''):
        try:
            # Load and render the template with context
            template = get_template(template_src)
            html = template.render(context_dict)
        except TemplateDoesNotExist:
            raise FileNotFoundError(f"Template '{template_src}' does not exist.")
        except TemplateSyntaxError as e:
            raise ValueError(f"Template syntax error in '{template_src}': {e}")
        except Exception as e:
            raise RuntimeError(f"Error rendering template '{template_src}': {e}")

        # Define the file path where the PDF will be saved
        file_path = os.path.join(os.path.abspath(os.path.dirname("__file__")),"media/converted1", file_name)

        # Ensure the media/converted directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Configure pdfkit to use wkhtmltopdf
        config = pdfkit.configuration(wkhtmltopdf='/usr/local/bin/wkhtmltopdf')
        #config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')

        import tempfile, datetime
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as temp:
                temp.write(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                </head>
                <body>
                        <center>
                        <table>
                        <tbody>
                        <tr>
                                    <td style="color:blue;font-weight:bold;font-size: 24px;text-align:center;">Indian Railways</td>
                            </tr>
                        <tr><td style="color:black;font-weight:bold;font-size: 16px;text-align:center;">{pdf_type}</td></tr>
                            </tbody>
                        </table>
                        </center>
                        <p style="margin-top:0;padding-top:0;color:grey;font-size: 12px;text-align:right;">File Number:- {file_no}
                        <br> Generated on:- {created_on}
                        </p>
                </body>
                </html>
                """)
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.85in',
            'margin-bottom': '0.5in',
            'margin-right': '0.5in',
            'margin-left': '0.5in',
            'encoding': "UTF-8",
            'header-html': temp.name,
            'footer-center': "Page [page] of [topage]",
            'footer-font-size': "6",
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ],
            'enable-local-file-access': False,
            'no-outline': None
        }


        try:
            pdfkit.from_string(html, file_path, configuration=config, options=options)
        except Exception as e:
            raise RuntimeError(f"Error generating PDF: {e}")
        temp.close()
        return file_path

    def render_to_file_pdfkit2(self, template_src, context_dict={}, file_name='abc',file_no = 0, pdf_type = ''):
        try:
            # Load and render the template with context
            template = get_template(template_src)
            html = template.render(context_dict)
        except TemplateDoesNotExist:
            raise FileNotFoundError(f"Template '{template_src}' does not exist.")
        except TemplateSyntaxError as e:
            raise ValueError(f"Template syntax error in '{template_src}': {e}")
        except Exception as e:
            raise RuntimeError(f"Error rendering template '{template_src}': {e}")

        # Define the file path where the PDF will be saved
        file_path = os.path.join(os.path.abspath(os.path.dirname("__file__")),"media/converted1", file_name)

        # Ensure the media/converted directory exists
        os.makedirs(os.path.dirname(file_path), exist_ok=True)

        # Configure pdfkit to use wkhtmltopdf
        config = pdfkit.configuration(wkhtmltopdf='/usr/local/bin/wkhtmltopdf')
        #config = pdfkit.configuration(wkhtmltopdf='C:\\Program Files\\wkhtmltopdf\\bin\\wkhtmltopdf.exe')

        import tempfile, datetime
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')
        with tempfile.NamedTemporaryFile(delete=False, suffix='.html', mode='w', encoding='utf-8') as temp:
                temp.write(f"""
                <!DOCTYPE html>
                <html>
                <head>
                    <meta charset="UTF-8">
                </head>
                <body>
                        <center>
                        <table>
                        <tbody>
                        <tr>
                                    <td style="color:blue;font-weight:bold;font-size: 24px;text-align:center;">Indian Railways</td>
                            </tr>
                        <tr><td style="color:black;font-weight:bold;font-size: 16px;text-align:center;">{pdf_type}</td></tr>
                            </tbody>
                        </table>
                        </center>
                        <p style="margin-top:0;padding-top:0;color:grey;font-size: 12px;text-align:right;">
                        Generated on:- {created_on}
                        </p>
                </body>
                </html>
                """)
        
        options = {
            'page-size': 'A4',
            'margin-top': '0.85in',
            'margin-bottom': '0.5in',
            'margin-right': '0.5in',
            'margin-left': '0.5in',
            'encoding': "UTF-8",
            'header-html': temp.name,
            'footer-center': "Page [page] of [topage]",
            'footer-font-size': "6",
            'custom-header': [
                ('Accept-Encoding', 'gzip')
            ],
            'enable-local-file-access': False,
            'no-outline': None
        }


        try:
            pdfkit.from_string(html, file_path, configuration=config, options=options)
        except Exception as e:
            raise RuntimeError(f"Error generating PDF: {e}")
        temp.close()
        return file_path

####  with library encrypt hindi font also

class encryption_decription:
    def encryptWithAesEinspect(self,data):
        key = 'AAAAAAAAAAAAAAAA'
        iv =  'BBBBBBBBBBBBBBBB'.encode('utf-8')
        data= pad(data.encode(),16)
        cipher = AES.new(key.encode('utf-8'),AES.MODE_CBC,iv)
        encrypted = base64.b64encode(cipher.encrypt(data))
        return encrypted.decode("utf-8", "ignore")

    def decryptWithAesEinspect(self,enc):
        key = 'AAAAAAAAAAAAAAAA'
        iv =  'BBBBBBBBBBBBBBBB'.encode('utf-8')
        enc = base64.b64decode(enc)
        cipher = AES.new(key.encode('utf-8'), AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(enc),16)
        return decrypted.decode("utf-8", "ignore")


from decimal import Decimal

def convert_decimals_to_strings(d):
    new_dict = {}
    for k, v in d.items():
        if isinstance(v, dict):
            new_dict[k] = convert_decimals_to_strings(v)  # Recursively handle nested dictionaries
        elif isinstance(v, tuple):
            new_dict[k] = tuple(str(x) if isinstance(x, Decimal) else x for x in v)  # Convert tuple elements
        elif isinstance(v, Decimal):
            new_dict[k] = str(v)  # Convert Decimal to string
        else:
            new_dict[k] = v  # Keep other types unchanged
    return new_dict


def mnp_preview_pdf(request, *args, **kwargs):
    import datetime
    
    pdf_type = request.GET.get('type')
    MAVPRSLNO = request.GET.get('slno')
    if pdf_type == 'D':
        proposal = MEM_PRSLN_DRAFT.objects.filter(MAVPRSLNO = MAVPRSLNO).all()
        slno = proposal[0].MAVPRSLNO
        rep_add = proposal[0].MAVADDNRPLC
        location = list(railwayLocationMaster.objects.filter(rly_unit_code = proposal[0].MAVRLYCODE_id).values('location_code','location_type'))
        division, railway = find_div_railway(proposal[0].MAVRLYCODE_id)
        cost = list(MED_PRSLCOST_DRAFT.objects.filter(MANPRSNNO = slno).values().order_by('MANCPCODE'))
        cost_parameter = ['Optional Accessories','Excise Duty','CST','Freight','Insurance',
                            'Contingencies','Mech.Sub Estimate','Electrical Sub Estimate','Eng Sub Estimate',
                            'S % T Sub Estimate','Other Charges','D&G','GST']
        cost_data = []
        for i in range(1, len(cost_parameter) + 1):
            filtered_data = list(custom_filter(lambda x : x['MANCPCODE'] == i , cost))
            if len(filtered_data):
                cost_data.append({'par':cost_parameter[i-1], 'unit':filtered_data[0]['MANCPAMNT'], 'value':filtered_data[0]['MANCPPER']})
            else:
                cost_data.append({'par':cost_parameter[i-1], 'unit':0, 'value':0})
        just = list(MED_PRSLJSTN_DRAFT.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MATJSFN'))
        encrpt = encryption_decription()
        if len(just) > 0:
            try:
                just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
            except:
                just = just[0]['MATJSFN']
        else:
            just = ''
        replacement = list(MED_ASSTRGNN_DRAFT.objects.filter(MAVPRSLNO = slno).values('MAVASSTCODE','MAIYEARPURC','MAVITEMCODE','MAIEXPLIFE','MAVDESC','MAICOST'))
        if len(replacement):
            catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = replacement[0]['MAVASSTCODE'])
            replacement[0].update({'MAVASSTCODE':catg_id.MAV_ITEM_CODE})
        rep_just = list(MED_PRSLRPLCDTLS_DRAFT.objects.filter(MAVPRSLNO = slno).values('MANSIFTNO','MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL',
                                                                                'MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB'))
        addition = list(MED_PRSLRORN_DRAFT.objects.filter(MAVPRSLNO = slno).values())
        add = ''

        rorType = '1'
        ror_attacch = None
        if len(addition) > 0:
            encrpt = encryption_decription()
            if addition[0]['RORREQUIRED'] == 'N':
                rorType = '1'
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
                except:
                    add = addition[0]['MATRORDETL']
            else:
                rorType = '2'
                if addition[0]['RORPDFNAME'] != None:
                    ror_attacch = addition[0]['RORPDFNAME']
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['RORREMARKS'])
                except:
                    add = addition[0]['RORREMARKS']
        
        # if len(addition) > 0:
        #     try:
        #         add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
        #     except:
        #         add = addition[0]['MATRORDETL']
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')
        #### get uploaded file 
        file_obj = FileFormatter()
        uploaded_file = []
        all_file_uploaded = list(MED_PRSLUPLDFILE_DRAFT.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MAVPDFNAME','MAVORGPDFNAME','MADUPLDDATETIME').order_by('MADUPLDDATETIME'))
        
        username = request.user.MAV_username
        merge_list = []
        directory = "media/converted"  # Change this to your directory
        prefix = username
        excluding_keyword = 'final'
        
        attac_count = 1
        for i in all_file_uploaded:
            up_file = i['MAVORGPDFNAME']
            up_relative_path = f'media/{up_file}'
            up_abs_path = os.path.abspath(up_relative_path)
            file_type = file_obj.determine_file_type(up_abs_path)
            if file_type != 'Unknown':
                try:
                    if file_type == 'PDF':
                        folder_abs_path = os.path.abspath('media/converted')
                        blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                        file_obj.create_blank_pdf(blank_abs_path)
                        title = f'Attachement-{attac_count}'
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                        merge_list.append(out_abs_path)

                    elif file_type == 'Image':
                        title = f'Attachement-{attac_count}'
                        folder_abs_path = os.path.abspath('media/converted')
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                        merge_list.append(out_abs_path)

                    uploaded_file.append(i)
                    attac_count += 1
                except:
                    pass
        attac_count = 0
        if ror_attacch != None:
            up_file = ror_attacch
            up_relative_path = f'media/{up_file}'
            up_abs_path = os.path.abspath(up_relative_path)
            file_type = file_obj.determine_file_type(up_abs_path)
            if file_type != 'Unknown':
                try:
                    if file_type == 'PDF':
                        folder_abs_path = os.path.abspath('media/converted')
                        blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                        file_obj.create_blank_pdf(blank_abs_path)
                        title = f'Annexure-{attac_count}'
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                        merge_list.append(out_abs_path)

                    elif file_type == 'Image':
                        title = f'Annexure-{attac_count}'
                        folder_abs_path = os.path.abspath('media/converted')
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                        merge_list.append(out_abs_path)     
                except:
                    pass 
        proposal_type = 'Draft MNP Proposal(Preview Only)'
        
        context = {
            # 'file_name':file_name,
            'rorType':rorType,
            'attac_count':attac_count,
            'created_on':created_on,
            'proposal':proposal,
            'slno':slno,
            'division':division,
            'railway':railway,
            'location':location,
            'cost_data':cost_data,
            'just':just,
            'rep_add':rep_add,
            'replacement':replacement,
            'addition':addition,
            'rep_just':rep_just,
            'uploaded_file':uploaded_file,
            'add':add,
        }
        file_no = 'xxxxx'
        folder_abs_path = os.path.abspath('media/converted')
        file_name = f'{username}_main.pdf'
        file_obj.render_to_file_pdfkit('mnp_document_pdf.html', context, file_name, file_no, proposal_type)
        file_name = f'{folder_abs_path}/{file_name}'
        file_name = os.path.abspath(file_name)

        file_name = os.path.abspath(file_name)


        merge_list.insert(0,file_name)

        pdf_path = f'{folder_abs_path}/{username}_final.pdf'
        file_obj.merge_pdfs(merge_list, pdf_path)
        file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, excluding_keyword)

        
        with open(pdf_path, 'rb') as pdf_file:
            pdf_content = pdf_file.read()
            response = HttpResponse(pdf_content, content_type='application/pdf')        
            response['Content-Disposition'] = 'inline; filename="file.pdf"'
            return response
    

    else:
        proposal = MEM_PRSLN.objects.filter(MAVPRSLNO = MAVPRSLNO).all()
        slno = proposal[0].MAVPRSLNO
        rep_add = proposal[0].MAVADDNRPLC
        location = list(railwayLocationMaster.objects.filter(rly_unit_code = proposal[0].MAVRLYCODE_id).values('location_code','location_type'))
        division, railway = find_div_railway(proposal[0].MAVRLYCODE_id)
        cost = list(MED_PRSLCOST.objects.filter(MANPRSNNO = slno).values().order_by('MANCPCODE'))
        cost_parameter = ['Optional Accessories','Excise Duty','CST','Freight','Insurance',
                            'Contingencies','Mech.Sub Estimate','Electrical Sub Estimate','Eng Sub Estimate',
                            'S % T Sub Estimate','Other Charges','D&G','GST']
        cost_data = []
        for i in range(1, len(cost_parameter) + 1):
            filtered_data = list(custom_filter(lambda x : x['MANCPCODE'] == i , cost))
            if len(filtered_data):
                cost_data.append({'par':cost_parameter[i-1], 'unit':filtered_data[0]['MANCPAMNT'], 'value':filtered_data[0]['MANCPPER']})
            else:
                cost_data.append({'par':cost_parameter[i-1], 'unit':0, 'value':0})
        just = list(MED_PRSLJSTN.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MATJSFN'))
        encrpt = encryption_decription()
        if len(just) > 0:
            try:
                just = encrpt.decryptWithAesEinspect(just[0]['MATJSFN'])
            except:
                just = just[0]['MATJSFN']
        else:
            just = ''
        replacement = list(MED_ASSTRGNN.objects.filter(MAVPRSLNO = slno).values('MAVASSTCODE','MAIYEARPURC','MAVITEMCODE','MAIEXPLIFE','MAVDESC','MAICOST'))
        if len(replacement):
            catg_id = MEM_ITEMMSTN.objects.get(MAV_ITEM_CODE = replacement[0]['MAVASSTCODE'])
            replacement[0].update({'MAVASSTCODE':catg_id.MAV_ITEM_CODE})
        rep_just = list(MED_PRSLRPLCDTLS.objects.filter(MAVPRSLNO = slno).values('MANSIFTNO','MAVJOBLOAD','MAVWORKLOAD','MAVTOTLSMLRMACN','MAVCAPSHRTFALL',
                                                                                'MAVBREKDWNFRQN','MAVBREKDWNVLUE','MAVACCRRQRM','MAACTLCAPB'))
        addition = list(MED_PRSLRORN.objects.filter(MAVPRSLNO = slno).values())
        add = ''
        rorType = '1'
        ror_attacch = None
        if len(addition) > 0:
            encrpt = encryption_decription()
            if addition[0]['RORREQUIRED'] == 'N':
                rorType = '1'
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['MATRORDETL'])
                except:
                    add = addition[0]['MATRORDETL']
            else:
                rorType = '2'
                if addition[0]['RORPDFNAME'] != None:
                    ror_attacch = addition[0]['RORPDFNAME']
                try:
                    add = encrpt.decryptWithAesEinspect(addition[0]['RORREMARKS'])
                except:
                    add = addition[0]['RORREMARKS']
        
        curr_date = datetime.datetime.now()
        created_on = curr_date.strftime('%d-%m-%Y')

        #### get uploaded file 
        file_obj = FileFormatter()
        uploaded_file = []
        all_file_uploaded = list(MED_PRSLUPLDFILE.objects.filter(MAVPRSLNO = slno, DLTFLAG = False).values('MAVPDFNAME','MAVORGPDFNAME','MADUPLDDATETIME').order_by('MADUPLDDATETIME'))
        attac_count = 1
        username = request.user.MAV_username
        merge_list = []
        directory = "media/converted"  # Change this to your directory
        prefix = username
        excluding_keyword = 'final'
        for i in all_file_uploaded:
            up_file = i['MAVORGPDFNAME']
            up_relative_path = f'media/{up_file}'
            up_abs_path = os.path.abspath(up_relative_path)
            file_type = file_obj.determine_file_type(up_abs_path)
            if file_type != 'Unknown':
                try:
                    if file_type == 'PDF':
                        folder_abs_path = os.path.abspath('media/converted')
                        blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                        file_obj.create_blank_pdf(blank_abs_path)
                        title = f'Attachement-{attac_count}'
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                        merge_list.append(out_abs_path)

                    elif file_type == 'Image':
                        title = f'Attachement-{attac_count}'
                        folder_abs_path = os.path.abspath('media/converted')
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                        merge_list.append(out_abs_path)

                    uploaded_file.append(i)
                    attac_count += 1
                except:
                    pass
        attac_count = 0
        if ror_attacch != None:
            up_file = ror_attacch
            up_relative_path = f'media/{up_file}'
            up_abs_path = os.path.abspath(up_relative_path)
            file_type = file_obj.determine_file_type(up_abs_path)
            if file_type != 'Unknown':
                try:
                    if file_type == 'PDF':
                        folder_abs_path = os.path.abspath('media/converted')
                        blank_abs_path = f'{folder_abs_path}/{username}_0.pdf'
                        file_obj.create_blank_pdf(blank_abs_path)
                        title = f'Annexure-{attac_count}'
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.add_title_to_first_page(up_abs_path, out_abs_path, title)
                        merge_list.append(out_abs_path)

                    elif file_type == 'Image':
                        title = f'Annexure-{attac_count}'
                        folder_abs_path = os.path.abspath('media/converted')
                        out_abs_path = f'{folder_abs_path}/{username}_{attac_count}.pdf'
                        file_obj.convert_image_to_pdf(up_abs_path,out_abs_path,title)
                        merge_list.append(out_abs_path)     
                except:
                    pass 
        
        if  proposal[0].form_status == 0:
            # slno = proposal[0].MAVDRFTPRSLNO
            proposal_type = 'Draft MNP Proposal(Preview Only)'
        else:
            proposal_type = 'MNP Proposal(Preview Only)'
        context = {
            # 'file_name':file_name,
            'rorType':rorType,
            'attac_count':attac_count,
            'created_on':created_on,
            'proposal':proposal,
            'slno':slno,
            'division':division,
            'railway':railway,
            'location':location,
            'cost_data':cost_data,
            'just':just,
            'rep_add':rep_add,
            'replacement':replacement,
            'addition':addition,
            'rep_just':rep_just,
            'uploaded_file':uploaded_file,
            'add':add,
        }
        file_no = 'xxxxx'
        folder_abs_path = os.path.abspath('media/converted')
        file_name = f'{username}_main.pdf'
        file_obj.render_to_file_pdfkit('mnp_document_pdf.html', context, file_name, file_no, proposal_type)
        file_name = f'{folder_abs_path}/{file_name}'
        file_name = os.path.abspath(file_name)

        file_name = os.path.abspath(file_name)


        merge_list.insert(0,file_name)

        pdf_path = f'{folder_abs_path}/{username}_final.pdf'
        file_obj.merge_pdfs(merge_list, pdf_path)
        file_obj.delete_files_with_prefix_excluding_keyword(directory, prefix, excluding_keyword)

        
        with open(pdf_path, 'rb') as pdf_file:
            pdf_content = pdf_file.read()
            response = HttpResponse(pdf_content, content_type='application/pdf')        
            response['Content-Disposition'] = 'inline; filename="file.pdf"'
            return response


list_node, list_arrow, global_count = [], [], None
def default_file_movement(request):
    all_type_id = workflow_type.objects.values('type_id','type_name')
    type_id = None
    if request.method == 'GET':
        context = {
        'all_type_id':all_type_id,
        'type_id':type_id,
        'list_node':json.dumps([]),
        'list_arrow':json.dumps([]),
        'scroll':'NO'
        }
        return render(request, 'default_movement.html', context)

       
    elif request.method == 'POST':
        type_id = int(request.POST.get('select-type'))    
    global global_count
    global list_arrow
    global list_node
    global_count = 1
    list_arrow = []
    list_node = []
    user_id = request.user.MAV_userid
    desig = request.user.MAV_userdesig
    rly_details = railwayLocationMaster.objects.filter(rly_unit_code = request.user.MAV_rlycode_id).first()
    rly = rly_details.location_code
    rly_type = rly_details.location_type
    
    list_node.append({'id': 1, 
         'label': desig, 
         'title': desig, 
         'color':  'lightgreen',
         'rly': str(rly)+'/'+str(rly_type),
         'shape': 'box',
         'level' : 0
         })
    

    
    find_file_movement_internal(user_id ,type_id, desig, 0)
    context = {
        'all_type_id':all_type_id,
        'type_id':type_id,
        'list_node':json.dumps(list_node),
        'list_arrow':json.dumps(list_arrow),
        'scroll':'YES'
    }
    return render(request, 'default_movement.html', context)


def find_file_movement_internal(user_id, type_id, from_desig, level):
    global global_count
    global list_arrow
    global list_node
    d1 = list(workflow_internal_forward.objects.filter(by_user = user_id, type_id = type_id).values('to_user','to_user_id__MAV_userdesig','to_user_id__MAV_rlycode'))
    d2 = list(workflow_external_forward.objects.filter(by_user = user_id, type_id = type_id).values('to_user','to_user_id__MAV_userdesig','to_user_id__MAV_rlycode'))
    d1.extend(d2)
    level += 1
    for i in d1:
        user_id = i['to_user']
        desig = i['to_user_id__MAV_userdesig']
        code = i['to_user_id__MAV_rlycode']
        rly_details = railwayLocationMaster.objects.filter(rly_unit_code = code).first()
        rly = rly_details.location_code
        rly_type = rly_details.location_type
        is_present = any(item['title'] == desig for item in list_node)
        if not is_present:
            global_count += 1
            list_node.append({'id': global_count, 
                     'label': desig, 
                     'title': desig, 
                     'color':  'orange',
                     'rly': str(rly)+'/'+str(rly_type),
                     'shape': 'box',
                     'level' : level})
        to_id = next((item['id'] for item in list_node if item['title'] == desig), None)
        from_id = next((item['id'] for item in list_node if item['title'] == from_desig), None)
        if to_id != None and to_id != None:
            dict_a = {'from': from_id, 'to': to_id}
            if not dict_a in list_arrow:
                list_arrow.append(dict_a)
                find_file_movement_internal(user_id , type_id, desig, level)













#######################################   Login from Irpsm

def generate_unique_token():
    import uuid
    while True:
        token = ''.join(str(uuid.uuid4()) for _ in range(10))[:256]
        if not IrpsmLoginMaster.objects.filter(mu_token=token).exists():
            return token

def login_from_icms(request):
    from datetime import datetime
    isTrue = False
    token = request.GET.get("token")
    if not token:
        return render(request, "z_missing_token.html", status=400)
    try:
        login_master_user = IrpsmLoginMaster.objects.get(irpsm_token=token)

        if login_master_user.irpsm_token_validity and login_master_user.irpsm_token_validity < datetime.now():
            return render(request, "z_token_expired.html", status=401)

        # if TokenLog.objects.filter(token=token, action="login_from_irpsm").exists():
        #     return render(request, "z_token_already_used.html", status=403)
        
        
        users = MEM_usersn.objects.exclude(hrms__isnull = True).filter(hrms=login_master_user.hrmsid)
        if not users.exists():
            return render(request, "z_user_not_mapped.html", {"mu_username": login_master_user.loginid})
        else:
            user = users.first()
        
        # login_master_user.irpsm_token = None
        # login_master_user.irpsm_token_validity = None
        # login_master_user.save()


        ############  code added to manage session and login history
        user.backend = 'mnpapp.backends.CustomAuthBackend'
        login(request, user)
        session_key = request.session.session_key
        session_mgmt.objects.update_or_create(
            defaults = {'session_key' : session_key},  
            username = request.user
        )

        user_agent_string = request.META.get('HTTP_USER_AGENT', 'Unknown')
        browser_details, os_details = extract_browser_and_os(user_agent_string)
        client_ip = get_client_ip(request)
        login_history.objects.create(
            username = request.user,session_key = session_key,browser_type = browser_details,os_type = os_details,ip_address = client_ip, userlvlcode = request.user.MAV_userlvlcode_id
        )
        pref = list(MED_userprsninfo.objects.filter(MAV_userid = user.MAV_userid).values())
        if len(pref) ==0:
            preference = 'M'
        else:
            preference = pref[0]['preference']
        request.session["username"] = str(request.user)
        request.session["department"] = user.MAV_deptcode.MACDEPTCODE
        request.session["rly"] = user.MAV_rlycode.rly_unit_code
        request.session["division"] = user.MAV_divcode_id
        request.session["userrole"] = request.user.MAV_userlvlcode_id
        request.session["nav"] = custommenu2(request.user.MAV_userlvlcode_id, request.user.MAV_userid)

        TokenLog.objects.create(
            token=token,
            hrmsid=login_master_user.hrmsid,
            action="login_from_irpsm",
            source_ip = client_ip
        )
        return redirect('user_personalinfo')
    except IrpsmLoginMaster.DoesNotExist:
        return render(request, "z_invalid_token.html", status=404)


from django.views.decorators.csrf import csrf_exempt
@csrf_exempt
def request_user_mapping(request):
    from datetime import datetime
    if request.method == "POST":
        hrms_id = request.POST.get("requested_id")
        user_id = request.POST.get("login_id")
        if hrms_id and len(hrms_id) == 6 and user_id:
            try:
            
                login_master_user = IrpsmLoginMaster.objects.get(loginid = user_id)
                try:
                    hrms_exists = HRMS.objects.get(hrms_employee_id = hrms_id)
                except:
                    messages.error(request,"HRMS Id is not valid, enter other id or contact Admin...")
                    return render(request, "z_user_not_mapped.html", {"mu_username": login_master_user.loginid})
                
                if login_master_user.irpsm_token_validity and login_master_user.irpsm_token_validity < datetime.now():
                    return render(request, "z_token_expired.html", status=401)
                login_master_user.hrmsid = hrms_id
                login_master_user.save()
                users = MEM_usersn.objects.exclude(hrms__isnull = True).filter(hrms=login_master_user.hrmsid)
                if not users.exists():
                    return render(request, "z_hrms_not_mapped.html", {"hrmsid": login_master_user.hrmsid})
                else:
                    user = users.first()
                ############  code added to manage session and login history
                user.backend = 'mnpapp.backends.CustomAuthBackend'
                login(request, user)
                session_key = request.session.session_key
                session_mgmt.objects.update_or_create(
                    defaults = {'session_key' : session_key},  
                    username = request.user
                )

                user_agent_string = request.META.get('HTTP_USER_AGENT', 'Unknown')
                browser_details, os_details = extract_browser_and_os(user_agent_string)
                client_ip = get_client_ip(request)
                login_history.objects.create(
                    username = request.user,session_key = session_key,browser_type = browser_details,os_type = os_details,ip_address = client_ip, userlvlcode = request.user.MAV_userlvlcode_id
                )
                pref = list(MED_userprsninfo.objects.filter(MAV_userid = user.MAV_userid).values())
                if len(pref) ==0:
                    preference = 'M'
                else:
                    preference = pref[0]['preference']
                request.session["username"] = str(request.user)
                request.session["department"] = user.MAV_deptcode.MACDEPTCODE
                request.session["rly"] = user.MAV_rlycode.rly_unit_code
                request.session["division"] = user.MAV_divcode_id
                request.session["userrole"] = request.user.MAV_userlvlcode_id
                request.session["nav"] = custommenu2(request.user.MAV_userlvlcode_id, request.user.MAV_userid)

                TokenLog.objects.create(
                    token=login_master_user.irpsm_token,
                    hrmsid=login_master_user.hrmsid,
                    action="login_from_irpsm",
                    source_ip = client_ip
                )
                return redirect('user_personalinfo')
            except:
                return render(request, "z_error.html", status=500)
    return render(request, "z_error.html",datetime,  status=500)



def login_to_icms(request):
    try:
        from datetime import  datetime,timedelta
        loginid = request.session.get("username")  # or however you're tracking the logged-in user
        client_ip = get_client_ip(request)
        if not loginid:
            return HttpResponseRedirect('/')
        users = MEM_usersn.objects.get(MAV_username = loginid)   
        try:
            login_master_user = IrpsmLoginMaster.objects.get(hrmsid=users.hrms)
            
        except IrpsmLoginMaster.DoesNotExist:
            return render(request, "z_hrms_not_mapped_icms.html", {"hrmsid": users.hrms})


        token = generate_unique_token()
        login_master_user.mu_token = token
        login_master_user.mu_token_validity = datetime.now() + timedelta(minutes=10)
        login_master_user.save()
        TokenLog.objects.create(
            token = token,
            hrmsid = users.hrms,  # or use loginid if user is not FK
            action = "login_to_irpsm",
            source_ip=client_ip
        )
        session_key = request.session.session_key
        login_history.objects.filter(username = request.user,session_key = session_key).update(logout_date_time = datetime.now())
        logout(request)
        
        return render(request, "z_redirect_to_icms.html",{'token':token},  status=200)
    except:
        return render(request, "z_error.html",  status=500)
    
#<!-----start nlp chatbot-------->
from pathlib import Path
from collections import defaultdict
from typing import Dict, List, Tuple

from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login, logout
from django.http import JsonResponse, HttpRequest

from rapidfuzz import process, fuzz


BASE_DIR = Path(__file__).resolve().parent.parent
QA_PATH = BASE_DIR / 'qa.txt'


def load_faq() -> Tuple[Dict[str, Dict[str, str]], Dict[str, str]]:
    categories: Dict[str, Dict[str, str]] = defaultdict(dict)
    flat_q_to_a: Dict[str, str] = {}

    if not QA_PATH.exists():
        return {}, {}

    with QA_PATH.open('r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split('\t')
            if len(parts) < 3:
                continue

            category, question, answer = parts[0].strip(), parts[1].strip(), parts[2].strip()
            if category.lower() in {"category", "general"}:
                continue

            categories[category][question] = answer
            flat_q_to_a[question.lower()] = answer

    return categories, flat_q_to_a


def get_faq_data():
    return load_faq()


def chatbot_categories(request: HttpRequest):
    categories, _ = get_faq_data()
    return JsonResponse({'categories': sorted(categories.keys())})

def chatbot_questions(request: HttpRequest, category: str):
    categories, _ = get_faq_data()
    questions = sorted(categories.get(category, {}).keys())
    return JsonResponse({'category': category, 'questions': questions})


def chatbot_answer(request: HttpRequest):
    user_query = request.GET.get('q', '').strip()
    if not user_query:
        return JsonResponse({'answer': ''})

    # Reload data every request so updated qa.txt reflects immediately
    categories, flat_qa = load_faq()

    # Exact match first
    answer = flat_qa.get(user_query.lower())
    if not answer and flat_qa:
        best_match, score, _ = process.extractOne(user_query, list(flat_qa.keys()), scorer=fuzz.token_sort_ratio)
        if score >= 60:
            answer = flat_qa.get(best_match)

    if not answer:
        return JsonResponse({'answer': "Sorry, I don’t have an answer for that yet."})

    # --- Smart media detection ---
    if "::" in answer:
        parts = [p.strip() for p in answer.split("::", 1)]
        text = parts[0]
        media = parts[1] if len(parts) > 1 else ""
        if media.lower().endswith((".png", ".jpg", ".jpeg", ".gif")):
            answer = f'{text}<br><img src="{media}" alt="Image" style="max-width:100%; border-radius:8px; margin-top:8px;">'
        elif media.lower().endswith((".pdf",)):
            answer = f'{text}<br><a href="{media}" target="_blank" style="color:#4f46e5;">📄 Open PDF</a>'
        elif media.lower().startswith("http"):
            answer = f'{text}<br><a href="{media}" target="_blank" style="color:#4f46e5;">🔗 Open Link</a>'
        else:
            answer = f'{text}<br>{media}'

    return JsonResponse({'answer': answer})


# ---------- END ----------