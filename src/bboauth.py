#!/usr/bin/python3
#
#
# ====================================================
#               Python Blogger REST API  v3
# ====================================================
#
#
# Author:
#           Suraj Singh Bisht
#           surajsinghbisht054@gmail.com
#           www.bitforestinfo.com
#           www.blaregroup.com
#
#
# This Script Going To Help You, To Setup New Google Project To Use Blogger API
#
#
#
#
# import module modules
import webbrowser

# google Console Useful URLS 
GoogleConsole = "https://console.developers.google.com/apis/dashboard"
GoogleOauthDocumentation = "https://developers.google.com/identity/protocols/OAuth2"
GoogleConsole_Oauth_Consent = "https://console.developers.google.com/apis/credentials/consent"
GoogleConsole_Oauth_Credentails = "https://console.developers.google.com/apis/credentials"
BloggerConsole = "https://developers.google.com/blogger/docs/3.0/using"
BloggerConsole_CreateProjectSection = "#AboutAuthorization"


# Set Scope To Other
firstnote = """
    # ==========================================================
    #......Welcome Google OAuth 2.0 API Generator Helper.......#        
    #.............v0.1..By Surajsinghbisht054@gmail.com........#         
    # ==========================================================

    [+] Read All Instructions Carefully. 

    - I'm going to help you, To Generate OAuth Token Key Through Google Console.
    
    - This Script Will Automatically Open New Tab In Your Browser.

    - Read Instruction, Perform And Get Back To This Script.
     
    - First, If You Want Some More Information About OAuth 2.0, 

[=] Check Browser New Tab : {}
"""

second_note = """
    
    - Start By Creating A New Project Called 'BloggerAuto'.
    - You Have To Create Project Into Google Console.

[=] Click Browser New Tab : {}
"""


third_note = """
    - After Creating Project, You Have to Fill Some Useful Information,
    - Related To Your Newly Created Project.

    [+] Fill These Feilds.
        - Application Name     : Anything
        - Support Email        : Your Email
        - Scope For Google API :
            Add Scope ./auth/blogger

    Now, Save It

[=] Check Browser : {}
"""

fourth_note = """
    - Now, Time To Create New OAuth Credentials.
    - Go To Dashboard, Click Create Crediantials and 
    - Select OAuth Client ID.

[=] Check Browser : {}
"""

def main():

    print(firstnote.format(GoogleOauthDocumentation))
    webbrowser.open_new_tab(GoogleOauthDocumentation)
    input('Press Enter, If You have done it')
    

    print(second_note.format(GoogleConsole))
    webbrowser.open_new_tab(GoogleConsole)
    input('Press Enter, If You have done it')
    

    print(third_note.format(GoogleConsole_Oauth_Consent))
    webbrowser.open_new_tab(GoogleConsole_Oauth_Consent)
    input('Press Enter, If You have done it')
    

    print(fourth_note.format(GoogleConsole_Oauth_Credentails))
    webbrowser.open_new_tab(GoogleConsole_Oauth_Credentails)
    input('Press Enter, If You have done it')

    print("Now, Download JSON file Of OAuth Key. Download Button Available Bottom Right Side.")
    print("After Downloading, Rename File .oauth.crediantials.json and save in home folder")
    return


if __name__ == '__main__':
    main()
