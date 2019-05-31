#!/usr/bin/python3
#
#
# ====================================================
#               Python Blogger REST API  v2
# ====================================================
#
#
# Author :
#       Suraj Singh Bisht
#       surajsinghbisht054@gmail.com
#
#           www.bitforestinfo.com
#           github.com/surajsinghbisht054
#
#           www.blaregroup.com
#           github.com/blaregroup
#
#
#
# import modules
import requests
import os
import json
import urllib
import webbrowser
import socket
import base64

# ===================================================================
#               Default Configuration File
# ===================================================================
#

# default OAuth Json File Download From Google API Console. Check bbauth.py
HOME_PATH   = os.path.expanduser("~")		# Your Home Directory path
OAuthJsonFile   = os.path.join(HOME_PATH, ".oauth.crediantials.json") # Download And Add Your API Console Downloaded Json File path
OAuthToken  = os.path.join(HOME_PATH, ".blogger.secret.api.crediantials.json") # No Need to Change Anything Here, if you don't know what is this..! 


#
# https://developers.google.com/blogger/docs/3.0/performance#partial-response
#


# Oauthorization Generating Flow Handling Class
class OAuthurizationAccessTokenGenerator:
    '''
    Class To Automatically Handle Google Console JSON API Handler.
    
    '''
    def __init__(self, oauth_json, addr=('localhost', 8081)):
        self.addr = addr # Server Address To Use
        
        # if oauth json found
        if os.path.exists(oauth_json):
            try:
                self.auth_data = json.loads(open(oauth_json,'r').read())
            except Exception as e:
                print('[-] OAuth File is Not Correct.')
                print('[-] Want To Generate New Json, Execute bboauth.py')
                exit(0)

            self.check_json()
            print('[+] OAuth File Verified..')
            
        # if oauth json not found
        else:
            self.auth_data = None
            print("[-] OAuth Json Not Found.")
            exit(0)


    # http response header to dictionary object conversion
    def header_extractor(self, data):
        obj = {}
        data = data.decode('utf-8').split('\r\n')
        obj['request_type'] = data[0]
        for i in data[1:]:
            if i:
                a,b = i.split(': ', maxsplit=1)
                obj[a] = b
            else:
                break
        return obj

    def start_oauth_server(self, url):
        print(url)
        #return False
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(self.addr)
        s.listen(3)
        webbrowser.open_new_tab('http://{}:{}'.format(self.addr[0], self.addr[1]))

        # phase one,
        sock, addr = s.accept()
        print(sock.recvfrom(1024)[0])
        sock.send("HTTP/1.1 302 Found\r\nLocation: {}\r\n\r\n".format(url).encode('ascii'))
        sock.close()

        # phase two
        sock, addr = s.accept()
        response = self.header_extractor(sock.recvfrom(1024)[0])
        sock.send("HTTP/1.1 302 Found\r\n\r\n".encode('ascii'))
        sock.close()
        s.close()
        if "code" in response['request_type']:
            return urllib.parse.parse_qs(response['request_type'])['GET /?code'][0]
        return False
        
    # Get Oauthorization token
    def generate_authorization_token(self):
                
        # check client credentials
        if self.check_json():
            print('[+] OAuth File Verified..')    
            
            # request header
            oauth_header = {
                
                'redirect_uri':'http://{}:{}/'.format(self.addr[0], self.addr[1]),
                'prompt':'consent',
                'response_type':'code',
                'client_id':self.client_id,
                'scope':'https://www.googleapis.com/auth/blogger',
                'access':'offline',
            }

            oauth_window = "{}?{}".format(self.auth_uri, urllib.parse.urlencode(oauth_header))
            return self.start_oauth_server(oauth_window)
        
        return False


    # Check All Client Credientials
    def check_json(self):
        if self.auth_data:
            
            # check installed
            if "installed" in self.auth_data.keys():
                try:
                    self.client_id    = self.auth_data['installed']["client_id"]
                    self.project_id   = self.auth_data['installed']["project_id"]
                    self.auth_uri     = self.auth_data['installed']["auth_uri"]
                    self.token_url    = self.auth_data['installed']["token_uri"]
                    self.token_secret = self.auth_data['installed']["client_secret"]
                    return True
                except Exception as e:
                    print(e)
        print('[Error] Json file not good..')
        exit(0)
        return False



# OAuthentication Class To Handle All Operations
class OAuthentication:
    '''
        Class To handle OAuthentication Crediantials And Tokens Automatically.
        
    '''
    def __init__(self, oauth_client_json_file, db=OAuthToken, reset=False):
        
        self.db = OAuthToken # Credientails Storing Path
        
        # load json crediantials
        try:
            self.__dict__ = {**self.__dict__, **json.loads(open(oauth_client_json_file, 'r').read())['installed']}
        
        except Exception as e:
            print('[Error] Access OAuth Json File Failed.')
            print("[=] Possible Reason")
            print("[-] OAuth Json File Not Exists.")
            print("[-] Wrong OAuth Json File Path Passed Into Paramenter")
            print("[-] Bad Format Of OAuth Json File.")
            print("[-] Access Problem")
            print('[-] Or You Want To Generate New Json, Execute bboauth.py')
            raise e
            
        # OAuthorization Token        
        if not os.path.exists(OAuthToken):
            print("[+] Generating New OAuth Token File")
            obj = OAuthurizationAccessTokenGenerator(oauth_client_json_file)
            token = obj.generate_authorization_token()
            self.writeRecord(record={'authorization':token})
            
        if not self.checkRecord('authorization') or reset:
            print("[+] Generating New OAuth Token Key")
            obj = OAuthurizationAccessTokenGenerator(oauth_client_json_file)
            token = obj.generate_authorization_token()
            self.writeRecord(record={'authorization':token})
            
        if reset:
            self.request_tokens()
            
        self.access_token = self.checkRecord('access_token')
        self.refresh_token = self.checkRecord('refresh_token')
        
        # Read Record
    def readRecord(self):
        '''
        Read Record From API Crediantial JSON File and Return Dictionary Object
        '''
        obj = open(self.db, 'r').read()
        print(obj)
        # if noting available
        if len(obj)<5:
            self.writeRecord()
            return

        return json.loads(obj)
    
    def checkRecord(self, key):
        '''
        Check, if key is Available in JSON crediantial file.
        '''
        obj = self.readRecord()
        if not obj:
            return False
        if key in obj.keys():
            return obj[key]
        return False
    
    def updateRecord(self, key, value):
        '''
        Updat Record in JSON Crediantial File
        '''
        data = self.readRecord()
        data[key] = value
        obj = open(self.db, 'w')
        obj.write(json.dumps(data))
        obj.close()

        return
    
        # add Record
    def addRecord(self, record={}):
        '''
        Add Record in JSON crediantial file
        '''
        old = self.readRecord()
        new = {**old, **record}
        return self.writeRecord(record=new)
    
        # write Record
    def writeRecord(self, record={}):
        '''
        Write Record To JSON Crediantial File
        '''
        obj = open(self.db, 'w')
        obj.write(json.dumps(record))
        obj.close()
        return
    
    def request_tokens(self):
        '''
        Get New Authorization Access Token
        '''
        payload = {
            'code':self.checkRecord('authorization'),
            'redirect_uri':"http://localhost:8081/",
            'client_id':self.client_id,
            'client_secret':self.client_secret,
            'grant_type':'authorization_code',
        }

        req = requests.post(self.token_uri, data=payload)
        req.json
        return self.addRecord(record=req.json())
    
    def refresh(self):
        '''
        Get New Access Token
        '''
        payload = {
            'client_id':self.client_id,
            'client_secret':self.client_secret,
            'grant_type':'refresh_token',
            'refresh_token':self.readRecord()['refresh_token'],
        }
        req = requests.post(self.token_uri, data=payload)
        obj = req.json()['access_token']
        self.updateRecord('access_token', obj)
        self.access_token = obj
        return obj
    
    def reset(self):
        '''
        Reset Crediantials
        '''
        self.writeRecord()
        return
    
    


class Blogger:
    '''
        class to handle Blogging API. User Just need to create Object of this Class
        and Just Use its Functions To Manage Blog Content.
        
    '''
    def __init__(self, oauth, blogID='', blogURL="", verbose=True):
        self.verbose = verbose
        self.oauth = oauth
        #self.oauth.refresh()
        
        self.blogid = blogID
        self.blogurl = blogURL
        
        # Get ID
        if blogURL:
            self.blogid = self.getIdByUrl(blogURL)[1]['id']
            
            
    def getRequest(self, section , data={}):
        '''
        To Generate a blogger api GET request. 

        parameters
            Section   : pass section url. for more details, check usages in source code
            data      : Get Request Data feilds
        '''
        url = os.path.join("https://www.googleapis.com/blogger/v3/", section)
        if self.verbose:print(url)
        req = requests.get(url, data, headers={'Authorization':"Bearer "+self.oauth.access_token})
        if self.verbose:print(req.status_code)
        if self.verbose:print(req.json())
        return (req.status_code, req.json())
    
    def getIdByUrl(self, url):
        '''
        Get Blog ID Using BLog URL.

        Response Template
        
        {
              "kind": "blogger#blogList",
              "items": [
                {
                  "kind": "blogger#blog",
                  "id": "4967929378133675647",
                  "name": "Brett's Test Blawg",
                  "description": "",
                  "published": "2010-10-06T23:33:31.662Z",
                  "updated": "2011-08-08T06:50:02.005Z",
                  "url": "http://brettmorgan-test-blawg.blogspot.com/",
                  "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647",
                  "posts": {
                    "totalItems": 13,
                    "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647/posts"
                  },
                  "pages": {
                    "totalItems": 1,
                    "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647/pages"
                  },
                  "locale": {
                    "language": "en",
                    "country": "",
                    "variant": ""
                  }
                }
              ]
            }
        
        '''
        return self.getRequest('blogs/byurl', data={'url':self.blogurl})
        #
    def getUsers(self):
        '''
        Get List of Blog USERS.


        Response Template
        
            {
              "kind": "blogger#blogList",
              "items": [
                {
                  "kind": "blogger#blog",
                  "id": "4967929378133675647",
                  "name": "Brett's Test Blawg",
                  "description": "",
                  "published": "2010-10-06T23:33:31.662Z",
                  "updated": "2011-08-08T06:50:02.005Z",
                  "url": "http://brettmorgan-test-blawg.blogspot.com/",
                  "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647",
                  "posts": {
                    "totalItems": 13,
                    "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647/posts"
                  },
                  "pages": {
                    "totalItems": 1,
                    "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647/pages"
                  },
                  "locale": {
                    "language": "en",
                    "country": "",
                    "variant": ""
                  }
                }
              ]
            }
        '''
        

        return self.getRequest('users/self/blogs')[1]
    
    def getPosts(self, data={}):
        '''
        Get Few Starting Posts Details

        Response Template
        
        {
              "kind": "blogger#postList",
              "nextPageToken": "CgkIChiAkceVjiYQ0b2SAQ",
              "prevPageToken": "CgkIChDBwrK3mCYQ0b2SAQ",
              "items": [
                {
                  "kind": "blogger#post",
                  "id": "7706273476706534553",
                  "blog": {
                    "id": "2399953"
                  },
                  "published": "2011-08-01T19:58:00.000Z",
                  "updated": "2011-08-01T19:58:51.947Z",
                  "url": "http://buzz.blogger.com/2011/08/latest-updates-august-1st.html",
                  "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/7706273476706534553",
                  "title": "Latest updates, August 1st",
                  "content": "elided for readability",
                  "author": {
                    "id": "401465483996",
                    "displayName": "Brett Wiltshire",
                    "url": "http://www.blogger.com/profile/01430672582309320414",
                    "image": {
                      "url": "http://4.bp.blogspot.com/_YA50adQ-7vQ/S1gfR_6ufpI/AAAAAAAAAAk/1ErJGgRWZDg/S45/brett.png"
                     }
                  },
                  "replies": {
                    "totalItems": "0",
                    "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/7706273476706534553/comments"
                  }
                },
                {
                  "kind": "blogger#post",
                  "id": "6069922188027612413",
                  elided for readability
                }
              ]
            }
        
        
        
        '''
        temp = "items(id,url,title),nextPageToken"
        data['fields']=temp
        return self.getRequest('blogs/{}/posts'.format(self.blogid), data=data)

    def getAllPostList(self, template="items(title, id, url,author)"):
        '''
        Auto nextPageToken Handler. 
        Get All Data in Once, And You Can Also Filter Data 
        Using Template Parameter. 
        
        '''
        collect = []
        nextPageToken = "firstpage"
        temp = "nextPageToken,"+template
        
        while True:

            req = {
                'fields':temp
            }

            if nextPageToken=="firstpage":
                pass

            elif nextPageToken=="":
                break
            else:
                req['pageToken']=nextPageToken

            req = self.getRequest('blogs/{}/posts'.format(self.blogid), data=req)

            # No Response
            if not req[0]==200:
                print('[-] No Response.')
                print(req[0])
                print(req[1])
                break

            if "nextPageToken" in req[1].keys():
                nextPageToken = req[1]['nextPageToken']
            else:
                nextPageToken = ""
            collect.append(req[1])

        return collect
    
    def getBlogsAccess(self):
        '''
        Get The List of Blog, User had access. 

        Response Template
        
        {
          "kind": "blogger#blogList",
          "items": [
            {
              "kind": "blogger#blog",
              "id": "4967929378133675647",
              "name": "Brett's Test Blawg",
              "description": "",
              "published": "2010-10-06T23:33:31.662Z",
              "updated": "2011-08-08T06:50:02.005Z",
              "url": "http://brettmorgan-test-blawg.blogspot.com/",
              "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647",
              "posts": {
                "totalItems": 13,
                "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647/posts"
              },
              "pages": {
                "totalItems": 1,
                "selfLink": "https://www.googleapis.com/blogger/v3/blogs/4967929378133675647/pages"
              },
              "locale": {
                "language": "en",
                "country": "",
                "variant": ""
              }
            }
          ]
        }

        '''
        return self.getRequest('users/self/blogs')
    
    def getPost(self, postid):
        # https://www.googleapis.com/blogger/v3/blogs/blogId/posts/postId
        '''
        Get Specific Post Complete Details using post ID

        Response Template
        
        {
              "kind": "blogger#post",
              "id": "7706273476706534553",
              "blog": {
                "id": "2399953"
              },
              "published": "2011-08-01T19:58:00.000Z",
              "updated": "2011-08-01T19:58:51.947Z",
              "url": "http://buzz.blogger.com/2011/08/latest-updates-august-1st.html",
              "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/7706273476706534553",
              "title": "Latest updates, August 1st",
              "content": "elided for readability",
              "author": {
                "id": "401465483996",
                "displayName": "Brett Wiltshire",
                "url": "http://www.blogger.com/profile/01430672582309320414",
                "image": {
                  "url": "http://4.bp.blogspot.com/_YA50adQ-7vQ/S1gfR_6ufpI/AAAAAAAAAAk/1ErJGgRWZDg/S45/brett.png"
                }
              },
              "replies": {
                "totalItems": "0",
                "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/7706273476706534553/comments"
              }
            }
        '''
        return self.getRequest('blogs/{}/posts/{}'.format(self.blogid, postid))
    def searchPost(self, query):
        '''
        Search Post By Passing Query

        Response Template
        
        {
              "kind": "blogger#postList",
              "nextPageToken": "CgkIChiAj86CpB8QzJTEAQ",
              "prevPageToken": "CgkIChDBq5v24yYQzJTEAQ",
              "items": [
              {
                "kind": "blogger#post",
                "id": "1387873546480002228",
                "blog": {
                  "id": "3213900"
                },
                "published": "2012-03-23T01:58:00-07:00",
                "updated": "2012-03-23T01:58:12-07:00",
                "url": "http://code.blogger.com/2012/03/blogger-documentation-has-moved-to.html",
                "selfLink": "https://www.googleapis.com/blogger/v3/blogs/3213900/posts/1387873546480002228",
                "title": "Blogger Documentation has moved to developers.google.com",
                "content": "content elided for readability",
                "author": {
                  "id": "16258312240222542576",
                  "displayName": "Brett Morgan",
                  "url": "http://www.blogger.com/profile/16258312240222542576",
                  "image": {
                    "url": "https://resources.blogblog.com/img/b16-rounded.gif"
                  }
                },
                "replies": {
                  "totalItems": "0",
                  "selfLink": "https://www.googleapis.com/blogger/v3/blogs/3213900/posts/1387873546480002228/comments"
                }
              },
              ...
              ]
            }
        '''
        # GET https://www.googleapis.com/blogger/v3/blogs/3213900/posts/search?q=documentation&key=YOUR-API-KEY
        return self.getRequest('blogs/{}/posts/search'.format(self.blogid), data={'q':query})
    
    def newPost(self, post_data):
        '''
        New Post

        post_data Example
            {
              "title": "A new post",
              "content": "With <b>exciting</b> content..."
              
            }
            
        Response Template
        
        {
             "kind": "blogger#post",
             "id": "6819100329896798058",
             "blog": {
              "id": "8070105920543249955"
             },
             "published": "2012-05-20T20:08:00-07:00",
             "updated": "2012-05-20T20:08:35-07:00",
             "url": "http://brettmorgan-test2.blogspot.com/2012/05/new-post.html",
             "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/6819100329896798058",
             "title": "A new post",
             "content": "With <b>exciting</b> content...",
             "author": {
              "id": "16258312240222542576",
              "displayName": "Brett Morgan",
              "url": "http://www.blogger.com/profile/16258312240222542576",
              "image": {
               "url": "https://resources.blogblog.com/img/b16-rounded.gif"
              }
             },
             "replies": {
              "totalItems": "0",
              "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/6819100329896798058/comments"
             }
        }
        '''
        post_data['kind']="blogger#post"
        post_data['blog']={"id":self.blogid}
        #       POST https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/
        #       Authorization: /* OAuth 2.0 token here */
        #       Content-Type: application/json
        url = "https://www.googleapis.com/blogger/v3/blogs/{}/posts/".format(self.blogid)
        req = requests.post(url, json=post_data, headers={'Authorization':"Bearer "+self.oauth.access_token})
        if self.verbose:print(req.status_code)
        if self.verbose:print(req.json())
        return (req.status_code, req.json())
    
    
    def deletePost(self, postid):
        '''
        Delete Post. Pass Post ID
        '''
        url = "https://www.googleapis.com/blogger/v3/blogs/{}/posts/{}".format(self.blogid, postid)
        req = requests.delete(url, headers={'Authorization':"Bearer "+self.oauth.access_token})
        if self.verbose:print(req.status_code)
        if self.verbose:print(req.json())
        return (req.status_code)
    
    def getPostByPath(self, path):

        # https://www.googleapis.com/blogger/v3/blogs/blogId/posts/bypath?path=post-
        '''
        Get POST details by using post url.

        Request
            path=/2011/08/latest-updates-august-1st.html
            
        Response Template
        
              "kind": "blogger#post",
              "id": "7706273476706534553",
              "blog": {
                "id": "2399953"
              },
              "published": "2011-08-01T19:58:00.000Z",
              "updated": "2011-08-01T19:58:51.947Z",
              "url": "http://buzz.blogger.com/2011/08/latest-updates-august-1st.html",
              "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/7706273476706534553",
              "title": "Latest updates, August 1st",
              "content": "elided for readability",
              "author": {
                "id": "401465483996",
                "displayName": "Brett Wiltshire",
                "url": "http://www.blogger.com/profile/01430672582309320414",
                "image": {
                  "url": "http://4.bp.blogspot.com/_YA50adQ-7vQ/S1gfR_6ufpI/AAAAAAAAAAk/1ErJGgRWZDg/S45/brett.png"
                }
              },
              "replies": {
                "totalItems": "0",
                "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/7706273476706534553/comments"
              }
            }
        '''
        return self.getRequest('blogs/{}/posts/bypath'.format(self.blogid), data={'path':path})
    
    def updatePost_hard(self, postid, post_data):
        '''
        Update Post Using PUT Request

        Example Post_Data
        
            "url": "http://brettmorgan-test2.blogspot.com/2012/05/new-post_20.html",
            "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/3445355871727114160",
            "title": "An updated post",
            "content": "With really <b>exciting</b> content..."
             
             
        Request 

            PUT https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/3445355871727114160
            Authorization: /* OAuth 2.0 token here */
            Content-Type: application/json

            {
             "kind": "blogger#post",
             "id": "3445355871727114160",
             "blog": {
              "id": "8070105920543249955"
             },
             "url": "http://brettmorgan-test2.blogspot.com/2012/05/new-post_20.html",
             "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/3445355871727114160",
             "title": "An updated post",
             "content": "With really <b>exciting</b> content..."
            }


            Response Template


        {
         "kind": "blogger#post",
         "id": "6819100329896798058",
         "blog": {
          "id": "8070105920543249955"
         },
         "published": "2012-05-20T20:08:00-07:00",
         "updated": "2012-05-20T20:08:35-07:00",
         "url": "http://brettmorgan-test2.blogspot.com/2012/05/new-post.html",
         "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/6819100329896798058",
         "title": "An updated post",
         "content": "With really <b>exciting</b> content...",
         "author": {
          "id": "16258312240222542576",
          "displayName": "Brett Morgan",
          "url": "http://www.blogger.com/profile/16258312240222542576",
          "image": {
           "url": "https://resources.blogblog.com/img/b16-rounded.gif"
          }
         },
         "replies": {
          "totalItems": "0",
          "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/6819100329896798058/comments"
         }
        }
        '''
        post_data['kind']="blogger#post"
        post_data['blog']={"id":self.blogid}
        post_data['id']=postid
        url = "https://www.googleapis.com/blogger/v3/blogs/{}/posts/{}".format(self.blogid, postid)
        req = requests.put(url, json=post_data, headers={'Authorization':"Bearer "+self.oauth.access_token})
        if self.verbose:print(req.status_code)
        if self.verbose:print(req.json())
        return (req.status_code, req.json())
    
    def updatePost_soft(self, postid, post_data):
        '''
        Update POST using Patch Request

        
        Example Post_Data [Pass Only The Fields, Need To Update]
        
            "url": "http://brettmorgan-test2.blogspot.com/2012/05/new-post_20.html" 
            
            Or
            
            "title": "An updated post", 
            
            Or
            
            "content": "With really <b>exciting</b> content..."
        
        
        Reuqest
            PATCH https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/3445355871727114160
            Authorization: /* OAuth 2.0 token here */
            Content-Type: application/json

            {
             "content": "With absolutely <b>fabulous</b> content..."
            }

        Response:
             
             {
                 "kind": "blogger#post",
                 "id": "6819100329896798058",
                 "blog": {
                  "id": "8070105920543249955"
                 },
                 "published": "2012-05-20T20:08:00-07:00",
                 "updated": "2012-05-20T20:08:35-07:00",
                 "url": "http://brettmorgan-test2.blogspot.com/2012/05/new-post.html",
                 "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/6819100329896798058",
                 "title": "An updated post",
                 "content": "With absolutely <b>fabulous</b> content...",
                 "author": {
                  "id": "16258312240222542576",
                  "displayName": "Brett Morgan",
                  "url": "http://www.blogger.com/profile/16258312240222542576",
                  "image": {
                   "url": "https://resources.blogblog.com/img/b16-rounded.gif"
                  }
                 },
                 "replies": {
                  "totalItems": "0",
                  "selfLink": "https://www.googleapis.com/blogger/v3/blogs/8070105920543249955/posts/6819100329896798058/comments"
                 }
            }
        '''
        post_data['kind']="blogger#post"
        post_data['blog']={"id":self.blogid}
        post_data['id']=postid
        url = "https://www.googleapis.com/blogger/v3/blogs/{}/posts/{}".format(self.blogid, postid)
        req = requests.put(url, json=post_data, headers={'Authorization':"Bearer "+self.oauth.access_token})
        if self.verbose:print(req.status_code)
        if self.verbose:print(req.json())
        return (req.status_code, req.json())
    
    def getComment(self, postid):
        '''
        Request
            GET https://www.googleapis.com/blogger/v3/blogs/2399953/posts/6069922188027612413/comments?key=YOUR-API-KEY
            
        Response:
            {
                  "kind": "blogger#commentList",
                  "nextPageToken": "CgkIFBDwjvDXlyYQ0b2SARj9mZe9n8KsnlQ",
                  "prevPageToken": "CgkIFBisvMGRlyYQ0b2SARj9mZe9n8KsnlQ",
                  "items": [
                    {
                       "kind": "blogger#comment",
                       "id": "9200761938824362519",
                       "post": {
                         "id": "6069922188027612413"
                       },
                       "blog": {
                         "id": "2399953"
                       },
                       "published": "2011-07-28T19:19:57.740Z",
                       "updated": "2011-07-28T21:29:42.015Z",
                       "selfLink": "https://www.googleapis.com/blogger/v3/blogs/2399953/posts/6069922188027612413/comments/9200761938824362519",
                       "content": "elided",
                       "author": {
                         "id": "530579030283",
                         "displayName": "elided",
                         "url": "elided",
                         "image": {
                           "url": "elided"
                         }
                       }
                    },
                    {
                      "kind": "blogger#comment",
                      "id": "400101178920857170",
                      elided for readability
                    }
                  ]
            }
        '''
        return self.getRequest('blogs/{}/posts/{}/comments'.format(self.blogid, postid))
    
# Parameter Reference : https://github.com/googleapis/google-api-go-client/blob/master/blogger/v3/blogger-api.json    
# https://www.googleapis.com/blogger/v3/users/userId
# https://www.googleapis.com/blogger/v3/users/self
# https://www.googleapis.com/blogger/v3/users/userId/blogs
# https://www.googleapis.com/blogger/v3/users/self/blogs
# https://www.googleapis.com/blogger/v3/blogs/blogId
# https://www.googleapis.com/blogger/v3/blogs/byurl
# https://www.googleapis.com/blogger/v3/blogs/blogId/posts
# https://www.googleapis.com/blogger/v3/blogs/blogId/posts/bypath
# https://www.googleapis.com/blogger/v3/blogs/blogId/posts/search
# https://www.googleapis.com/blogger/v3/blogs/blogId/posts/postId
# https://www.googleapis.com/blogger/v3/blogs/blogId/posts/postId/comments
# https://www.googleapis.com/blogger/v3/blogs/blogId/posts/postId/comments/commentId
# https://www.googleapis.com/blogger/v3/blogs/blogId/pages
# https://www.googleapis.com/blogger/v3/blogs/blogId/pages/pageId


def routine_check():
    '''
    Check Routine To Verify Blogger API Working Correctly.
    '''
    auth = OAuthentication(OAuthJsonFile)
    #auth.refresh()
    print(auth.__dict__)
    b = Blogger(auth, verbose=False, blogURL="https://thisisaturotilablogh.blogspot.com/")


    # s=b.getAllPostList()
    print('[+] Blog Access By Your Account')
    print(b.getBlogsAccess())
    print('\n\n\n')
    print('============================= Creating New Post ============================')
    r = b.newPost(post_data={'title':'Blogger Api Bot', 'content':"YUP! Its Working"})
    input('Check Blog Manually, Is There Any New Post With Title Blogger Api Bot')
    postID = r[1]['id']
    
    input("[=] Now Going To Update it...")
    b.updatePost_soft(postID, {'content':'Second Update'})
    input('[=] Check Post Body = Second Update')
    input("[=] Now Going To Delete....")
    b.deletePost(postID)
    input("[=] Check its Deleted..")
    input("[=] If Every Thing Working.. Then, Its Working")
    return


# Generate Client Crediatials
def check_client(oauth_json_file=OAuthJsonFile):

    # if OAuth Json Not Found
    if not os.path.exists(oauth_json_file):
        print('[Error] OAuth Json File Not Found.')
        print('------------------------- | Note | ---------------------------')
        print('[INFO] Please set OAuthJsonFile = Your_Google_Console_API_Json_File_path')
        print('[INFO] Or You Can Also Pass File Path By Parameter oauth_file ')
        print('[INFO] Or Generate New OAuthJsonFile. Execute bboauth.py')
        return False

    OAuthurizationAccessTokenGenerator(oauth_json_file)

    # if found
    return True



# main function
def main():
    # Oauth Json found
    if check_client():
        
        print('[+] Searching OAuth Json File... Ok')
        
        
        try:
            routine_check()
            
        except Exception as e:
            print(e)
            print('Exiting....')
            exit(0)

    # When OAuth Json Not Found
    else:

        print('Exiting...')
        exit(0)
    return False

# trigger
if __name__=='__main__':
    main()
