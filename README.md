# Python Client To Handle Blogger REST Api

With the help of these project codes, anyone can easily interact with blogger REST api using python. I wrote this script for other python developer who want to use blogger REST api with their python project. 

## Getting Started

Well, to get start with this project. First you have to clone this git repo. Type In Your Terminal `git clone THIS_REPO_URL`.
and second thing, Keep In Your Mind, this Project can do every thing.. thats possible to do with blogger API. this python script had many automatic functions.
so, if you able to understand.. You Can Appriciate my work by clicking that Star Button.

ok 

### Prerequisites

```
Only python 3.x
python3 requests module

```

### Installing

Installation is very easy. 

First, Clone Repo.  

Second, You needed Google Developer Console Project Authentication JSON File.  

If You Don't Know, What it is, And How to Get it.  

Just Run `python3 bboauth.py` script.  

After Downloading, `Crediential Json File`, Rename it And Save It In Home Directory.  
Well, Because This JSON file is very important. hence, keep it in home directory.

Now, Open blogger.py and Configure These Fields. According To your situation.

```
HOME_PATH   = os.path.expanduser("~")
OAuthJsonFile   = os.path.join(HOME_PATH, ".oauth.crediantials.json") # Download And Add Your API Console Downloaded Json File path
``` 

Now, You Are Ready To Play With These Codes.
```
# import module
from blogger import *

# create class object to automatically handle oauth related security procedure
auth = OAuthentication(OAuthJsonFile)

# generate new access point token, you have to generate new access point in an hour because its gets expire.
auth.refresh() 

# oauthentication access details
print(auth.__dict__)

# blogger API, Here Insert Your Blogger URL.
b = Blogger(auth, verbose=False, blogURL="https://thisisaturotilablogh.blogspot.com/")

# if Every Thing is Ok, It Will Return Your Blog Post Lists
s=b.getAllPostList()

# To Get All Blog Details, Your Account Has Access
print('[+] Blog Access By Your Account')
print(b.getBlogsAccess())

# From Here, Give Attension, This Line Will Post New Article.
r = b.newPost(post_data={'title':'Blogger Api Bot', 'content':"YUP! Its Working"})
input('Check Blog Manually, Is There Any New Post With Title Blogger Api Bot')
postID = r[1]['id']
    
# To Update That Posted Article
b.updatePost_soft(postID, {'content':'Second Update'})

# To Delete That posted Article
b.deletePost(postID)

```

For More information, Check `blogger.py` source code comments. Or Use help(Blogger) function. To Get Details of Any Class Object And function.
I would prefer you to use IPython. because.. it Will provide you tab completion.


### Useful Blogger API URL

```
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

```



## Running the tests

```

python3 blogger.py

```


## Contributing

Currently, I'm The Only One Guy

## Authors

* **Suraj Singh Bisht** - *Complete work* - [@bitforestinfo](https://github.com/surajsinghbisht054)

## License

This project is licensed under the Apache License - see the [LICENSE.md](LICENSE.md) file for details


