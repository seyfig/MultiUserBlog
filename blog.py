import os
import webapp2
import jinja2
import re
import hashlib
import hmac
import random
import string
from models import User, Post, Comment
from config import SECRET

from google.appengine.ext import ndb

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# Form Validation
def valid_username(username):
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    return USER_RE.match(username)


def valid_password(password):
    USER_RE = re.compile(r"^.{3,20}$")
    return USER_RE.match(password)


def valid_email(email):
    USER_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")
    return USER_RE.match(email)


# Hash Cookie Part
def hash_str(s):
    return hmac.new(SECRET, s).hexdigest()


def make_secure_val(s):
    return "%s|%s" % (s, hash_str(s))


def check_secure_val(h):
    s = h.split('|')[0]
    if h == make_secure_val(s):
        return s


# Hash Password Part
def make_salt():
    return ''.join(random.choice(string.letters) for x in xrange(5))


def make_pw_hash(name, pw):
    salt = make_salt()
    h = hashlib.sha256(name + pw + salt).hexdigest()
    return "%s,%s" % (h, salt)


def valid_pw(name, pw, h):
    [x, s] = h.split(',')
    n = hashlib.sha256(name + pw + s).hexdigest()
    return n == x


# START Handlers
# START User Handlers
class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        if hasattr(self, 'user') and self.user:
            params.update({'user': self.user})
        else:
            params.update({'user': None})
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def login(self):
        user_cookie_str = self.request.cookies.get('user')
        if user_cookie_str:
            user_cookie = check_secure_val(user_cookie_str)
            if user_cookie:
                self.user = User.get_by_id(int(user_cookie))
                return
        self.user = None

    def validatelogin(self):
        """User logged in or not"""
        self.login()
        if not self.user:
            self.redirect('/signup')
            return False
        else:
            return True

    def error(self, error):
        self.render("error.html", error=error)


class SignUp(Handler):
    def get(self):
        self.login()
        if self.user:
            self.redirect("/welcome")
            return
        self.render("signup.html",
                    uvalid=True,
                    uunique=True,
                    pvalid=True,
                    vvalid=True,
                    evalid=True)

    def post(self):
        username = self.request.get('username')
        password1 = self.request.get('password')
        password2 = self.request.get('verify')
        email = self.request.get('email')
        uvalid = True
        uunique = True
        pvalid = True
        vvalid = True
        evalid = True

        uvalid = valid_username(username)
        pvalid = valid_password(password1)
        vvalid = (password1 == password2)
        evalid = valid_email(email) or len(email) == 0

        if uvalid and pvalid and vvalid and evalid:
            user = User.by_name(username)
            if user:
                uunique = False
            else:
                password = make_pw_hash(username, password1)
                user = User.register(username, password, email)
                user.put()
                user_id = user.key.id()
                user_cookie = make_secure_val(str(user_id))
                self.response.headers.add_header(
                    'Set-Cookie', 'user=%s' % user_cookie)
                self.redirect("/welcome")
                return

        self.render("signup.html",
                    username=username,
                    email=email,
                    uvalid=uvalid,
                    uunique=uunique,
                    pvalid=pvalid,
                    vvalid=vvalid,
                    evalid=evalid)


class Login(Handler):
    def get(self):
        self.login()
        if self.user:
            self.redirect("/welcome")
            return
        self.render("login.html", valid=True)

    def post(self):
        username = self.request.get('username')
        password1 = self.request.get('password')
        valid = True
        user = User.by_name(username)
        if user:
            hashpass = user.password
            user_id = user.key.id()
            if hashpass:
                if valid_pw(username, password1, hashpass):
                    user_cookie = make_secure_val(str(user_id))
                    self.response.headers.add_header(
                        'Set-Cookie', 'user=%s' % user_cookie)
                    self.redirect("/welcome")
                    return
        valid = False
        self.render("login.html",
                    username=username,
                    valid=valid)


class Logout(Handler):
    def get(self):
        self.response.delete_cookie('user')
        self.redirect("/signup")


class Welcome(Handler):
    def get(self):
        if self.validatelogin():
            self.render("welcome.html")

# END User Handlers
# START Post Handlers


class PostHandler(Handler):
    """Handler for Post object.
    CommentHandler inherits from this class.
    pc refers to Post or Comment"""

    def type(self):
        return self.pc.__class__.__name__

    def render_form(self, subject="", content="", error=""):
        self.render("postform.html",
                    subject=subject,
                    content=content,
                    error=error)

    def get_key_by_urlsafe(self, url_safe_key):
        if url_safe_key:
            try:
                return ndb.Key(urlsafe=url_safe_key)
            except Exception:
                pass
        self.error("%s doesn't exist" % self.type())

    def get_by_urlsafe(self, url_safe_key):
        pc_key = self.get_key_by_urlsafe(url_safe_key)
        if pc_key:
            try:
                pc = pc_key.get()
                if pc:
                    return pc
            except Exception:
                pass
        self.error("%s doesn't exist" % self.type())

    def validate_user(self):
        """Logged in user and user of pc are same or not"""
        if self.pc.user == self.user.key:
            return True
        else:
            self.error("You are not authorized to modify this %s" %
                       self.type())
            return False

    def validate_modificaiton(self, url_safe_key):
        """Does user authenticated to modify pc"""
        if not self.validatelogin():
            return False
        if not self.set_pc(url_safe_key):
            return False
        if not self.validate_user():
            return False
        return True

    def validate_like(self, url_safe_key):
        """Does user authenticated to like the post"""
        if not self.validatelogin():
            return False
        if not self.set_pc(url_safe_key):
            return False
        if self.pc.user == self.user.key:
            self.error("You can not like / unlike your own posts")
            return False
        else:
            return True

    def validate_form(self):
        """Is the form valid to submit"""
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            if not self.pc:
                user_key = self.user.key
                post = Post.new_post(
                    subject=subject,
                    content=content,
                    user_key=user_key)
                self.pc = post
            else:
                self.pc.subject = subject
                self.pc.content = content
            return True
        else:
            error = "Both subject and content are required"
            self.render_form(subject, content, error)
            return False

    def set_pc(self, url_safe_key):
        """Find the post or comment element with url_safe_key"""
        self.pc = self.get_by_urlsafe(url_safe_key)
        if not self.pc:
            return False
        else:
            return True

    def save_pc(self):
        """Save the post or comment element.
        This function shall be called after validations completed."""
        pc_key = self.pc.put()
        pc_url_safe_key = pc_key.urlsafe()
        self.redirect("/viewpost/" + pc_url_safe_key)

    def likeunlikepost(self, url_safe_key, likeunlike):
        """Function for a user to like or unlike a post
        First calls like validation function.
        If user already liked a post and press like button again
        the like will be taken back. Same for unlike."""
        if self.validate_like(url_safe_key):
            if self.pc.like_post(likeunlike, self.user.key):
                self.redirect("/viewpost/%s" % url_safe_key)
                return
        self.error("There has been en error")


class MainPage(PostHandler):
    def get(self, url_safe_key=""):
        self.login()
        posts = []
        if not url_safe_key:
            posts = Post.all_posts()
            if posts.count() == 0:
                posts = []
            self.render("blog.html", posts=posts)
        else:
            post = self.get_by_urlsafe(url_safe_key)
            if post:
                posts = [post]
                self.render("post.html", posts=posts)


class NewPost(PostHandler):
    def get(self):
        if self.validatelogin():
            self.render_form()

    def post(self):
        if not self.validatelogin():
            return
        self.pc = None
        if not self.validate_form():
            return
        else:
            self.save_pc()


class EditPost(PostHandler):
    def get(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            self.render_form(self.pc.subject, self.pc.content)

    def post(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            if self.validate_form():
                self.save_pc()


class DeletePost(PostHandler):
    def get(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            self.render("deletepost.html", post=self.pc)

    def post(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            self.pc.key.delete()
            self.redirect("/")


class LikePost(PostHandler):
    def get(self, url_safe_key=""):
        self.likeunlikepost(url_safe_key, True)


class UnlikePost(PostHandler):
    def get(self, url_safe_key=""):
        self.likeunlikepost(url_safe_key, False)

# END Post Handlers
# START Comment Handlers


class CommentHandler(PostHandler):
    def get_post_url_safe_key(self):
        """Find the Post of a Comment"""
        url_safe_key = self.request.get('post_key')
        if not url_safe_key and self.pc:
            url_safe_key = self.pc.key.parent().urlsafe()
        if not url_safe_key:
            self.error("Invalid post")
            return None
        else:
            return url_safe_key

    def get_post_key(self):
        """Find the Key of the Post of a Comment"""
        url_safe_key = self.request.get('post_key')
        if not url_safe_key and self.pc:
            post_key = self.pc.key.parent()
        else:
            post_key = self.get_key_by_urlsafe(url_safe_key)
        if not post_key:
            self.error("Invalid post")
            return None
        else:
            return post_key

    def render_form(self, content="", error=""):
        """Overrides PostHandler.render_form"""
        post_url_safe_key = self.get_post_url_safe_key()
        if not post_url_safe_key:
            self.error("Invalid post")
            return
        self.render("commentform.html",
                    post_key=post_url_safe_key,
                    content=content,
                    error=error)

    def validate_form(self):
        """Overrides PostHandler.validate_form"""
        post_key = self.get_post_key()
        if not post_key:
            self.error("Invalid post")
            return
        content = self.request.get("content")
        if content:
            if not self.pc:
                user_key = self.user.key
                comment = Comment(
                    parent=post_key, content=content, user=user_key)
                self.pc = comment
            else:
                self.pc.content = content
            return True
        else:
            error = "Content is required"
            self.render_form(content, error)
            return False

    def save_pc(self):
        """Overrides PostHandler.save_pc"""
        self.pc.put()
        post_url_safe_key = self.pc.key.parent().urlsafe()
        self.redirect("/viewpost/" + post_url_safe_key)


class ListComment(CommentHandler):
    def get(self, url_safe_key=""):
        self.login()
        comment = self.get_by_urlsafe(url_safe_key)
        if comment:
            self.render("viewcomment.html", comment=comment)
            return
        else:
            return
        comments = []
        if not url_safe_key:
            comments = Comment.all_comment()
        else:
            comment = self.get_by_urlsafe(url_safe_key)
            if comment:
                comment = [comment]
        if comments:
            self.render("viewcomment.html", comment=comment)


class NewComment(CommentHandler):
    def get(self):
        if self.validatelogin():
            self.render_form()

    def post(self):
        if not self.validatelogin():
            return
        self.pc = None
        if not self.validate_form():
            return
        else:
            self.save_pc()


class EditComment(CommentHandler):
    def get(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            self.render_form(content=self.pc.content)

    def post(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            if self.validate_form():
                self.save_pc()


class DeleteComment(CommentHandler):
    def get(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            self.render("deletecomment.html", comment=self.pc)

    def post(self, url_safe_key=""):
        if self.validate_modificaiton(url_safe_key):
            post_url_safe_key = self.pc.key.parent().urlsafe()
            self.pc.key.delete()
            self.redirect("/viewpost/" + post_url_safe_key)

# END Comment Handlers
# END Handlers

app = webapp2.WSGIApplication([('/', MainPage),
                               ('/signup', SignUp),
                               ('/login', Login),
                               ('/logout', Logout),
                               ('/welcome', Welcome),
                               ('/newpost', NewPost),
                               ('/editpost/(.+)', EditPost),
                               ('/deletepost/(.+)', DeletePost),
                               ('/viewpost/(.+)', MainPage),
                               ('/likepost/(.+)', LikePost),
                               ('/unlikepost/(.+)', UnlikePost),
                               ('/comments', ListComment),
                               ('/newcomment', NewComment),
                               ('/editcomment/(.+)', EditComment),
                               ('/deletecomment/(.+)', DeleteComment),
                               ('/viewcomment/(.+)', ListComment),
                               ], debug=True)
