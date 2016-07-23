from google.appengine.ext import ndb


def users_key(group='default'):
    return ndb.Key('users', group)


def blog_key(name='default'):
    key = ndb.Key('blogs', name)
    return key


class User(ndb.Model):
    """User Profile - Passwords are assumed to be hashed before"""
    username = ndb.StringProperty(required=True)
    password = ndb.StringProperty(required=True)
    email = ndb.StringProperty()
    created = ndb.DateTimeProperty(auto_now_add=True)

    @classmethod
    def by_id(cls, user_id):
        return cls.get_by_id(user_id, parent=users_key())

    @classmethod
    def by_name(cls, username):
        filter_query = ndb.query.FilterNode('username', '=', username)
        return cls.query().filter(filter_query).get()

    @classmethod
    def register(cls, username, password, email=None):
        return cls(username=username,
                   password=password,
                   email=email)

    @classmethod
    def login(cls, username, pw):
        return cls.by_name(username)


class Post(ndb.Model):
    """Post Object"""
    subject = ndb.StringProperty(required=True)
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(required=True, kind='User')
    likecount = ndb.IntegerProperty(required=True, default=0)

    def user_post(self, user_key):
        """ if post belongs to user returns true"""
        return self.user == user_key

    def user_post_like(self, user_key):
        """ if user neither liked nor unliked post return 0
        if user liked post returns 1
        if user unliked post returns -1"""
        like = Like.get_post_user_likes(self.key, user_key)
        if not like:
            return 0
        elif like.like:
            return 1
        else:
            return -1

    @ndb.transactional(xg=True)
    def like_post(self, likeunlike, user_key):
        """ When user liked or unliked a post;
        new like record created if it doesn't exist
        else the existing record is updated.
        User may take  like or unlike back."""
        if self.user == user_key:
            return False
        likecount = 0
        if likeunlike:
            likecount += 1
        else:
            likecount -= 1
        like = Like.get_post_user_likes(self.key, user_key)
        if not like:
            like = Like.new_like(self.key, likeunlike, user_key)
            self.likecount += likecount
            like.put()
            self.put()
            return True
        else:
            if like.like == likeunlike:
                likecount *= -1
                self.likecount += likecount
                like.key.delete()
                self.put()
                return True
            else:
                like.like = likeunlike
                likecount *= 2
                self.likecount += likecount
                like.put()
                self.put()
                return True

    def get_comments(self):
        return Comment.get_post_comments(self.key)

    @classmethod
    def by_id(cls, post_id):
        return cls.get_by_id(post_id)

    @classmethod
    def new_post(cls, subject, content, user_key):
        post = cls(parent=blog_key(),
                   subject=subject,
                   content=content,
                   user=user_key)
        return post

    @classmethod
    def all_posts(cls):
        return Post.query(ancestor=blog_key()).order(-cls.created)


class Comment(ndb.Model):
    """Comment Object"""
    content = ndb.TextProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(required=True, kind='User')

    def user_comment(self, user_key):
        return self.user == user_key

    @classmethod
    def by_id(cls, comment_id):
        return cls.get_by_id(comment_id)

    @classmethod
    def new_comment(cls, content, user_key, post_key):
        comment = cls(parent=post_key,
                      content=content,
                      user=user_key)
        return comment

    @classmethod
    def get_post_comments(cls, post_key):
        return cls.query(ancestor=post_key).order(-cls.created)


class Like(ndb.Model):
    """Like Object
    if user likes post set Like.like == True
    if user unlikes post set Like.like == False
    otherwise no Like object exists """
    like = ndb.BooleanProperty(required=True)
    created = ndb.DateTimeProperty(auto_now_add=True)
    last_modified = ndb.DateTimeProperty(auto_now=True)
    user = ndb.KeyProperty(required=True, kind='User')

    @classmethod
    def by_id(cls, like_id):
        return cls.get_by_id(like_id)

    @classmethod
    def new_like(cls, post_key, likeunlike, user_key):
        like = cls(parent=post_key,
                   like=likeunlike,
                   user=user_key)
        return like

    @classmethod
    def get_post_likes(cls, post_key):
        return cls.query(ancestor=post_key).order(-cls.created)

    @classmethod
    def get_post_user_likes(cls, post_key, user_key):
        likes_query = cls.query(ancestor=post_key)
        filter_query = ndb.query.FilterNode('user', '=', user_key)
        return likes_query.filter(filter_query).get()
