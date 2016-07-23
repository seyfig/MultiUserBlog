# Multi User Blog

## Multi User Blog is a web application, which allows users to do mainly the following:
 * Browse blog posts,
 * Post new blog posts, edit and delete their own blog posts
 * Comment on blog posts, edit and delete their own comments
 * Like / unlike blog posts of other users

## In order to run the web site, it is required to
 * Have Python 2 and Google App Engine installed
 * Run Google App Engine localy, or deploy project to Google App Engine server
 * In config.py file SECRET parameter is used to hash cookies, it is required to set
 this variable to a more secure string

## Browsing the web site:
 * Browse http://syf-udacity-cs253.appspot.com/
(or http://localhost:8080 for local deployment)
 * Users should sign up in order to send new posts and comments, Sign Up link exists
on the top right corner
 * Login / Sign Up links are on the top right corner when user not logged in
 * Logout link are on the top right corner when user logged in
 * User can post new blog post clicking the New Post navigation button after logged in
 * Posts can be viewed in detail by clicking their subjects
 * In detail view comments of posts can be seen
 * New comments can be added by clicking Add Comment button located under each post
 * Posts and Comments can be modified if they are created by the logged in user.
If user is authorized to modify Post or Comment, Edit and Delete links are located under
content at bottom right corner
 * Users may like and unlike a post by clicking Like and Unlike buttons. It is required
to logged in, in order to perform like operation. In addition, users should't like or
unlike their own posts.
 * After the content of a post, at bottom right corner there exists,
 	* Edit / Delete links if user owns that post
 	* Like / Unlike links if user doesn't own that post
 * Like link changes to Liked link if user Liked that post before and Unlike link changes
to Unliked if user Unliked that post before. If user clicks the Liked or Unliked link
they take their like or unlike back.
 * When there are Liked and Unlike links, user Liked that post before, if user clicks
Unlike, the Like is taken back and Unlike recorder.
Same condition applies for the opposite.
