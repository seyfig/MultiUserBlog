/*
 After you have changed the settings at "Your code goes here",
 run this with one of these options:
  "grunt" alone creates a new, completed images directory
  "grunt clean" removes the images directory
  "grunt responsive_images" re-processes images without removing the old ones
*/

module.exports = function(grunt) {

grunt.initConfig({

  uncss: {
    dist: {
      files: {'static/css/tidy.css' : ['templates/comments.html', 'templates/welcome.html', 'templates/postform.html', 'templates/viewcomment.html', 'templates/signup.html', 'templates/error.html', 'templates/login.html', 'templates/postview.html', 'templates/commentform.html', 'templates/post.html', 'templates/base.html', 'templates/deletepost.html', 'templates/blog.html', 'templates/deletecomment.html']
      }

    }
  }

})
  grunt.loadNpmTasks('grunt-uncss');

  grunt.registerTask('default', ['uncss']);

};
