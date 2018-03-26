'use strict';

module.exports = function (grunt) {

  // Add the grunt-mocha-test and jshint tasks.
  grunt.loadNpmTasks('grunt-mocha-test');
  grunt.loadNpmTasks('grunt-contrib-jshint');
  grunt.loadNpmTasks('grunt-contrib-watch');

  grunt.initConfig({
    // Configure a mochaTest task
    mochaTest: {
      test: {
        options: {
          reporter: 'spec',
          timeout: 20000
        },
        src: ['test/**/*.js']
      }
    },

    jshint: {
      options: {
        reporter: require('jshint-stylish'),
        jshintrc: '.jshintrc'
      },
      all: [
        'Gruntfile.js',
        'index.js',
        'lib/**/*.js',
        'test/**/*.js'
      ]
    },

    watch: {
      all: {
        files: [
          'Gruntfile.js',
          'index.js',
          'lib/**/*.js',
          'test/**/*.js'
        ],
        tasks: ['jshint', 'mochaTest']
      }
    },
  });

  //custom tasks
  grunt.registerTask('default', ['watch']);
  grunt.registerTask('test', ['jshint', 'mochaTest']);

};