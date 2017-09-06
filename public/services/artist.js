angular.module('MyApp')
  .factory('Artist', ['$resource', function($resource) {
    return $resource('/api/artists/:_id');
  }]);