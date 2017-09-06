angular.module('MyApp')
  .controller('MainCtrl', ['$scope', 'Artist', function($scope, Artist) {

    $scope.alphabet = ['0-9', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J',
      'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
      'Y', 'Z'];

    $scope.genres = ['Action', 'Adventure', 'Animation', 'Children', 'Comedy',
      'Crime', 'Documentary', 'Drama', 'Family', 'Fantasy', 'Food',
      'Home and Garden', 'Horror', 'Mini-Series', 'Mystery', 'News', 'Reality',
      'Romance', 'Sci-Fi', 'Sport', 'Suspense', 'Talk Show', 'Thriller',
      'Travel'];

    $scope.headingTitle = 'Top 10 Artists';

    $scope.artists = Artist.query();

    $scope.filterByGenre = function(genre) {
      $scope.artists = Artist.query({ genre: genre });
      $scope.headingTitle = genre;
    };

    $scope.filterByAlphabet = function(char) {
      $scope.artists = Artist.query({ alphabet: char });
      $scope.headingTitle = char;
    };
  }]);