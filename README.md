# JWT

Simple JsonWebToken with PHP

### Usage

```
composer require sanjos/jwtauth

use Sanjos\JwtAuthentication;

$jwt = JwtAuthentication::getInstance(null);

$jwt->setPayload([
    'uuid'  => 'uuidTest',
    'github' => 'github.com/jeconias'
]);

$token = $jwt->getToken();

//Return: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJodHRwOlwvXC8xMjcuMC4wLjEiLCJpYXQiOjE1ODQyOTg2NDYsImV4cCI6MTU4NDMwMjg0NiwiY29udGV4dCI6eyJ1dWlkIjoidXVpZFRlc3QyIiwiZ2l0aHViIjoiZ2l0aHViLmNvbVwvamVjb25pYXMifX0.nuzDQhdfGbAIzaSQvlPpirH4DrphMMp6hRq_TqIZ1Hc

$jwt->isValid($token);

//Return: Boolean

```
