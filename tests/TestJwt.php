<?php declare(strict_types=1);

namespace Tests;
use \PHPUnit\Framework\TestCase;
use \Sanjos\JwtAuthentication;

class TestJwt extends TestCase {

    // VERY SIMPLES
    public function testNewJwt()
    {
        $jwt = JwtAuthentication::getInstance([
            'lifetime' => 70
        ]);

        $jwt->setPayload([
            'name'  => 'Jeconias',
            'email' => 'jeconiass2009@hotmail.com'
        ]);

        //echo $jwt->getToken();

        $this->assertInstanceOf(JwtAuthentication::class, $jwt);
        $this->assertEquals(true, $jwt->isValid( $jwt->getToken() ));
    }

}