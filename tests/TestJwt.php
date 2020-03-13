<?php

declare(strict_types=1);

namespace Tests;

use PHPUnit\Framework\TestCase;
use Sanjos\JwtAuthentication;

class TestJwt extends TestCase
{

    /**
     * @testdox Should test if Token is valid
     *
     * @return void
     */
    public function testNewJwt()
    {
        $jwt = JwtAuthentication::getInstance(null);

        $jwt->setPayload([
            'name'  => 'Jeconias',
            'email' => 'jeconiass2009@hotmail.com'
        ]);

        $this->assertInstanceOf(JwtAuthentication::class, $jwt);
        $this->assertEquals(true, $jwt->isValid($jwt->getToken()));
    }

    /**
     * @testdox Should test if values of token is correct
     *
     * @return void
     */
    public function testJwtValues()
    {
        $jwt = JwtAuthentication::getInstance(null);

        $jwt->setPayload([
            'uuid'  => 'uuidTest',
            'email' => 'jeconiass2009@hotmail.com'
        ]);

        $payload = $jwt->getPayload();
        $this->assertEquals('uuidTest', $payload->uuid);
        $this->assertEquals('jeconiass2009@hotmail.com', $payload->email);
    }
}
