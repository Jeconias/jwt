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
}
