<?php

declare(strict_types=1);

namespace Sanjos;

use Sanjos\Options;
use Sanjos\Exception\{
    InvalidTokenException,
    InvalidTokenOptionException
};

final class JwtAuthentication
{


    /**
     * Instance of JwtAuthentication
     * 
     * @var JwtAuthentication $instance
     */
    private static ?JwtAuthentication $instance = null;

    /**
     * Header JsonWebToken
     * 
     * @var array $header
     */
    private array $header = [];

    /**
     * Header JsonWebToken
     * 
     * @var string $headerB64
     */
    private string $headerB64 = '';

    /**
     * Payload JsonWebToken
     * 
     * @var array $payload
     */
    private array $payload = [];

    /**
     * Payload JsonWebToken
     * 
     * @var string $payloadB64
     */
    private string $payloadB64 = '';

    /**
     * Options for validate and generate token
     * 
     * @var Options $options
     */
    private Options $options;


    private const ALGS = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512'
    ];


    private function __construct(?Options $options)
    {
        $this->options = new Options();
        $this->hydrateToken($options);
        $time = time();

        $this->header['alg'] = $this->options->getAlg();
        $this->header['typ'] = 'JWT';
        $this->payload = [
            'iss'       => $this->options->getIss(),
            'iat'       => $time,
            'exp'       => $time + ($this->options->getLifeTime() * 60),
        ];

        $this->headerB64 = $this->base64Encode(json_encode($this->header, JSON_UNESCAPED_UNICODE));
    }

    public static function getInstance(?Options $options): JwtAuthentication
    {
        if (self::$instance === null) return new JwtAuthentication($options);
        return self::$instance;
    }

    public function setPayload(array $args): JwtAuthentication
    {
        foreach ($args as $key => $value) {
            $this->payload['context'][$key] = $value;
        }

        $this->payloadB64 = $this->base64Encode(json_encode($this->payload, JSON_UNESCAPED_UNICODE));
        return $this;
    }

    public function getPayload(): object
    {
        return (object) $this->payload['context'];
    }

    public function getToken(): string
    {
        return $this->signature();
    }

    public function isValid(string $token): bool
    {
        $splitToken = explode('.', $token);

        if (count($splitToken) != 3) throw new InvalidTokenException('Invalid token structure.');

        list($header, $payload, $signature) = $splitToken;

        if (null === $headerObj = json_decode($this->base64Decode($header))) throw new InvalidTokenException('Invalid token header.');

        if (null === $payloadObj = json_decode($this->base64Decode($payload))) throw new InvalidTokenException('Invalid token payload.');

        if (false === $signature = $this->base64Decode($signature)) throw new InvalidTokenException('Invalid token signature.');

        if ($headerObj->alg != $this->options->getAlg()) throw new InvalidTokenException('Invalid token algorithm.');

        if ($payloadObj->exp < time()) throw new InvalidTokenException('Token expired.');

        $alg = isset(self::ALGS[$this->options->getAlg()]) ? self::ALGS[$this->options->getAlg()] : $this->options->getAlg();
        $hash = hash_hmac($alg, "$header.$payload", $this->options->getKey(), true);

        if (hash_equals($signature, $hash) !== true) throw new InvalidTokenException('Invalid Token.');

        $this->payload = (array) $payloadObj;

        return true;
    }

    private function hydrateToken(?Options $options): void
    {
        if ($options === null) return;
        $this->options = $options;
    }

    private function base64Encode($data): string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode($data));
    }

    private function base64Decode($data): ?string
    {
        return base64_decode(str_replace(['-', '_', ''], ['+', '/', '='], $data));
    }

    private function signature(): string
    {
        $alg = isset(self::ALGS[$this->options->getAlg()]) ? self::ALGS[$this->options->getAlg()] : $this->options->getAlg();
        $signature = hash_hmac($alg, "$this->headerB64.$this->payloadB64", $this->options->getKey(), true);

        return "$this->headerB64.$this->payloadB64.{$this->base64Encode($signature)}";
    }
}
