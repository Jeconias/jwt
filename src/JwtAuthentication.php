<?php declare(strict_types=1);

namespace Jsantos;
use \Jsantos\Exception\{
    InvalidTokenException, 
    InvalidTokenOptionException};

final class JwtAuthentication {


    /**
     * Instance of JwtAuthentication
     * 
     * @var JwtAuthentication $instance
     */
    private static $instance    = null;

    /**
     * Header JsonWebToken
     * 
     * @var array $header
     */
    private $header = [];

    /**
     * Payload JsonWebToken
     * 
     * @var array $payload
     */
    private $payload = [];

    /**
     * Options for validate and generate token
     * 
     * @var mixed $options
     */
    private $options = [
        'lifetime'  => 60,
        'alg'       => 'HS256',
        'key'       => 'def@ultKey',
        'iss'       => 'http://localhost'
    ];

    private const ALGS = [
        'HS256' => 'SHA256',
        'HS384' => 'SHA384',
        'HS512' => 'SHA512'
    ];


    
    private function __construct(array $options = [])
    {
        $this->hydrateToken($options);
        $time = time();
        
        $this->header['alg'] = $this->options['alg'];
        $this->header['typ'] = 'JWT';
        $this->payload = [
            'iss'       => $this->options['iss'],
            'iat'       => $time,
            'exp'       => $time + ($this->options['lifetime'] * 60),
        ];

        $this->header = $this->base64Encode( json_encode( $this->header, JSON_UNESCAPED_UNICODE));
    }
    
    public static function getInstance(array $options = []) : JwtAuthentication 
    {
        if(self::$instance === null) return new JwtAuthentication($options);
        return self::$instance;
    }

    public function isValid(string $token) : bool
    {
        return $this->validateToken($token);
    }

    public function setPayload(array $args) : JwtAuthentication
    {
        foreach ($args as $key => $value) {
            $this->payload['context'][$key] = $value;
        }
        
        $this->payload =$this->base64Encode( json_encode($this->payload, JSON_UNESCAPED_UNICODE) );
        return $this;
    }

    public function getPayload() : object {
        return $this->payload->context;
    }

    public function getToken() : string
    {
        return $this->signature();
    }

    private function hydrateToken(array $options) : void
    {
        foreach($options as $key => $value)
        {
            $method = strtolower($key);
            if(method_exists($this, $key))
            {
                call_user_func([$this, $method], $value);
            }else{
                throw new InvalidTokenOptionException("{$key} is not a valid option.");
            }
        }
    }

    private function lifetime(int $time) : void
    {
        $this->options['lifetime'] = $time;
    }

    private function alg(string $alg) : void
    {
        $this->options['alg'] = $alg;
    }

    private function key(string $key) : void
    {
        $this->options['key'] = $key;
    }

    private function iss(string $iss) : void
    {
        $this->options['iss'] = $iss;
    }

    private function base64Encode($data) : string
    {
        return str_replace(['+', '/', '='], ['-', '_', ''], base64_encode( $data ));
    }
    
    private function base64Decode($data) : ?string
    {
        return base64_decode( str_replace(['-', '_', ''], ['+', '/', '='], $data) );
    }

    private function signature() : string
    {
        $this->payload = (gettype($this->payload) === "array") ? $this->base64AndJsonEncode($this->payload) : $this->payload;
        
        $alg = isset( self::ALGS[$this->options['alg']] ) ? self::ALGS[$this->options['alg']] : $this->options['alg'];
        $signature = hash_hmac($alg, "$this->header.$this->payload", $this->options['key'], true);
        
        return "$this->header.$this->payload.{$this->base64Encode( $signature )}";
    }

    
    private function validateToken(string $token) : bool
    {
        $splitToken = explode('.', $token);
        
        if(count($splitToken) != 3) throw new InvalidTokenException('Invalid token structure.');

        list($header, $payload, $signature) = $splitToken;
        
        if(null === $headerObj = json_decode($this->base64Decode( $header ))) throw new InvalidTokenException('Invalid token header.');

        if(null === $payloadObj = json_decode($this->base64Decode( $payload ))) throw new InvalidTokenException('Invalid token payload.');

        if(false === $signature = $this->base64Decode($signature)) throw new InvalidTokenException('Invalid token signature.');

        if($headerObj->alg != $this->options['alg']) throw new InvalidTokenException('Invalid token algorithm.');

        if($payloadObj->exp < time()) throw new InvalidTokenException('Token expired.');
        
        $alg = isset( self::ALGS[$this->options['alg']] ) ? self::ALGS[$this->options['alg']] : $this->options['alg'];
        $hash = hash_hmac($alg, "$header.$payload", $this->options['key'], true);

        if(hash_equals($signature, $hash) !== true) throw new InvalidTokenException('Invalid Token.');

        $this->payload = $payloadObj;

        return true;
    }
}