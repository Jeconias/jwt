<?php

declare(strict_types=1);

namespace Sanjos;

/**
 * Options for validate and generate token
 */
final class Options
{
    /**
     * Timestamp of Token
     */
    private int $lifeTime = 70;

    /**
     * Alg used
     */
    private string $alg = 'HS256';

    /**
     * Key for check token
     */
    private string $key = 'def@ultKey';

    /**
     * Emitter of token
     */
    private string $iss = 'http://127.0.0.1';


    /**
     * Return the duration of Token in minutes
     *
     * @return integer
     */
    public function getLifeTime(): int
    {
        return $this->lifeTime;
    }

    /**
     * Change duration of Token (value in minutes)
     *
     * @param integer $option
     * @return Options
     */
    public function setLifeTime(int $option): Options
    {
        $this->lifeTime = $option;
        return $this;
    }

    /**
     * Return the algorithm used
     *
     * @return string
     */
    public function getAlg(): string
    {
        return $this->alg;
    }

    /**
     * Change algorithm used
     *
     * @param string $option
     * @return Options
     */
    public function setAlg(string $option): Options
    {
        $this->alg = $option;
        return $this;
    }

    /**
     * Return the key of Token
     *
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * Change the key of Token
     *
     * @param string $option
     * @return Options
     */
    public function setKey(string $option): Options
    {
        $this->key = $option;
        return $this;
    }

    /**
     * Return the emitter of token
     *
     * @return string
     */
    public function getIss(): string
    {
        return $this->iss;
    }

    /**
     * Change the emitter
     *
     * @param string $option
     * @return Options
     */
    public function setIss(string $option): Options
    {
        $this->iss = $option;
        return $this;
    }
}
