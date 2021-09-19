<?php

namespace DarkGhostHunter\Laraguard\Doctrine;

use DateTime;
use Illuminate\Support\Carbon;
use OTPHP\TOTP;
use ParagonIE\ConstantTime\Base32;

trait HandlesCodes {
    /**
     * Current instance of the Cache Repository.
     *
     * @var \Illuminate\Contracts\Cache\Repository
     */
    protected $cache;

    /**
     * String to prefix the Cache key.
     *
     * @var string
     */
    protected $prefix;

    /**
     * Whether the trait has been initialised yet
     * @var bool
     */
    protected $initialized = false;

    /**
     * Initializes the current trait.
     *
     * @throws \Exception
     */
    protected function initializeHandlesCodes() {
        ['store' => $store, 'prefix' => $this->prefix] = config('laraguard.cache');

        $this->cache = $this->useCacheStore($store);

        $this->initialized = true;
    }

    /**
     * Returns the Cache Store to use.
     *
     * @param  string  $store
     * @return \Illuminate\Contracts\Cache\Repository
     * @throws \Exception
     */
    protected function useCacheStore(string $store = null) {
        return cache()->store($store);
    }

    /**
     * Validates a given code, optionally for a given timestamp and future window.
     *
     * @param  string  $code
     * @param  int  $window
     * @return bool
     */
    public function validateCode(string $code, int $window = null) : bool {
        if(!$this->initialized) {
            $this->initializeHandlesCodes();
        }
        if($this->codeHasBeenUsed($code)) {
            return false;
        }

        $window = $window ?? $this->window;

        return $this->makeOTP()->verify($code, null, $window);
    }

    /**
     * Returns a two-factor code for the current timestamp.
     * @return string
     */
    public function makeTwoFactorCode(): string {
        $code = $this->makeOTP()->now();
        // quick sanity check that this is verifiable
        assert($this->makeOTP()->verify($code));
        return $code;
    }

    /**
     * Creates a Code for a given timestamp, optionally by a given period offset.
     *
     * @return TOTP
     */
    public function makeOTP() {
        if (!$this->initialized) {
            $this->initializeHandlesCodes();
        }

        $otp = TOTP::create($this->getSharedSecret(), $this->seconds, $this->algorithm, $this->digits);
        return $otp;
    }

    /**
     * Normalizes the Timestamp from a string, integer or object.
     *
     * @param  int|string|\Datetime|\Illuminate\Support\Carbon  $at
     * @return int
     */
    protected function parseTimestamp($at) : int {
        if ($at instanceof DateTime) {
            return $at->getTimestamp();
        }

        if (is_string($at)) {
            return Carbon::parse($at)->getTimestamp();
        }

        return $at;
    }

    /**
     * Returns the cache key string to save the codes into the cache.
     *
     * @param  string  $code
     * @return string
     */
    protected function cacheKey(string $code) {
        if (!$this->initialized) {
            $this->initializeHandlesCodes();
        }
        return "{$this->prefix}|{$this->getId()}|$code";
    }

    /**
     * Checks if the code has been used.
     *
     * @param  string  $code
     * @return bool
     */
    protected function codeHasBeenUsed(string $code) {
        if (!$this->initialized) {
            $this->initializeHandlesCodes();
        }
        return $this->cache->has($this->cacheKey($code));
    }

    /**
     * Sets the Code has used so it can't be used again.
     *
     * @param  string  $code
     * @param  int|string|\Datetime|\Illuminate\Support\Carbon  $at
     * @return bool
     */
    protected function setCodeHasUsed(string $code, $at) {
        if (!$this->initialized) {
            $this->initializeHandlesCodes();
        }
        // We will safely set the cache key for the whole lifetime plus window just to be safe.
        return $this->cache->set($this->cacheKey($code), true,
            Carbon::createFromTimestamp($this->getTimestampFromPeriod($at, $this->window + 1))
        );
    }
}
