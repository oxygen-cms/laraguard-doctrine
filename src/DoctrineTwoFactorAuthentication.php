<?php

namespace DarkGhostHunter\Laraguard;

use Doctrine\ORM\EntityManager;
use Doctrine\ORM\Mapping AS ORM;

use Illuminate\Http\Request;
use Illuminate\Support\Collection;

trait DoctrineTwoFactorAuthentication
{
//    /**
//     * Initialize the current Trait.
//     *
//     * @return void
//     */
//    public function initializeTwoFactorAuthentication()
//    {
//        // For security, we will hide the Two Factor Authentication data from the parent model.
//        $this->makeHidden('twoFactorAuth');
//    }
//
//    /**
//     * This connects the current Model to the Two Factor Authentication model.
//     *
//     * @return \Illuminate\Database\Eloquent\Relations\MorphOne|\DarkGhostHunter\Laraguard\Eloquent\TwoFactorAuthentication
//     */
//    public function twoFactorAuth()
//    {
//        return $this->morphOne(config('laraguard.model'), 'authenticatable')
//            ->withDefault(config('laraguard.totp'));
//    }

    /**
     * @ORM\OneToOne(targetEntity="DarkGhostHunter\Laraguard\Doctrine\TwoFactorAuthentication", mappedBy="authenticatable")
     * @var \DarkGhostHunter\Laraguard\Doctrine\TwoFactorAuthentication
     */
    protected $twoFactorAuth;

    /**
     * Determines if the User has Two Factor Authentication enabled.
     *
     * @return bool
     */
    public function hasTwoFactorEnabled() : bool
    {
        return $this->twoFactorAuth != null && $this->twoFactorAuth->isEnabled();
    }

    /**
     * Enables Two Factor Authentication for the given user.
     *
     * @return void
     */
    public function enableTwoFactorAuth() : void {
        $this->twoFactorAuth->setEnabledAt(now());

        if (config('laraguard.recovery.enabled')) {
            $this->generateRecoveryCodes();
        }

        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();

        event(new Events\TwoFactorEnabled($this));
    }

    /**
     * Disables Two Factor Authentication for the given user.
     *
     * @return void
     */
    public function disableTwoFactorAuth() : void
    {

        $this->twoFactorAuth->flushAuth();
        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();

        event(new Events\TwoFactorDisabled($this));
    }

    /**
     * Creates a new Two Factor Auth mechanisms from scratch, and returns a new Shared Secret.
     *
     * @return \DarkGhostHunter\Laraguard\Contracts\TwoFactorTotp
     */
    public function createTwoFactorAuth() : Contracts\TwoFactorTotp {
        if($this->twoFactorAuth == null) {
            $this->twoFactorAuth = new \DarkGhostHunter\Laraguard\Doctrine\TwoFactorAuthentication($this);
        }
        $this->twoFactorAuth
            ->flushAuth()
            ->setLabel($this->twoFactorLabel());

        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();

        return $this->twoFactorAuth;
    }

    /**
     * Returns the label for TOTP URI.
     *
     * @return string
     */
    protected function twoFactorLabel()
    {
        return $this->email;
    }

    /**
     * Confirms the Shared Secret and fully enables the Two Factor Authentication.
     *
     * @param  string  $code
     * @return bool
     */
    public function confirmTwoFactorAuth(string $code) : bool {
        if ($this->hasTwoFactorEnabled()) {
            return true;
        }

        if ($this->validateCode($code)) {
            $this->enableTwoFactorAuth();
            return true;
        }

        return false;
    }

    /**
     * Verifies the Code against the Shared Secret.
     *
     * @param $code
     * @return bool
     */
    protected function validateCode($code)
    {
        return $this->twoFactorAuth->validateCode($code);
    }

    /**
     * Validates the TOTP Code or Recovery Code.
     *
     * @param  string  $code
     * @return bool
     */
    public function validateTwoFactorCode(?string $code = null) : bool
    {
        if (! $code || ! $this->hasTwoFactorEnabled()) {
            return false;
        }

        return $this->useRecoveryCode($code) || $this->validateCode($code);
    }

    /**
     * Makes a Two Factor Code.
     * @return string
     */
    public function makeTwoFactorCode() : string
    {
        return $this->twoFactorAuth->makeTwoFactorCode();
    }

    /**
     * Determines if the User has Recovery Codes available.
     *
     * @return bool
     */
    protected function hasRecoveryCodes() : bool
    {
        return $this->twoFactorAuth->containsUnusedRecoveryCodes();
    }

    /**
     * Return the current set of Recovery Codes.
     *
     * @return \Illuminate\Support\Collection
     */
    public function getRecoveryCodes() : Collection
    {
        return $this->twoFactorAuth->getRecoveryCodes() ?? collect();
    }

    /**
     * Generates a new set of Recovery Codes.
     *
     * @return \Illuminate\Support\Collection
     */
    public function generateRecoveryCodes() : Collection
    {
        [$enabled, $amount, $length] = array_values(config('laraguard.recovery'));

        $this->twoFactorAuth->setRecoveryCodes(config('laraguard.model')::generateRecoveryCodes($amount, $length));
        $this->twoFactorAuth->setRecoveryCodesGeneratedAt(now());
        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();

        event(new Events\TwoFactorRecoveryCodesGenerated($this));

        return $this->twoFactorAuth->getRecoveryCodes();
    }

    /**
     * Uses a one-time Recovery Code if there is one available.
     *
     * @param  string  $code
     * @return mixed
     */
    protected function useRecoveryCode(string $code) : bool
    {
        if (! config('laraguard.recovery.enabled') || ! $this->twoFactorAuth->setRecoveryCodeAsUsed($code)) {
            return false;
        }

        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();

        if (! $this->hasRecoveryCodes()) {
            event(new Events\TwoFactorRecoveryCodesDepleted($this));
        }

        return true;
    }

    /**
     * Adds a "safe" Device from the Request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    public function addSafeDevice(Request $request) : string
    {
        $devices = collect($this->twoFactorAuth->getSafeDevices())->push([
            '2fa_remember' => $token = $this->generateTwoFactorRemember(),
            'ip'           => $request->ip(),
            'added_at'     => now()->timestamp,
        ])->sortByDesc('added_at');

        if ($devices->count() > $max = config('laraguard.safe_devices.max_devices')) {
            $devices = $devices->slice(0, $max)->values();
        }

        $this->twoFactorAuth->setSafeDevices($devices);

        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();

        cookie()->queue('2fa_remember', $token, config('laraguard.safe_devices.expiration_days', 0) * 1440);

        return $token;
    }

    /**
     * Generates a Device token to bypass Two Factor Authentication.
     *
     * @return string
     */
    protected function generateTwoFactorRemember()
    {
        return config('laraguard.model')::generateDefaultTwoFactorRemember();
    }

    /**
     * Deletes all saved safe devices.
     *
     * @return bool
     */
    public function flushSafeDevices() : bool
    {
        $this->twoFactorAuth->setSafeDevices(new Collection());
        app(EntityManager::class)->persist($this->twoFactorAuth);
        app(EntityManager::class)->flush();
    }

    /**
     * Return all the Safe Devices that bypass Two Factor Authentication.
     *
     * @return \Illuminate\Support\Collection
     */
    public function safeDevices() : Collection
    {
        return $this->twoFactorAuth->getSafeDevices() ?? collect();
    }

    /**
     * Determines if the Request has been made through a previously used "safe" device.
     *
     * @param  null|\Illuminate\Http\Request  $request
     * @return bool
     */
    public function isSafeDevice(Request $request) : bool
    {
        $timestamp = $this->twoFactorAuth->getSafeDeviceTimestamp(
            $this->getTwoFactorRememberFromRequest($request)
        );

        if ($timestamp) {
            return $timestamp->addDays(config('laraguard.safe_devices.expiration_days'))->isFuture();
        }

        return false;
    }

    /**
     * Returns the Two Factor Remember Token of the request.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return null|array|string
     */
    protected function getTwoFactorRememberFromRequest(Request $request)
    {
        return $request->cookie('2fa_remember');
    }

    /**
     * Determines if the Request has been made through a not-previously-known device.
     *
     * @param  null|\Illuminate\Http\Request  $request
     * @return bool
     */
    public function isNotSafeDevice(Request $request) : bool
    {
        return ! $this->isSafeDevice($request);
    }
}
