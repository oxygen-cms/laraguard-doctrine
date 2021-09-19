<?php

namespace DarkGhostHunter\Laraguard\Doctrine;

use Doctrine\ORM\Mapping AS ORM;
use Illuminate\Support\Collection;
use Oxygen\Data\Behaviour\PrimaryKey;
use Oxygen\Data\Behaviour\Timestamps;
use ParagonIE\ConstantTime\Base32;
use DarkGhostHunter\Laraguard\Contracts\TwoFactorTotp;

/**
 * @ORM\Entity
 * @ORM\Table(name="`two_factor_auth`")
 * @ORM\HasLifecycleCallbacks
 */
class TwoFactorAuthentication implements TwoFactorTotp {
    use HandlesCodes;
    use HandlesRecoveryCodes;
    use HandlesSafeDevices;
    use SerializesSharedSecret;

    use PrimaryKey, Timestamps;

    /**
     * @ORM\OneToOne(targetEntity="\Oxygen\Auth\Entity\User", inversedBy="twoFactorAuth")
     */
    protected $authenticatable;

    /**
     * @ORM\Column(type="string")
     */
    protected $shared_secret;

    /**
     * @ORM\Column(name="enabled_at", type="datetime", nullable=true)
     * @var \DateTime
     */
    private $enabled_at;

    /**
     * @ORM\Column(type="string")
     * @var \DateTime
     */
    private $label;

    /**
     * @ORM\Column(type="smallint")
     */
    private $digits;
    /**
     * @ORM\Column(type="smallint")
     */
    private $seconds;
    /**
     * @ORM\Column(type="smallint", name="`window`")
     */
    private $window;

    /**
     * @ORM\Column(type="string", name="`algorithm`")
     */
    private $algorithm;

    /**
     * @ORM\Column(type="json_array", nullable=true)
     */
    protected $recovery_codes;

    /**
     * @ORM\Column(name="recovery_codes_generated_at", type="datetime", nullable=true)
     * @var \DateTime
     */
    private $recovery_codes_generated_at;

    /**
     * @ORM\Column(type="json_array", nullable=true)
     */
    private $safe_devices;

    /**
     * TwoFactorAuthentication constructor.
     */
    public function __construct($authenticatable) {
        $this->authenticatable = $authenticatable;
        $this->digits = 6;
        $this->seconds = 30;
        $this->window = 0;
    }

    /**
     * The model that uses Two Factor Authentication.
     *
     * @return \Oxygen\Auth\Entity\User
     */
    public function authenticatable() {
        return $this->authenticatable();
    }

    public function setLabel(string $string) {
        $this->label = $string;
    }

    /**
     * @return Collection
     */
    public function getRecoveryCodes() {
        return collect($this->recovery_codes);
    }

    /**
     * @param Collection $codes
     * @return void
     */
    public function setRecoveryCodes(Collection $codes) {
        $this->recovery_codes = $codes->toArray();
    }

    public function setRecoveryCodesGeneratedAt(\Illuminate\Support\Carbon $now) {
        $this->recovery_codes_generated_at = $now->toDateTime();
    }

    public function getSafeDevices() {
        return collect($this->safe_devices);
    }

    public function setSafeDevices(Collection $devices) {
        $this->safe_devices = $devices->toArray();
    }

    public function setEnabledAt(\Illuminate\Support\Carbon $now) {
        $this->enabled_at = $now->toDateTime();
    }

    /**
     * Gets the Shared Secret attribute from its binary form.
     * @return null|string
     */
    protected function getSharedSecret() {
        return $this->shared_secret;
    }

    /**
     * Sets the Shared Secret attribute to its binary form.
     *
     * @param $value
     */
    protected function setSharedSecret($value) {
        $this->shared_secret = $value;
    }

    /**
     * Sets the Algorithm to lowercase.
     *
     * @param $value
     */
    protected function setAlgorithmAttribute($value) {
        $this->algorithm = strtolower($value);
    }

    /**
     * Returns if the Two Factor Authentication has been enabled.
     *
     * @return bool
     */
    public function isEnabled() {
        return $this->enabled_at !== null;
    }

    /**
     * Returns if the Two Factor Authentication is not been enabled.
     *
     * @return bool
     */
    public function isDisabled() {
        return !$this->isEnabled();
    }

    /**
     * Flushes all authentication data and cycles the Shared Secret.
     *
     * @return $this
     */
    public function flushAuth() {
        $this->recovery_codes = null;
        $this->recovery_codes_generated_at = null;
        $this->safe_devices = null;
        $this->enabled_at = null;

        $defaults = config('laraguard.totp');

        $this->digits = $defaults['digits'];
        $this->seconds = $defaults['seconds'];
        $this->window = $defaults['window'];
        $this->algorithm = $defaults['algorithm'];

        $this->shared_secret = static::generateRandomSecret();

        return $this;
    }

    /**
     * Creates a new Random Secret.
     *
     * @return string
     */
    public static function generateRandomSecret() {
        return trim(Base32::encodeUpper(random_bytes(config('laraguard.secret_length')), '='));
    }
}
