<?php

namespace DarkGhostHunter\Laraguard\Eloquent;

use Oxygen\Data\Behaviour\PrimaryKey;
use Oxygen\Data\Behaviour\Timestamps;
use ParagonIE\ConstantTime\Base32;
use Illuminate\Database\Eloquent\Model;
use DarkGhostHunter\Laraguard\Contracts\TwoFactorTotp;

///**
// * @mixin \Illuminate\Database\Eloquent\Builder
// *
// * @property-read int $id
// *
// * @property-read null|\DarkGhostHunter\Laraguard\Contracts\TwoFactorAuthenticatable $authenticatable
// *
// * @property string $shared_secret
// *
// * @property string $label
// * @property int $digits
// * @property int $seconds
// * @property int $window
// * @property string $algorithm
// * @property array $totp_config
// * @property null|\Illuminate\Support\Collection $recovery_codes
// * @property null|\Illuminate\Support\Collection $safe_devices
// * @property null|\Illuminate\Support\Carbon|\DateTime $enabled_at
// * @property null|\Illuminate\Support\Carbon|\DateTime $recovery_codes_generated_at
// *
// * @property null|\Illuminate\Support\Carbon|\DateTime $updated_at
// * @property null|\Illuminate\Support\Carbon|\DateTime $created_at
// */

/**
 * @ORM\Entity
 * @ORM\Table(name="`two_factor_auth`")
 */
class TwoFactorAuthentication implements TwoFactorTotp {
    use HandlesCodes;
    use HandlesRecoveryCodes;
    use HandlesSafeDevices;
    use SerializesSharedSecret;

    use PrimaryKey, Timestamps;

//    /**
//     * The attributes that should be cast to native types.
//     *
//     * @var array
//     */
//    protected $casts = [
//        'authenticatable_id' => 'int',
//        'digits'             => 'int',
//        'seconds'            => 'int',
//        'window'             => 'int',
//        'recovery_codes'     => 'collection',
//        'safe_devices'       => 'collection',
//    ];

//    /**
//     * The attributes that should be mutated to dates.
//     *
//     * @var array
//     */
//    protected $dates = [
//        'enabled_at',
//        'recovery_codes_generated_at',
//    ];

    /**
     * @ORM\ManyToOne(targetEntity="Oxygen\Auth\Entity\User", fetch="EAGER", cascade="persist")
     */
    protected $authenticatable;

    /**
     * @ORM\Column(type="string")
     */
    protected $shared_secret;

    /**
     * @ORM\Column(name="enabled_at", type="datetime")
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
     * @ORM\Column(type="smallint")
     */
    private $window;

    /**
     * @ORM\Column(type="string")
     */
    private $algorithm;

    /**
     * @ORM\Column(type="json_array")
     */
    protected $recovery_codes;

    /**
     * @ORM\Column(name="recovery_codes_generated_at", type="datetime")
     * @var \DateTime
     */
    private $recovery_codes_generated_at;

    /**
     * @ORM\Column(type="json_array")
     */
    private $safe_devices;

    /**
     * TwoFactorAuthentication constructor.
     */
    public function __construct() {
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

//    /**
//     * The model that uses Two Factor Authentication.
//     *
//     * @return \Illuminate\Database\Eloquent\Relations\MorphTo
//     */
//    public function authenticatable()
//    {
//        return $this->morphTo('authenticatable');
//    }

    /**
     * Gets the Shared Secret attribute from its binary form.
     *
     * @param $value
     * @return null|string
     */
    protected function getSharedSecretAttribute($value)
    {
        return $value === null ? $value : Base32::encodeUpper($value);
    }

    /**
     * Sets the Shared Secret attribute to its binary form.
     *
     * @param $value
     */
    protected function setSharedSecretAttribute($value)
    {
        $this->shared_secret = Base32::decodeUpper($value);
    }

    /**
     * Sets the Algorithm to lowercase.
     *
     * @param $value
     */
    protected function setAlgorithmAttribute($value)
    {
        $this->algorithm = strtolower($value);
    }

    /**
     * Returns if the Two Factor Authentication has been enabled.
     *
     * @return bool
     */
    public function isEnabled()
    {
        return $this->enabled_at !== null;
    }

    /**
     * Returns if the Two Factor Authentication is not been enabled.
     *
     * @return bool
     */
    public function isDisabled()
    {
        return ! $this->isEnabled();
    }

    /**
     * Flushes all authentication data and cycles the Shared Secret.
     *
     * @return $this
     */
    public function flushAuth()
    {
        $this->recovery_codes = null;
        $this->recovery_codes_generated_at = null;
        $this->safe_devices = null;
        $this->enabled_at = null;

        $defaults = config('laraguard.totp');

        $this->digits = $defaults['digits'];
        $this->seconds = $defaults['seconds'];
        $this->window = $defaults['window'];
        $this->algorithm = $defaults['algorithm'];

        $this->setSharedSecretAttribute(static::generateRandomSecret());

        return $this;
    }

    /**
     * Creates a new Random Secret.
     *
     * @return string
     */
    public static function generateRandomSecret()
    {
        return Base32::encodeUpper(
            random_bytes(config('laraguard.secret_length'))
        );
    }
}
