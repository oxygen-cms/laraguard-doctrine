<?php

namespace DarkGhostHunter\Laraguard\Rules;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Translation\Translator;
use DarkGhostHunter\Laraguard\Contracts\TwoFactorAuthenticatable;
use Illuminate\Contracts\Validation\Rule;

class TotpCodeRule implements Rule {
    /**
     * The auth user.
     *
     * @var Authenticatable|TwoFactorAuthenticatable
     */
    protected $user;

    /**
     * Create a new "totp code" rule instance.
     *
     * @param Authenticatable|null  $user
     */
    public function __construct(Authenticatable $user = null) {
        $this->user = $user;
    }

    /**
     * Validate that an attribute is a valid Two Factor Authentication TOTP code.
     *
     * @param  string  $attribute
     * @param  mixed  $value
     * @return bool
     */
    public function passes($attribute, $value) {
        if (is_string($value) && $this->user instanceof TwoFactorAuthenticatable) {
            return $this->user->validateTwoFactorCode($value);
        }

        return false;
    }

    /**
     * Get the validation error message.
     *
     * @return string|array
     */
    public function message() {
        return trans('laraguard::validation.totp_code');
    }

}
