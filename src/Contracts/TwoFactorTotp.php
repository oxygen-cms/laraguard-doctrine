<?php

namespace DarkGhostHunter\Laraguard\Contracts;

use Illuminate\Contracts\Support\Renderable;

interface TwoFactorTotp extends Renderable
{
    /**
     * Validates a given code, optionally for a given timestamp and future window.
     *
     * @param  string $code
     * @param  int  $window
     * @return bool
     */
    public function validateCode(string $code, int $window = null) : bool;

    /**
     * Creates a Code for the current timestamp.
     * @return string
     */
    public function makeTwoFactorCode() : string;

    /**1
     * Returns the Shared Secret as a QR Code.
     *
     * @return string
     */
    public function toQr() : string;

    /**
     * Returns the Shared Secret as a string.
     *
     * @return string
     */
    public function toString() : string;

    /**
     * Returns the Shared Secret as an URI.
     *
     * @return string
     */
    public function toUri() : string;
}
