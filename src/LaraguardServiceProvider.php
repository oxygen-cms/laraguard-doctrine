<?php

namespace DarkGhostHunter\Laraguard;

use Illuminate\Routing\Router;
use Illuminate\Auth\Events\Validated;
use Illuminate\Auth\Events\Attempting;
use Illuminate\Contracts\Events\Dispatcher;
use Illuminate\Contracts\Config\Repository;
use Illuminate\Contracts\Validation\Factory;
use Oxygen\Data\BaseServiceProvider;

class LaraguardServiceProvider extends BaseServiceProvider {
    /**
     * Register the application services.
     *
     * @return void
     */
    public function register() {
        $this->loadEntitiesFrom(__DIR__ . '/Doctrine');
        $this->mergeConfigFrom(__DIR__ . '/../config/laraguard.php', 'laraguard');
    }

    /**
     * Bootstrap the application services.
     *
     * @param Repository $config
     * @param Dispatcher $dispatcher
     * @param Factory $validator
     * @return void
     */
    public function boot(Repository $config, Dispatcher $dispatcher, Factory $validator) {
        $this->loadTranslationsFrom(__DIR__ . '/../resources/lang', 'laraguard');

        $this->registerRules($validator);

        if ($this->app->runningInConsole()) {
            $this->publishFiles();
        }
    }

    /**
     * Register custom validation rules.
     *
     * @param Factory $validator
     * @return void
     */
    protected function registerRules(Factory $validator) {
        $validator->extendImplicit('totp_code', Rules\TotpCodeRule::class, trans('laraguard::validation.totp_code'));
    }

    /**
     * Publish config, view and migrations files.
     *
     * @return void
     */
    protected function publishFiles() {
        $this->publishes([
            __DIR__ . '/../config/laraguard.php' => config_path('laraguard.php'),
        ], 'config');

        $this->publishes([
            __DIR__ . '/../resources/lang' => resource_path('lang/vendor/laraguard'),
        ], 'translations');

        // We will allow the publishing for the Two Factor Authentication migration that
        // holds the TOTP data, only if it wasn't published before, avoiding multiple
        // copies for the same migration, which can throw errors when re-migrating.
        if (! class_exists('CreateTwoFactorAuthenticationsTable')) {
            $this->publishes([
                __DIR__ . '/../database/migrations/2020_04_02_000000_create_two_factor_authentications_table.php' => database_path('migrations/' . now()->format('Y_m_d_His') . '_create_two_factor_authentications_table.php'),
            ], 'migrations');
        }
    }
}
