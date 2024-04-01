<?php

namespace DarkGhostHunter\Laraguard;

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
     * @param Factory $validator
     * @return void
     */
    public function boot(Factory $validator) {
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
            __DIR__ . '/../resources/lang' => $this->app->langPath('vendor/laraguard'),
        ], 'translations');
    }
}
