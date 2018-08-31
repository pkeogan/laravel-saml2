<?php

namespace KingStarter\LaravelSaml;

use Illuminate\Support\ServiceProvider;
use Illuminate\Foundation\Application as LaravelApplication;
use Config;
use KingStarter\LaravelSaml\Console\EncodeAssertionUrlCommand;
use KingStarter\LaravelSaml\Console\SamlSetupCommand;

class LaravelSamlServiceProvider extends ServiceProvider
{
    /**
     * Bootstrap the application services.
     *
     * @return void
     */
	public function boot()
	{
        $this->bootInConsole();
        $this->loadPackageRoutes();
    }

    /**
     * Register the application services.
     *
     * @return void
     */
    public function register()
    {
        // Merge configuration
        $this->mergeConfigFrom(
            __DIR__.'/config/saml.php', 'saml'
        );
    }

    /**
     * Perform various commands only if within console
     */
    protected function bootInConsole()
    {
        if ($this->app instanceof LaravelApplication && $this->app->runningInConsole()) {

            // Create storage/saml directory
            if (!file_exists(storage_path() . "/saml/idp")) {
                mkdir(storage_path() . "/saml/idp", 0755, true);
            }

            // Publishing configurations
            $this->publishes([
                __DIR__ . '/config/saml.php' => config_path('saml.php'),
                __DIR__ . '/resources/metadata.blade.php' => storage_path('saml/idp/metadata.blade.php')
            ], 'saml_config');

        }

        $this->registerCommands();
    }

    /**
     * Register the commands.
     *
     * @return void
     */
    protected function registerCommands()
    {
        $this->registerModuleMakeCommand();
    }

    /**
     * Register the command.
     *
     * @return void
     */
    protected function registerModuleMakeCommand()
    {
        $this->commands([
            SamlSetupCommand::class,
        ]);
    }

    /**
     * Load package's routes into application
     */
    protected function loadPackageRoutes()
    {
        if (Config::get('saml.use_package_routes')) {
            $this->loadRoutesFrom(__DIR__ . '/routes.php');
        }
    }
}
