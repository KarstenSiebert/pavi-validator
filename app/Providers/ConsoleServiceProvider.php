<?php

namespace App\Providers;

use Illuminate\Support\Facades\DB;
use Illuminate\Support\ServiceProvider;
use Illuminate\Console\Scheduling\Schedule;

class ConsoleServiceProvider extends ServiceProvider
{
    /**
     * Register services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap services.
     */
    public function boot(): void
    {
        $this->scheduleCommands();
    }

    protected function scheduleCommands(): void
    {    
        $schedule = $this->app->make(Schedule::class);

        $schedule->command('queue:work --stop-when-empty')->everyMinute();

        $schedule->command('cache:clear')->dailyAt('00:10');

        $schedule->call(function () {
            DB::table('sessions')
                ->where('last_activity', '<', now()->subMinutes(config('session.lifetime'))->timestamp)
                ->delete();
        })->daily();

        $schedule->call(function () {
            DB::table('log_messages')
                ->truncate();
        })->daily();        
    }

}
