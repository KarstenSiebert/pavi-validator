<?php

namespace App\Jobs;

use Illuminate\Support\Facades\Http;
use Illuminate\Queue\SerializesModels;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Foundation\Queue\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;

class UserVerificationInfo implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    private string $vurl;
    private string $user;
    private string $uuid;
    private string $creds;

    /**
     * Create a new job instance.
     */
    public function __construct(string $vurl, string $user, string $uuid, string $creds)
    {
        $this->vurl  = $vurl;
        $this->user  = $user;
        $this->uuid  = $uuid;
        $this->creds = $creds;
    }

    /**
     * Execute the job.
     */
    public function handle(): void
    {
        try {
            Http::retry(3, 200)
                ->timeout(10)
                ->asJson()
                ->post($this->vurl, [
                    "user"   => $this->user,
                    "issuer" => $this->uuid,                    
                    "creds"  => $this->creds
                ]);

        } catch (\Exception $e) {            
            // throw $e;
        }
    }

}
