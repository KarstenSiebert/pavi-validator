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

    private $userDetails;
    private $providerUrl;
    private $issuersUUID;
    private $statusMessg;

    /**
     * Create a new job instance.
     */
    public function __construct($providerUrl, $userDetails, $issuersUUID, $statusMessg)
    {
        $this->providerUrl = $providerUrl;
        $this->userDetails = $userDetails;
        $this->issuersUUID = $issuersUUID;
        $this->statusMessg = $statusMessg;
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
                ->post($this->providerUrl, [
                    "userid" => $this->userDetails,
                    "issuer" => $this->issuersUUID,
                    "status" => $this->statusMessg
                ]);

        } catch (\Exception $e) {            
            // throw $e;
        }
    }

}
