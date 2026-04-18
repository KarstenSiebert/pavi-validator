<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;
use App\Jobs\UserVerificationInfo;
use Illuminate\Support\Facades\URL;
use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Http;

class AgeVerificationController extends Controller
{    
    /**
     * Validating is a two step process, after contacting, the validator will introduce itself and send its Merkle
     * leaves and index, the mobile app will check the signature and the leaves against the root before sending the
     * proof. If the validator belongs to the network, it will get the proof for verification (step 2)
     */

    public function vstart(Request $request): JsonResponse
    {
        // Check, if validator is active or blacklisted, this code will be adaopted in production.

        $validatorIdentifier = env('VALIDATOR_UUID');

        $validator = $request->header('X-Age-Verification') ?? null;

        if ($validator == null || $validator !== $validatorIdentifier) {
            // return response()->json(['link' => '#'], 403);
        }
      
        // The client has 3 minutes for its calculations before we timeout (can be increased if required)

        $link = URL::temporarySignedRoute('api.age.verify', now()->addMinutes(5));
             
        $secretKey = base64_decode(env('CREDENTIALS_SECRET_KEY'));
        $publicKey = base64_decode(env('CREDENTIALS_PUBLIC_KEY'));
        
        $publicKeyBase64 = env('CREDENTIALS_PUBLIC_KEY');

        $addr = [];

        // Leaves and index get updated each time a new root is generated, clients will verify them against root

        try {
            $path = storage_path('app/private/merkle_leaf.json');

            $json = File::get($path);
        
            $addr = json_decode($json, true);       
        
        } catch (Exception $e) {
            return response()->json(['Error' => 'leaf not available'], 500);
        }
              
        $data = [        
            'link' => $link,
            'addr' => $addr
        ];

        $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        
        $signature = base64_encode(sodium_crypto_sign_detached($json, $secretKey));
                
        $credentials['proof'] = [
            'publickey' => $publicKeyBase64,
            'signature' => $signature
        ];

        $credentials['field'] = base64_encode($json);

        $creds = base64_encode(json_encode($credentials));
           
        return response()->json(['creds' => $creds], 200, [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
    }

    /**
     * Step 2, the validator will verify the proof and respond. It will sign the user variable (which is a random number / nonce)
     * The user app will later compare transmitted and signed values, the signature assures the value has been sent from this validator
     * The Circuit allows us to monitor 4 outputs. Inputs are network EPOCH and user birthdate, EPOCH is transmitted with the root leaf,
     * once the app has been launched, EPOCH is updated every day. birthdate is locally encrypted and stored on the device together with
     * the signature of the trust entity after the age has been verified at the initial start. 
     **/
 
    public function verify(Request $request)
    {
        if (! $request->hasValidSignature()) {
            return response()->json([], 403);
        }
        
        $uuid = $request->header('X-Age-Verification') ?? null;        

        $request->validate([
            'user' => 'nullable|string|max:255',            
            'mina' => 'nullable|integer|between:14,21',
            'vurl' => 'nullable|url:https',
            'nonce' => 'nullable|string|max:255',
            'proof' => 'required|array',
            'proof.proof' => 'required|array',        
            'proof.publicSignals' => 'required|array'
        ]);
        
        $user = $request->input('user') ?? null;
        $vurl = $request->input('vurl') ?? null;
        $mina = $request->input('mina') ?? null;

        $nonce = $request->input('nonce') ?? null;
                        
        $sumProof = $request->input('proof');

        $proof         = $sumProof['proof'];
        $publicSignals = $sumProof['publicSignals'];
        
        $proof = json_decode(json_encode($proof, JSON_UNESCAPED_SLASHES), true);
        $publicSignals = json_decode(json_encode($publicSignals, JSON_UNESCAPED_SLASHES), true);
        
        $proofValid = $this->verifyProof($proof, $publicSignals);
                
        if ($proofValid) {
 
            $display = "not verified";

            $verifiedAge = 0;

            // Our Circuit has multiple outputs

            if ($publicSignals[3] == "1") {            
                $verifiedAge = 21;

            } elseif ($publicSignals[2] == "1") {
                $verifiedAge = 18;

            } elseif ($publicSignals[1] == "1") {
                $verifiedAge = 16;

            } elseif ($publicSignals[0] == "1") {
                $verifiedAge = 14;                            
            }            

            $vage = null;

            // Mininmal age request, we answer only yes / no

            if ($mina !== null) {

                if ($mina > $verifiedAge) {
                    $vage = false;
                
                } else {
                    $vage = true;
                }
            }
            
            if ($vage !== null) {
                $display = $vage ? 'true' : 'false';
            }

            // Send result to requesting server (vurl), provider server makes further decisions!
            // vurl has been provided by server to app via QR code
            if (($vurl != null) && ($user != null) && ($uuid != null)) {
                UserVerificationInfo::dispatchSync($vurl, $user, $uuid, $display);
            }
                    
            $secretKey = base64_decode(env('CREDENTIALS_SECRET_KEY'));
            $publicKey = base64_decode(env('CREDENTIALS_PUBLIC_KEY'));

            $publicKeyBase64 = env('CREDENTIALS_PUBLIC_KEY');

            // none is used to avoid spoofing and middle men during app-to-app communication on mobiles
            // none gets signed and verified by the user app using the public kex of the validator
            $data = [
                'user'  => $user,
                'show'  => $display,                
                'nonce' => $nonce
            ];
                
            $json = json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        
            $signature = base64_encode(sodium_crypto_sign_detached($json, $secretKey));
                
            $credentials['proof'] = [
                'publickey' => $publicKeyBase64,
                'signature' => $signature
            ];

            $credentials['field'] = base64_encode($json);

            $creds = base64_encode(json_encode($credentials));
        
            return response()->json(['valid' => $display, 'creds' => $creds]);
        }

        return response()->json(['valid' => 'Verification failed', 'creds' => ""]);
    }

    private function verifyProof($proofString, $publicSignalsString): bool
    {
        $response = Http::post('http://localhost:3009/verify-proof', [
            'proof' => $proofString,
            'publicSignals' => $publicSignalsString
        ]);

        if (!$response->ok()) {
            return false;
        }

        $result = $response->json();

        return $result['valid'] ?? false;
    }

    public function leaf(Request $request): JsonResponse
    {
        if ($request->input('member') && $request->input('lindex')) {
            
            $addr = [];
            $path = storage_path('app/private/merkle_leaf.json');

            $addr['member'] = $request->input('member');
            $addr['lindex'] = $request->input('lindex');

            file_put_contents($path, json_encode($addr, JSON_PRETTY_PRINT |  JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES));

            return response()->json([['message' => 'ok']]);
        }
        
        return response()->json(['message' => 'Webhook test']);
    }

}
