<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class VerifyMobileClient
{
    /**
     * Handle an incoming request.
     *
     * @param  Closure(Request): (Response)  $next
     */
    public function handle(Request $request, Closure $next): Response
    {
        $xAgeVerificationHeader = $request->header('X-Age-Verification') ?? null;

        if ($xAgeVerificationHeader == null) {
            return response()->json(['message' => 'Not authorized'], 401);
        }
        
        return $next($request);
    }
}
