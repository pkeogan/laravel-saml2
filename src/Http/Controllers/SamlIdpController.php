<?php

namespace KingStarter\LaravelSaml\Http\Controllers;

use Illuminate\Routing\Controller as Controller;
use Storage;
use KingStarter\LaravelSaml\Http\Traits\SamlAuth;

class SamlIdpController extends Controller 
{
    use SamlAuth;

    protected function metadata() {
        return response(
            $this->getSamlFile(config('saml.idp.metadata'), false),
            200, [
                'Content-Type' => 'application/xml'
            ]
        );
    }
}