<?php

namespace Pkeogan\LaravelSaml\Http\Traits;

use LightSaml\Credential\KeyHelper;
use Storage;
use Illuminate\Http\Request;
use LightSaml\Model\Protocol\Response as Response;
use LightSaml\Credential\X509Certificate;
use LightSaml\Meta\TrustOptions\TrustOptions;
use LightSaml\Validator\Model\Statement\StatementValidator;
use Illuminate\Support\Facades\Auth;
// For debug purposes, include the Log facade
use Illuminate\Support\Facades\Log;
use RobRichards\XMLSecLibs\XMLSecurityKey;
use RobRichards\XMLSecLibs\XMLSecurityDSig;


trait SamlAuth
{
//TrustOptions::setSignatureDigestAlgorithm(XMLSecurityKey::RSA_SHA256);
    /*
    |--------------------------------------------------------------------------
    | File handling (metadata, certificates)
    |--------------------------------------------------------------------------
    */
    
    /**
     * Get either the url or the content of a given file.
     */    
    protected function getSamlFile($configPath, $url) {
        if ($url)
            return Storage::disk('saml')->url($configPath);
        return Storage::disk('saml')->get($configPath);
    }    
    
    /**
     * Get either the url or the content of the saml metadata file.
     *
     * @param boolean url   Set to true to get the metadata url, otherwise the
     *                      file content will be returned. Defaults to false.   
     * @return String with either the url or the content
     */
    protected function metadata($url = false) {
        return $this->getSamlFile(config('saml.idp.metadata'), $url);
    }
    
    /**
     * Get either the url or the content of the certificate file.
     *
     * @param boolean url   Set to true to get the certificate url, otherwise the
     *                      file content will be returned. Defaults to false.   
     * @return String with either the url or the content
     */
    protected function certfile($url = false) {
        return $this->getSamlFile(config('saml.idp.cert'), $url);
    }

    /**
     * Get either the url or the content of the certificate keyfile.
     *
     * @param boolean url   Set to true to get the certificate key url, otherwise
     *                      the file content will be returned. Defaults to false.   
     * @return String with either the url or the content
     */
    protected function keyfile($url = false) {
        return $this->getSamlFile(config('saml.idp.key'), $url);
    }
    
    /*
    |--------------------------------------------------------------------------
    | Saml authentication
    |--------------------------------------------------------------------------
    */    

    /**
     * Handle an http request as saml authentication request. Note that the method
     * should only be called in case a saml request is also included. 
     *
     * @param  \Illuminate\Http\Request  $request
     * @return void
     */    
    public function handleSamlLoginRequest($request) {
        // Store RelayState to session if provided
        if(!empty($request->input('RelayState'))){
            session()->put('RelayState', $request->input('RelayState'));
			
        }
        // Handle SamlRequest if provided, otherwise just exit
        if (isset($request->SAMLRequest)) {
            // Get and decode the SAML request
            $SAML = $request->SAMLRequest;
            $decoded = base64_decode($SAML);
            $xml = $decoded[0] == '<' ? $decoded : gzinflate($decoded);
            // Initiate context and authentication request object
            $deserializationContext = new \LightSaml\Model\Context\DeserializationContext();
            $deserializationContext->getDocument()->loadXML($xml);
            $authnRequest = new \LightSaml\Model\Protocol\AuthnRequest();
            $authnRequest->deserialize($deserializationContext->getDocument()->firstChild, $deserializationContext);
            // Generate the saml response (saml authentication attempt)
            return $this->buildSamlResponse($authnRequest, $request);
        }
    }

    /**
     * Make a saml authentication attempt by building the saml response.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\RedirectResponse
     * @see https://www.lightsaml.com/LightSAML-Core/Cookbook/How-to-make-Response/
     * @see https://imbringingsyntaxback.com/implementing-a-saml-idp-with-laravel/
     */
    protected function buildSamlResponse($authnRequest, $request)
    {
        // Get corresponding destination and issuer configuration from SAML config file for assertion URL
        // Note: Simplest way to determine the correct assertion URL is a short debug output on first run
        //     : The old code base64 encoded the url, the new config file format doesn't require this,
        //       It also makes some changes to the fields
        $url = $authnRequest->getAssertionConsumerServiceURL();
        $sp = config('saml.sp')[$url];
        if(!$sp){
            $sp = config('saml.sp.' . base64_encode($url));
            if(!$sp){
                throw new \Exception("Invalid SAML Consumer Url");
            }
        }
		if(Auth::check())
		{
			$user  = \Auth::user();
		} else {
		    throw new \Exception("User attempting SAML is not logged in");
		}
		
		if( isset($sp['permission_needed']) ){		
			if( !$user->can($sp['permission_needed']) )
			{
				throw new \Exception("You do not have the needed permission to use this Service Provider.");
			}}
        $destination = isset($sp['destination']) ? $sp['destination'] : $url;
        $issuer = isset($sp['issuer']) ? $sp['issuer'] : config('saml.idp.entityId');
        $audienceRestriction = $url;
        if(isset($sp['entity-id'])) $audienceRestriction = $sp['entity-id'];
        if(isset($sp['audience_restriction'])) $audienceRestriction = $sp['audience_restriction'];


        // Load in both certificate and keyfile
        // The files are stored within a private storage path, this prevents from
        // making them accessible from outside  
        $x509 = new X509Certificate();
        $certificate = $x509->loadPem($this->certfile());
        // Load in keyfile content (last parameter determines of the first one is a file or its content)
				//dd($this->keyfile());
        $privateKey = \LightSaml\Credential\KeyHelper::createPrivateKey($this->keyfile(), '', false, XMLSecurityKey::RSA_SHA256);
			//dd($privateKey->loadKey);

        if (config('saml.debug_saml_request')) {
            Log::debug('<SamlAuth::buildSAMLResponse>');
            Log::debug('Assertion URL: ' . $url);
            Log::debug('Assertion URL: ' . base64_encode($url));
            Log::debug('Destination: ' . $destination);
            Log::debug('Issuer: ' . $issuer);
            Log::debug('Certificate: ' . $this->certfile());
			Log::debug('Key: ' . $this->keyfile());
            Log::debug('SAMLRequest:' . $request->get('SAMLRequest'));
        }

        //Validate sp certifcate
        $spCert = null;
        if(isset($sp['certificate-file'])){
            $spCert = X509Certificate::fromFile(Storage::disk('saml')->path($sp['certificate-file']));
        }
        if(isset($sp['certificate'])){
            $x509 = new X509Certificate();
            $spCert = $x509->setData($sp['certificate']);
        }
		

		
        if($spCert && !$authnRequest->getSignature()->validate(KeyHelper::createPublicKey($spCert))){
            Log::error("Invalid signature for URL $url. SAMLRequest=" . $request->get('SAMLRequest'));
            throw new \Exception("Invalid signature for URL $url.");
        }

	
		
		
  
        // Generate the response object
        $response = new \LightSaml\Model\Protocol\Response();
        $response
            ->addAssertion($assertion = new \LightSaml\Model\Assertion\Assertion())
            ->setID(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setDestination($destination)
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))
            ->setStatus(new \LightSaml\Model\Protocol\Status(new \LightSaml\Model\Protocol\StatusCode(\LightSaml\SamlConstants::STATUS_SUCCESS)))
        ;
		
		//sign the response message if the config for this SP is set as such
		if(isset($sp['sign_message']) && $sp['sign_message']) 
		{
			$response->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey, $sp['sign_message']));
		}

        $this->addRelayStateToResponse($response);

		//generate attributes
		$attributes = new \LightSaml\Model\Assertion\AttributeStatement();
		foreach(config('saml.attributes') as $key=>$value)
		{
			if($key == 'email'){
				$attributes->addAttribute(new \LightSaml\Model\Assertion\Attribute($key, strtolower($user[$value]) ));
			} else {
				$attributes->addAttribute(new \LightSaml\Model\Assertion\Attribute($key, $user[$value]));
			}
		}
		
		
		if(isset($sp['nameID_format']))
		{
			$format = $sp['nameID_format'];
		} else {
			$format = 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress';
		}
		
		if(isset($sp['nameID_value']))
		{
			$nameID =  \Auth::user()[$sp['nameID_value']];
		} else {
			$nameID = strtolower(\Auth::user()['email']);
		}
        
        // Generate the SAML assertion for the response xml object
        $assertion
            ->setId(\LightSaml\Helper::generateID())
            ->setIssueInstant(new \DateTime())
            ->setIssuer(new \LightSaml\Model\Assertion\Issuer($issuer))
            
            ->setSubject(
                (new \LightSaml\Model\Assertion\Subject())
                    ->setNameID(new \LightSaml\Model\Assertion\NameID(
                        $nameID,
                        $format
                    ))
                    ->addSubjectConfirmation(
                        (new \LightSaml\Model\Assertion\SubjectConfirmation())
                            ->setMethod(\LightSaml\SamlConstants::CONFIRMATION_METHOD_BEARER)
                            ->setSubjectConfirmationData(
                                (new \LightSaml\Model\Assertion\SubjectConfirmationData())
                                    ->setInResponseTo($authnRequest->getId())
                                    ->setNotOnOrAfter(new \DateTime('+100 MINUTE'))
                                    ->setRecipient($authnRequest->getAssertionConsumerServiceURL())
                            )
                    )
            )
            ->setConditions(
                (new \LightSaml\Model\Assertion\Conditions())
                    ->setNotBefore(new \DateTime())
                    ->setNotOnOrAfter(new \DateTime('+100 MINUTE'))
                    ->addItem(
                        new \LightSaml\Model\Assertion\AudienceRestriction([
                            $audienceRestriction
                        ])
                    )
            )
            ->addItem($attributes)
            ->addItem(
                (new \LightSaml\Model\Assertion\AuthnStatement())
                    ->setAuthnInstant(new \DateTime('-100 MINUTE'))
                    ->setSessionIndex('_some_session_index')
                    ->setAuthnContext(
                        (new \LightSaml\Model\Assertion\AuthnContext())
                            ->setAuthnContextClassRef(\LightSaml\SamlConstants::AUTHN_CONTEXT_PASSWORD_PROTECTED_TRANSPORT)
                    )
            )
        ;
		

		if(isset($sp['sign_assertion']) && $sp['sign_assertion']) 
		{
			$assertion->setSignature(new \LightSaml\Model\XmlDSig\SignatureWriter($certificate, $privateKey, $sp['sign_assertion']));
		}


		$serializationContext = new \LightSaml\Model\Context\SerializationContext();

		$response->serialize($serializationContext->getDocument(), $serializationContext);
		

			
		$response = $serializationContext->getDocument()->saveXML();
		return ['response'   => base64_encode($response),
				'recipient'  => base64_encode($url),
				'relayState' => $request->input('RelayState'),
				'name'       => $sp['name'] ];

    }


    /**
     * @param $response
     */
    protected function addRelayStateToResponse($response)
    {
        if (session()->has('RelayState')) {
            $response->setRelayState(session()->get('RelayState'));
            session()->remove('RelayState');
        }
    }
}
