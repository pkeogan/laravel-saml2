<?php

/**
 * This file is part of laravel-saml,
 * a SAML IDP integration for laravel. 
 *
 * @license MIT
 * @package pkeogan/laravel-saml
 */

use RobRichards\XMLSecLibs\XMLSecurityKey; //https://github.com/robrichards/xmlseclibs/blob/master/src/XMLSecurityKey.php
use RobRichards\XMLSecLibs\XMLSecurityDSig; //https://github.com/robrichards/xmlseclibs/blob/master/src/XMLSecurityDSig.php


return [

    /*
    |--------------------------------------------------------------------------
    | Base settings
    |--------------------------------------------------------------------------
    |
    | General package settings
    |
    */
	
	//if set to false, the package will be turned off and SAML will be disabled
	'enabled' => env('SAML_ENABLED', true),
	
    // Include the pre-defined routes from package or not.
    'use_package_routes' => true,
    
    // Forward user roles
    // This option requires entrust to be installed and
    // the user model to support the roles() method. Otherwise an empty
    // array of user roles will be forwarded.
    'forward_roles' => false,

    // Allow debugging within SamlAuth trait to get SP data during SAML auth
    // request. The debug output is written to storage/logs/laravel.log.
    'debug_saml_request' => false,
	
	// If set to true, this will produce iFrames on the login page that are hidden, that will
	// load the logout page of a service provider, IF the service provider has 'logout_url'.
	'logout_apps_via_iframe' => true,

    /*
    |--------------------------------------------------------------------------
    | IDP (identification provider) settings
    |--------------------------------------------------------------------------
    |
    | Set overall configuration for laravel as idp server.
    |
    | All files are in storage/saml and referenced via Storage::disk('saml') 
    | as root directory. To have a valid storage configuration, add the root  
    | path to the config/filesystem.php file.
    |
    */
    
    'idp' => [
        'metadata' => 'metadata/idp.xml',
        'cert' => 'certs/idp/cert.crt',
        'key' => 'certs/idp/key.key',
        'entityId' => 'https://somesite.org'
    ],
	
	/*
    |--------------------------------------------------------------------------
    | Certifcate Settings
    |--------------------------------------------------------------------------
    |
    | These settings will be used as the config to create the .ini file for opensll on cert gen
    |
    |
    */
	'openssl_config_location' => 'openssl/config.cnf',
	'openssl_config' => [
		'req' => [
			'default_bits' => '2048', 
			'default_md' => 'sh256', // can be sh1, sh256, sh512
			'prompt' => 'no',
			'encrypt_key' => 'no',
			'distinguished_name' => 'req_distinguished_name'
		],
		'req_distinguished_name' => [				
			'countryName' => 'US',
			'stateOrProvinceName' => 'US STATE',
			'localityName' => 'US CITY',
			'organizationName' => 'Some Site',
			'organizationalUnitName' => 'SS',
			'commonName' => 'SS',
			'emailAddress' => 'john.doe@somesite.org'
			],
	],
	
	/*
    |--------------------------------------------------------------------------
    | Metadata Settings
    |--------------------------------------------------------------------------
    |
    | Metadata Settings
    |
    | SAMLS Responses can be very complex, and can include signatures in the message 
    | and the assertion. The default settings will be provided here, and  
    | can be overided in each service provider aswell
    |
    */
    'metadata' => [
		'location' => 'metadata/idp.xml',
		// EnitityID (Required) Recommened to have it be the IDPs base URL
		'entityId' => 'https://somesite.org', 
		'cacheDuration' => 'PT1536873598S',
		// singleSignOnService (Required) full url to login or saml login
		'singleSignOnService_url' => 'https://somesite.org/login/saml',
		'singleSignOnService_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
		// singleLogoutService (Required) full url to logout or saml logout
		'singleLogoutService_url' => 'https://somesite.org/logout/saml', 
		'singleLogoutService_binding' => 'urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST',
		// NameIDFormat (Required) http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf
		'NameIDFormat' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress', // go to http://docs.oasis-open.org/security/saml/v2.0/saml-core-2.0-os.pdf and see page 78
		// wantAuthnRequestsSigned (Required) boolean, but keep it as a string
		'wantAuthnRequestsSigned' => 'true',
		// Public X509 Cert - file path form SAML Storage disk to x.509 CERT (Required )
		'cert' => 'certs/idp/cert.crt',
		'key' => 'certs/idp/key.key',
		// Organization Info
		// Organization Name (Optional)
		'organization_name' => 'Some Site', 
		// Organization Display Name (Optional)
		'organization_display_name' => 'SS',
		// Organization URL (Optional)
		'organization_url' => 'https://somesite.org',
		
		// Contact Info
		// Technical Contact Name (Optional)
		'technical_name' => 'Jane Doe',
		// Technical Contact Email (Optional)
		'technical_email' => 'jane.doe@somesite.org',
		// Support Contact Name (Optional)
		'support_name' => 'John Doe',
		// Support Contact Email (Optional)
		'support_email' => 'john.doe@somesite.com',
		
		// Should we sign the metadata? (Optional) Boolean
		'sign_metadata' => true,
		// file path form SAML Storage disk to x.509 CERT (Required if sign_metadata == true)
		'sign_metadata_cert' => 'certs/idp/metadata/cert.crt',
		// file path form SAML Storage disk the Private Key for signing meta data (Required if sign_metadata == true)
		'sign_metadata_key' => 'certs/idp/metadata/key.key',
		'sign_metadata_key_passphrase' => '',
		//
		'sign_metadata_key_hash' => XMLSecurityKey::RSA_SHA256,
		'sign_metadata_hash' => XMLSecurityDSig::SHA256
	],
	

    /*
    |--------------------------------------------------------------------------
    | SP (service provider) settings
    |--------------------------------------------------------------------------
    |
    | Array of service provider data. Add your list of SPs here.
    |
    | An SP is defined by its consumer service URL. Below as an example of an entry, with all settings
    | It contains:
    |   * entity-id (their entity id)
    |   * certificate (optional)
    |   * certificate-file (optional, the path within the 'saml' drive)
	|   * permission_needed (optional, will see if user attempting auth has the correct permission to use the listed service provider) 
   
		// A SP Entry
		'https://some-service-provider.com/auth/saml2/sp/saml2-acs.php' => [
			'name' => 'Some Service Provider', // REQUIRED - this name is used for displaying this service provider
			'entity-id' => "https://some-service-provider.com",  // REQUIRED - entity-id of the service provider. Needs to match what is on the SP metadata
			'certificate-file' => 'certs/sp/somesp/x509.crt', // OPTIONAL - If you was to sign the message or assertion, you need to provide the public X509 Cert. The root of this is the saml storage 
			'permission_needed' => 'saml-somesp', // OPTIONAL - string name of the permission neeed. You can use laravels native GATE system, or spatie/laravel-permission
			'logout_url' => "https://some-service-provider.com/logout", // OPTIONAL - if 'saml.logout_apps_via_iframe' is setup to true, this is the url that will used to attempt a logout via iframe
			'sign_message' => true, // OPTIONAL - will sign the message with cert given above with the given XMLSecurityDSig, if not present the message will not be signed
			'sign_assertion' => true // OPTIONAL - will sign the assertyion with cert given above with the given XMLSecurityDSig, if not present the assertion will not be signed
			'nameID_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', // OPTIONAL - will set the nameid format for the repsonse.DEFAULT IS urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
			'nameID_value' => 'id', // OPTIONAL - will set the value of the nane id from user attributes DEFAULT IS EMAIL
		],
   
   
   
   */

    'sp' => [
		// A SP Entry
		'https://some-service-provider.com/auth/saml2/sp/saml2-acs.php' => [
			'name' => 'Some Service Provider', // REQUIRED - this name is used for displaying this service provider
			'entity-id' => "https://some-service-provider.com",  // REQUIRED - entity-id of the service provider. Needs to match what is on the SP metadata
			'certificate-file' => 'certs/sp/somesp/x509.crt', // OPTIONAL - If you was to sign the message or assertion, you need to provide the public X509 Cert. The root of this is the saml storage 
			'permission_needed' => 'saml-somesp', // OPTIONAL - string name of the permission neeed. You can use laravels native GATE system, or spatie/laravel-permission
			'logout_url' => "https://some-service-provider.com/logout", // OPTIONAL - if 'saml.logout_apps_via_iframe' is setup to true, this is the url that will used to attempt a logout via iframe
			'sign_message' => true, // OPTIONAL - will sign the message with cert given above with the given XMLSecurityDSig, if not present the message will not be signed
			'sign_assertion' => true, // OPTIONAL - will sign the assertyion with cert given above with the given XMLSecurityDSig, if not present the assertion will not be signed
			'nameID_format' => 'urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified', // OPTIONAL - will set the nameid format for the repsonse.DEFAULT IS urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress
			'nameID_value' => 'id', // OPTIONAL - will set the value of the nane id from user attributes DEFAULT IS EMAIL
		],
    ],
	
	/*
    |--------------------------------------------------------------------------
    | Attribute Settings
    |--------------------------------------------------------------------------
    |
    | The array below is used for generating SAML Responses/
	| 
	| THE $USER MODEL MUST HAVE ATTRIBUTES LISTED AS THE KEY VALUE
	|
	| The Key Name is what the id in the SAML Attribute will be. The value refers to a models attributes and pulls 
	| The value from the current authed user.
    |
    */
	
	'attributes' => [
		
		'email' => 'email',
		'name' => 'name',
		'first_name' => 'first_name',
		'last_name' => 'last_name',
		'uuid' => 'uuid',
		'roles' => 'roles_for_saml',

    ],

];
