<?php

/**
 * The laravel-saml package route configuration
 */

Route::group([
        'namespace' => "Pkeogan\LaravelSaml\Http\Controllers",
	'middleware' => 'web'

    ], function () {
			Route::any('logout/all', 'SamlIdpController@logoutAll')->name('logout.all');

		Route::any('logout/saml', 'SamlIdpController@logout')->name('logout.saml');
	    Route::get('/saml', 'SamlIdpController@post')->name('saml.post');
        Route::get('/saml/idp/metadata', 'SamlIdpController@metadata')->name('saml.idp.metadata');
		Route::get('/saml/idp/metadata.xml', 'SamlIdpController@metadata')->name('saml.idp.metadata');
    }
);

